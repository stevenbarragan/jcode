# Simplest fix (issue #2052)

Goal: the smallest change that removes most of the practical risk for headless and container users, before any broker/executor split. Evidence in [FINDINGS.md](FINDINGS.md), target in [DESIGN-SKETCH.md](DESIGN-SKETCH.md).

## The insight

Today the cheapest leak is also the most likely one: a model runs `env`, `printenv` or a script that dumps the environment, and the key is right there, because the server copies every key into its own env (`crates/jcode-provider-env/src/lib.rs:226`, choke point `crates/jcode-core/src/env.rs:21`) and every tool child inherits it (`tool/bash.rs:918-922`, `tool/browser.rs:982`, `tool/computer/osa.rs:97`). Fixing spawns with an allowlist kills that leak in one place per spawn site, without touching how providers read keys. The deeper leaks (files, `/proc`, socket) then need a uid or sandbox boundary, and for containers that boundary is nearly free.

## Candidates, ranked by risk removed per line

| Rank | Candidate | Approx. lines | Risk removed | Notes |
|---|---|---|---|---|
| 1 | **(a1) `env_clear()` + allowlist at every tool spawn** (bash fg/bg, browser CLI, osascript, selfdev, MCP stdio replacing the denylist at `mcp/client.rs:597`) | ~120 incl. tests | env inheritance, the #1 casual leak, for all keys incl. `*_TOKEN`/`*_SECRET` the MCP denylist misses | Does not need (a2): even if the server env holds keys, children never see them |
| 2 | **(b) drop `JCODE_SOCKET` and `JCODE_DEBUG_CONTROL` from tool env; ignore `~/.jcode/debug_control` unless created before server start or owned by a different uid** | ~30 | runtime debug escalation (`server/util.rs:25-29`); casual socket discovery | Path is still guessable (default `default_socket_path()`), so this is hygiene, not a boundary. A real fix is a per-connection capability token (phase 3). Compat: the swarm/`jcode` CLI from bash uses `JCODE_SOCKET`; keep it opt-in via passthrough |
| 3 | **(c1) `prctl(PR_SET_DUMPABLE, 0)` in the server on Linux** | ~10 | same-uid `/proc/<server>/environ`, `/proc/<server>/mem`, `ptrace`, `process_vm_readv` | Non-dumpable makes `ptrace_may_access` require `CAP_SYS_PTRACE` in the target's user ns, which `/proc/pid/{environ,mem,maps}` reads use. Docker's default capability set drops `CAP_SYS_PTRACE`, so it holds even for root-in-container. Resets on `execve` (children unaffected). macOS `PT_DENY_ATTACH` only blocks debugger attach; `ps -E` shows the initial env regardless, so on macOS rely on (a1) and not copying keys into env |
| 4 | **(c2) container uid split**: when running as root on Linux and `JCODE_TOOL_UID` is set, spawn tools with `setgroups([]) + setgid + setuid` (via `pre_exec`, or `setpriv --reuid`), `no_new_privs`; credential files stay 0600 owned by root | ~80 | file reads of `~/.jcode`, `~/.config/jcode`, `~/.claude`, `google_oauth.json`; `/proc` of the server; socket connect (0600) | In-process file tools (read/edit/agentgrep) still run as the server uid: needs a path denylist for the credential dirs (~30 lines) until phase 4 moves them |
| 5 | (a2) `SecretStore` instead of `set_var` | ~400+, 10 call sites | defence in depth after (a1) and (c1) | Worth it, not first. Touches every provider's key lookup |
| 6 | (d) gateway mode, keyless boot, Jev base URL | ~150 | key not in jcode at all | Only isolating if the tool cannot reach the gateway. Separate, non-isolating track as the maintainer suggested |

## Recommended first PR (~250 lines): "tool env allowlist + debug toggle lock + non-dumpable server"

Does:
1. New `crates/jcode-core/src/child_env.rs`: `fn apply_tool_env(cmd, extra: &[(K,V)])` = `env_clear()` then copy `PATH HOME USER LOGNAME SHELL LANG LC_* TERM COLORTERM TMPDIR TZ SSH_AUTH_SOCK? (off) JCODE_SESSION_ID JCODE_SCRATCH_DIR` plus `config.tools.env_passthrough` (names or `PREFIX_*`), then explicit extras (cloud env, session env, MCP server `env`). Escape hatch: `tools.env_passthrough = ["*"]` restores today's behaviour.
2. Call it at bash fg (`bash.rs:918`), bash bg (`:706`, `:1160`, `:1321`), browser (`browser.rs:982`), osascript (`osa.rs:97`), desktop selfdev (`desktop_selfdev.rs:448`), MCP stdio (`mcp/client.rs:216`, delete the denylist).
3. `JCODE_SOCKET` not in the default allowlist; swarm-from-bash users add it to passthrough.
4. `debug_control_allowed()`: the file toggle only counts if it existed at server start (snapshot once).
5. Linux: `prctl(PR_SET_DUMPABLE, 0)` at `jcode serve` startup, behind `JCODE_ALLOW_DUMP=1` for developers who need gdb.

Protects (headless/container): `env`/`printenv` leaks of any provider key, MCP `*_TOKEN`/`*_SECRET` gap, `/proc/<server>/environ|mem` reads, runtime debug-socket enabling.

Does NOT protect: reading `~/.jcode/*.env`, `~/.config/jcode/*.env`, OAuth json, `~/.claude/.credentials.json`, Keychain via `security` (same uid); connecting to the main socket by its default path and spending the key; direct egress to providers or a local injecting gateway; file tools reading credential files. Honest summary: **against same-uid code without a sandbox, credentials cannot be fully protected**. Closing it needs a different uid (PR 3 below) or a mount-namespace/Seatbelt sandbox, plus a network policy.

## Second PR for container users (~120 lines): `JCODE_TOOL_UID`

Linux only, opt-in: tools exec as an unprivileged uid with `no_new_privs`; file tools refuse paths under jcode's credential dirs. With PR 1 this closes files, `/proc`, and the socket (0600, other uid) for the container case. Still open: egress to provider hosts (needs the proxy in the sketch) and the workspace itself if it holds secrets.

## Canary tests (fake key `sk-canary-2052-0000`, never a real one)

Unit (fast, every platform):
- `child_env_drops_secrets`: set `OPENAI_API_KEY`, `HUGGINGFACE_TOKEN`, `FOO_SECRET`, `JCODE_SOCKET` in a `Command` built by `apply_tool_env`; assert `get_envs()` contains none and keeps `PATH`, `HOME`.
- `passthrough_glob_and_star`: `FOO_*` passes `FOO_BAR`; `*` restores full env.
Integration (spawn real children):
- `bash_tool_env_has_no_canary`: run the bash tool with canary in process env; output of `env` has no `canary-2052`.
- `runtime_set_var_not_inherited`: `save_env_value_to_env_file` with canary, then bash `env`: no canary.
- `mcp_stdio_env_has_no_token_or_secret`: MCP server `sh -c 'env'` with `CANARY_TOKEN`/`CANARY_SECRET`: absent; explicit `env` entry: present.
- `debug_control_file_after_start_ignored`.
- Linux: `proc_environ_and_mem_denied`: child reads `/proc/$PPID/environ` and opens `/proc/$PPID/mem`: `EACCES`.
- Linux, root CI job: `tool_uid_cannot_read_env_files` (PR 2).
