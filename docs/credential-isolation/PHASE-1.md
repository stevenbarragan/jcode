# Phase 1: the fix (issue #2052)

Evidence and file:line references are in [FINDINGS.md](FINDINGS.md). Optional later hardening is in [DESIGN-SKETCH.md](DESIGN-SKETCH.md). No security guarantee is claimed until reviewed.

## What phase 1 is, and is not

The issue's use case: jcode headless in a Linux container, where the model must not **read** the key or **spend** it. Phase 1 is two PRs, and both are needed for that case:

- **PR 1 alone is not the fix.** It removes the key from every tool's environment and from `/proc`, but a tool still runs as the same uid as the server. It can still `cat ~/.config/jcode/openrouter.env`, read OAuth json, and connect to the server socket to make the server spend the key. PR 1 is a real improvement for everyone (laptops, macOS), and a prerequisite, but on its own it would only move the leak from `env` to `cat`.
- **PR 1 + PR 2 is the minimum real fix for containers.** PR 2 runs tools as a second uid. Same-uid file reads, `/proc` and the socket become cross-uid and are blocked by ordinary file permissions, which is the boundary the issue asks for.
- **One residual remains: spending via the network.** A credential-free tool can still send requests to an injecting gateway or a loopback proxy. Phase 1 closes this for containers with an operator-side egress rule (documented recipe below) plus a small webfetch change. The general, cross-platform solution is the egress proxy (optional hardening, phase 5).

Outside containers (laptop, macOS, no root), phase 1 gives you PR 1 only, and the honest summary there is: **against same-uid code without a sandbox, credentials cannot be fully protected.** That needs the sandbox phases.

## PR 1: env allowlist, socket and debug hygiene, non-dumpable (~250 lines, every platform)

1. New `crates/jcode-core/src/child_env.rs`: `apply_tool_env(cmd, extra)` = `env_clear()`, then copy `PATH HOME USER LOGNAME SHELL LANG LC_* TERM COLORTERM TMPDIR TZ JCODE_SESSION_ID JCODE_SCRATCH_DIR`, plus `tools.env_passthrough` (names or `PREFIX_*`), then explicit extras (cloud env, session env, MCP server `env`). `tools.env_passthrough = ["*"]` restores today's behaviour.
2. Call it at bash fg (`bash.rs:918`), bash bg (`:706`, `:1160`, `:1321`), browser (`browser.rs:982`), osascript (`osa.rs:97`), desktop selfdev (`desktop_selfdev.rs:448`), MCP stdio (`mcp/client.rs:216`, deleting the denylist at `:597`).
3. `JCODE_SOCKET` is not in the default allowlist. Swarm-from-bash users add it to passthrough. (Hygiene only: the default path is guessable. PR 2 is what makes the socket unreachable.)
4. `debug_control_allowed()` (`server/util.rs:25-29`): the `~/.jcode/debug_control` file only counts if it existed at server start.
5. Linux: `prctl(PR_SET_DUMPABLE, 0)` at `jcode serve` startup (opt out with `JCODE_ALLOW_DUMP=1`). Blocks same-uid `/proc/<server>/{environ,mem}`, `ptrace`, `process_vm_readv`; holds for root-in-container because Docker drops `CAP_SYS_PTRACE`. macOS has no equivalent for `ps -E`, so there PR 1 relies on step 1.

## PR 2: opt-in tool uid for containers (~150 lines, Linux, server runs as root)

1. When `JCODE_TOOL_UID` (and optional `JCODE_TOOL_GID`) is set and the server runs as root on Linux, every spawn from PR 1's `apply_tool_env` also does `setgroups([])`, `setgid`, `setuid` in `pre_exec`, with `PR_SET_NO_NEW_PRIVS`. Startup refuses if the uid equals the server's.
2. Startup check: credential dirs (`~/.jcode`, `~/.config/jcode`, `~/.claude`, `~/.codex`, `~/.config/github-copilot`, the socket runtime dir) are not readable by the tool uid; refuse to start otherwise, naming the path. The socket is already `0600` in a `0700` dir.
3. In-process file tools (read, write, edit, apply_patch, agentgrep) still run as root, so they get a path denylist for those same dirs, resolved after symlinks. (Moving them out of process is the executor split, phase 3.)
4. Webfetch, which also runs in-process, refuses loopback, link-local (`169.254.0.0/16`) and private ranges when tool uid mode is on, unless `tools.webfetch_allow_private` lists the host. Same checks as `trusted_gateway_base` / #1869.
5. Documented container recipe, including the egress rule for the gateway case:
   ```sh
   # tools (uid 1001) may not reach the injecting gateway on :8787 or cloud metadata
   iptables -A OUTPUT -m owner --uid-owner 1001 -p tcp --dport 8787 -j REJECT
   iptables -A OUTPUT -m owner --uid-owner 1001 -d 169.254.169.254 -j REJECT
   ```
   (Needs `NET_ADMIN` at container start, or the same rule in the pod network policy. Without it, tools can still spend through the gateway.)

## Canary tests (fake key `sk-canary-2052-0000`, never a real one)

Harness first, in PR 1: `crates/jcode-app-core/tests/credential_canary.rs`, one test per FINDINGS section 7 item, `#[ignore = "expected_leak"]` until its PR flips it.

- PR 1, unit: `child_env_drops_secrets` (`OPENAI_API_KEY`, `HUGGINGFACE_TOKEN`, `FOO_SECRET`, `JCODE_SOCKET` absent, `PATH`/`HOME` kept), `passthrough_glob_and_star`.
- PR 1, integration: `bash_tool_env_has_no_canary`, `runtime_set_var_not_inherited`, `mcp_stdio_env_has_no_token_or_secret`, `debug_control_file_after_start_ignored`, Linux `proc_environ_and_mem_denied`.
- PR 2, Linux root CI job: `tool_uid_cannot_read_env_files`, `tool_uid_cannot_connect_socket`, `file_tool_denies_credential_dir` (incl. symlink), `webfetch_denies_loopback_in_tool_uid_mode`, `egress_recipe_blocks_gateway` (fake gateway logs the `Authorization` header; expect no request from the tool).

## Threats, phases and residual risk

Threats are the FINDINGS section 7 canaries plus the other findings. "Residual after phase 1" assumes a Linux container with PR 1 + PR 2 and the egress recipe.

| # | Threat (FINDINGS) | Closed by | Residual after phase 1 (container) |
|---|---|---|---|
| 1 | Key in tool env (`bash.rs:918`) | PR 1 | none |
| 2 | Key set at runtime inherited (`provider-env:226`) | PR 1 | none for children. Key still in server memory (phase 2 SecretStore, defence in depth) |
| 3 | `/proc/<server>/environ`, `mem` | PR 1 (non-dumpable), PR 2 (other uid) | none |
| 4 | Credential files, OAuth json, `~/.claude` (2, 1.2) | PR 2 | none for tools. Secrets the user put **in the workspace** stay readable (out of scope: the workspace is the tools' job) |
| 4b | File tools read credential files in-process | PR 2 path denylist | a denylist, not a boundary: a missed path leaks. Phase 3 (executor split) makes it a boundary |
| 5 | MCP stdio denylist misses `*_TOKEN`, `*_SECRET` | PR 1 | none |
| 6 | Tool drives the server socket and spends the key | PR 2 (socket 0600, other uid) | none in containers. Laptops: still open until phase 2 capability token or a sandbox |
| 6b | Other local endpoints: browser daemon sockets, harness API server (2.2) | PR 2 if they are uid-protected Unix sockets | **unverified**: PR 2 must check each; any TCP loopback listener needs a token or the egress rule |
| 7 | `touch ~/.jcode/debug_control` enables debug socket | PR 1 | none |
| 8 | Direct egress spends the key | PR 1 + 2 (tool can't read the key) | spending through an injecting gateway: closed only by the egress recipe (operator config). Phase 5 egress proxy makes it built in |
| 8b | Webfetch reaches loopback gateway / metadata | PR 2 | none in tool uid mode |
| 9 | Jev and other hard-coded hosts bypass the gateway (section 4) | gateway track (phase 7) | not a leak to the model; an operator-config gap. Separate, non-isolating |
| - | Cross-session visibility in the shared server (2.4) | not by phase 1 (all sessions share one tool uid) | one session's tools can read another's workspace. Per-session executors, phase 3 |
| - | Keychain via `/usr/bin/security` (macOS) | phase 6 (Seatbelt) | n/a in Linux containers |
| - | Credential helper (`api_key_command`, section 5) | gateway track (phase 7) | feature, not a leak |
| - | Root in container, kernel bugs, malicious provider | out of scope (threat model) | |
| - | Windows | out of scope for now (6) | AppContainer later if wanted |
