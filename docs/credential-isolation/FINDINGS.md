# Credential isolation (issue #2052): findings

Status: investigation only, no code changes. Key claims re-verified 2026-11-05 (provider-env:226, socket.rs:331, util.rs:25, jev.rs:144-147, mcp/client.rs:597, bash.rs:918). Note: `JCODE_SOCKET` reaches tools because `set_socket_path` calls `set_var` in the server env (`server/socket.rs:331`), not via an explicit `.env()`. Base commit: `c725fa315` (origin default branch, 2026-11-05).
Line numbers refer to that commit. Rule followed: no real credential values were read or printed; only variable names and paths.

## 0. Summary

- jcode has one trust domain. The server process (`jcode serve`, the shared daemon) holds every provider credential in its own process environment and memory, and runs model-chosen tools (bash, MCP stdio, browser bridge, osascript) as plain child processes of the same uid.
- Provider keys are copied into the process environment on purpose (`jcode_core::env::set_var` after loading `*.env` files), so every child inherits them unless the spawn site scrubs them. Only MCP stdio scrubs (issue #771). Bash does not.
- Even with a scrubbed env, the tool child is the same uid: it can read `~/.jcode/*.env`, `~/.jcode/*oauth*.json`, `~/.claude/.credentials.json`, Copilot `hosts.json`, the macOS Keychain items jcode reads, and (Linux) `/proc/<server pid>/environ` and `/proc/<server pid>/mem`.
- The jcode server socket is `0600` in a `0700` dir, which protects against other uids but not against the tool child (same uid). Through it, a tool can drive the server, which makes authenticated provider calls on its behalf. The debug socket adds arbitrary server-side commands when enabled.
- Proposal 2 (gateway mode) gaps: many hard-coded hosts (Jev decisions, usage/billing probes, OAuth refresh, telemetry, catalog). Proposal 3 (credential helper): no `api_key_command` exists today.

Live evidence from this very session (macOS, agent running under the shared jcode server): `env | cut -d= -f1` inside the bash tool listed `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `MISTRAL_API_KEY`, `CEREBRAS_API_KEY`, `CURSOR_API_KEY`, `CLAUDE_API_KEY`, `HUGGINGFACE_TOKEN`, `BETTERSTACK_API_TOKEN`, `REPO_TOKEN` and `JCODE_SOCKET`. Values were not printed. `ps -p $PPID` shows the parent is `~/.jcode/builds/shared-server/jcode`, same user.

## 1. Where credentials enter the process

### 1.1 Environment variables and `*.env` files (the main path)

| Source | Reference | Notes |
|---|---|---|
| Inherited shell env | everywhere via `std::env::var` | e.g. `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `AIMLAPI_API_KEY`, `JCODE_API_KEY`, websearch `api_key_env` |
| `jcode login` writes `~/.config/jcode/<provider>.env` (or `$JCODE_HOME/config/jcode`) | `src/cli/login.rs:598` (openai.env), `:656` (anthropic.env), `:701` (openrouter.env), `:739` | file is owner-only (`crates/jcode-storage/src/lib.rs:569-614`) but same uid |
| Saving a key also exports it into the live process env | `crates/jcode-provider-env/src/lib.rs:221-226` (`save_env_value_to_env_file` then `jcode_core::env::set_var(env_key, value)`), `:285` | this is why every later child inherits it |
| Other dynamic `set_var(key, value)` sites that load env files / activate providers | `crates/jcode-base/src/provider/activation.rs:285`, `crates/jcode-base/src/auth/lifecycle.rs:1148`, `crates/jcode-base/src/provider/openai.rs:328`, `crates/jcode-base/src/provider_activity.rs:411`, `crates/jcode-base/src/copilot_usage.rs:121`, `crates/jcode-base/src/sidecar.rs:1311`, `src/cli/commands/provider_setup.rs:624`, `crates/jcode-app-core/src/server/lifecycle.rs:311`, `crates/jcode-app-core/src/tool/selfdev/reload.rs:549` | single choke point: `crates/jcode-core/src/env.rs:21` |
| Provider catalog `env_file` per OpenAI-compatible provider | `src/cli/provider_init.rs:838-842`, `crates/jcode-base/src/provider_catalog.rs:838` (`bearer_auth(api_key)`) | catalog + model list fetches |
| Cloud environment env vars injected into bash | `crates/jcode-app-core/src/tool/bash.rs:695-704`, used at `:919`, `:1160`, `:1321` | user-defined, intended for tools; may contain secrets by design |
| Per-session env injected into bash | `crates/jcode-app-core/src/session_env.rs:17-50`, `bash.rs:920` | same |

### 1.2 Config and credential files (all same uid)

- `~/.jcode/` (`crates/jcode-storage/src/lib.rs:163-169`, `JCODE_HOME` override), `~/.config/jcode/` (`:221-227`).
- Auth transfer list names `auth.json`, `openai-auth.json`, `anthropic.env`, `openai.env`, `config.toml` (`crates/jcode-base/src/auth/transfer.rs:48-49`, `:1756`).
- Google (Gmail/Calendar): `~/.jcode/google_credentials.json` (client secret) and `~/.jcode/google_oauth.json` (access + refresh token) (`crates/jcode-base/src/auth/google.rs:225-229`, token URL `:7`).
- Claude Code reuse: `~/.claude/.credentials.json` and macOS Keychain via `/usr/bin/security find-generic-password -w` (`crates/jcode-base/src/auth/claude.rs:165`, `:756-765`, `:836`).
- Copilot: `~/.config/github-copilot/hosts.json`, optional `gh auth token` (`crates/jcode-base/src/auth/copilot.rs:86`, `:152-155`, `:465`); token exchange `https://api.github.com/copilot_internal/v2/token` (`:45`).
- Codex / OpenAI OAuth (`crates/jcode-base/src/auth/codex.rs:597`), Antigravity Google OAuth (`crates/jcode-base/src/auth/antigravity.rs:5`), Muse/Meta key exchange (`crates/jcode-base/src/auth/muse.rs:18`, `:75`), Cursor (`crates/jcode-provider-cursor-runtime/src/lib.rs:29`), Bedrock AWS creds (`crates/jcode-provider-bedrock/src/lib.rs`), Azure (`crates/jcode-azure-auth`).
- External auth discovery and keyring helpers: `crates/jcode-base/src/external_auth.rs`, `crates/jcode-storage/src/lib.rs:309-394`.
- MCP remote OAuth tokens and static headers: `crates/jcode-base/src/mcp/mod.rs:4`, `crates/jcode-base/src/mcp/oauth.rs`; stdio `env` in MCP config.
- Laya optional `LAYA_API_KEY` in `laya.env` (`crates/jcode-base/src/config/default_file.rs:633`).

### 1.3 OAuth refresh

Refresh happens inside the server (Anthropic OAuth profile/usage `crates/jcode-base/src/auth/oauth.rs:23`, `crates/jcode-base/src/usage.rs:63`; Google `auth/google.rs:7`; Copilot token exchange). Refresh tokens therefore live in server memory and on disk. In a broker model refresh must move with the credential.

### 1.4 Other credential-bearing calls (non-chat)

| Path | Reference | Host |
|---|---|---|
| Jev decisions (browser, memory, voice) | `crates/jcode-base/src/jev.rs:115` (key env + env file), `:144` literal `https://openrouter.ai/api/alpha/decisions`, `:147` aimlapi, `:148` jcode gateway via `trusted_gateway_base` (`:593`) | not covered by `JCODE_OPENROUTER_API_BASE` |
| Laya | `jev.rs:18-19` `JCODE_LAYA_BASE_URL`, default `http://127.0.0.1:8080`; allowlisted in `crates/jcode-base/src/config.rs:230` | precedent for a URL override with checks (#1869) |
| Usage / billing probes | `crates/jcode-base/src/usage/api_keys.rs:140,181,338,442,699`, `crates/jcode-base/src/usage/provider_fetch.rs:740` | provider hosts, hard-coded |
| Anthropic side endpoints | `crates/jcode-provider-anthropic-runtime/src/lib.rs:63-66,386,396,406,438` | hard-coded |
| Model catalog | `crates/jcode-provider-openrouter-runtime/src/catalog_fetch.rs:14,273`, `crates/jcode-provider-metadata/src/catalog.rs` (all default bases) | |
| Web search | `crates/jcode-app-core/src/tool/websearch.rs:276` (`api_key_env`), `:298` Bing, `:385` SearXNG URL env, `websearch_kagi.rs` | key read in server, request made in server |
| compile_remote | `crates/jcode-app-core/src/tool/compile_remote.rs:114,233,292` (`bearer_auth(key)`, `JCODE_API_KEY` / `JCODE_API_BASE`) | api.jcode.sh |
| Discovery / catalog of integrations | `crates/jcode-config-types/src/lib.rs:985` (`https://api.jcode.sh/v1/discovery`), outbound text secret filter `tool/discover_secrets.rs` | |
| Cloud managed | `src/cli/cloud_managed.rs:23`, `crates/jcode-sdk/src/cloud.rs:213` | |
| Telemetry | `crates/jcode-telemetry-core/src/lib.rs:43-44`, `usage_outbox.rs:267`, `oauth_account.rs:185,213` | sends OAuth account label/check, no provider key observed |
| Gmail / Calendar tools | `crates/jcode-app-core/src/tool/gmail.rs`, `calendar.rs` using `auth/google.rs` tokens | |
| Update checks | `crates/jcode-app-core/src/update.rs:207,270` | unauthenticated GitHub API |

## 2. How tools execute

| Tool | Spawn site | Process / uid | Env |
|---|---|---|---|
| bash (foreground) | `crates/jcode-app-core/src/tool/bash.rs:661-678` (`bash` / `cmd.exe`), envs at `:918-922` | child of server, same uid | full server env inherited, plus cloud env, session env, `JCODE_SESSION_ID`. No `env_clear`, no scrub |
| bash (background / reload-persistent) | `bash.rs:706-717`, `:1160-1162`, `:1321-1323` | detached child, same uid, survives server reload | same full env |
| MCP stdio servers | `crates/jcode-base/src/mcp/client.rs:212-222` | child, same uid | scrubbed by `mcp_child_env` (`:612-619`) using a suffix denylist `is_sensitive_inherited_env_key` (`:597-610`): `*_API_KEY`, `*_ACCESS_TOKEN`, `*_AUTH_TOKEN`, AWS/Azure/Google names. Misses `*_TOKEN` (e.g. `HUGGINGFACE_TOKEN`, `REPO_TOKEN`), `*_SECRET`, `*_PASSWORD`, `*_KEY` without `API_` |
| MCP remote | `mcp/mod.rs:4`, `manager.rs` | in server | headers / OAuth tokens held in server |
| browser bridge CLI | `crates/jcode-app-core/src/tool/browser.rs:982-995` | child, same uid | full env + `BROWSER_SESSION` |
| browser handoff (Jev) | `tool/browser_jev.rs`, `jcode-base/src/jev.rs` | in server | key in server |
| macOS computer use / osascript | `tool/computer/osa.rs:97`, `computer/setup.rs` | child, same uid | full env |
| desktop selfdev | `tool/desktop_selfdev.rs:448-456` | child | full env minus `RUSTC_WORKSPACE_WRAPPER` |
| read / write / edit / apply_patch / agentgrep | in-process | server uid | unrestricted path access: can read `~/.jcode/*.env`, `~/.config/jcode/*.env`, `google_oauth.json`, `~/.claude/.credentials.json` |
| webfetch | in-process | server | can reach any host incl. loopback |
| debug_socket tool | `tool/debug_socket.rs`, registered `tool/mod.rs:1013,1850` (selfdev profile) | in server | talks to the debug socket |

### 2.1 Process visibility (Linux)

- A bash child can read `/proc/<ppid>/environ` and, subject to `ptrace_scope`, `/proc/<ppid>/mem` of the server (same uid, the server is its ancestor, so even Yama `ptrace_scope=1` allows it). Note that `environ` is the initial env block; keys added later with `set_var` are not reflected there but are inherited by children anyway, and live in heap memory readable via `mem`/`gdb`.
- `ps eww` / `/proc/*/cmdline` show other sessions' commands. With `hidepid` absent, every process of every session in the shared server is visible.
- macOS: no `/proc`; `ps -E`/`ps eww` shows env of same-uid processes on many versions, and `task_for_pid` is restricted by SIP/hardened runtime, but the env inheritance and file reads are the same.

### 2.2 Sockets

- Main socket: `JCODE_SOCKET` is exported to children (`crates/jcode-app-core/src/server/socket.rs:8`, `:331-332`), bound at `server.rs:2350`. Observed `srw-------` in a `drwx------` dir: safe against other uids, but the tool child is the same uid and knows the path. A tool can connect and speak the client protocol (start a session, send a prompt): the server then makes authenticated provider calls for it. The key is not exfiltrated, but it can be spent, and any server-side tool (webfetch, compile_remote) can be invoked.
- Debug socket: bound at `server.rs:2351` always; command execution gated by `debug_control_allowed` (`server/util.rs:13-31`): config `display.debug_socket` (default false, `config/default_file.rs:184`), `JCODE_DEBUG_CONTROL`, or the existence of the file `~/.jcode/debug_control`. A bash tool can `touch ~/.jcode/debug_control` and enable it at runtime without restart. That is a privilege-escalation path within the same domain.
- Browser session daemon sockets and the harness API server (`crates/jcode-harness-api-server`) are further local endpoints reachable by same-uid code.

### 2.3 Network reach

Nothing restricts tool egress. A bash tool with a key can `curl` the provider directly; webfetch can hit loopback (Laya default `127.0.0.1:8080`, a local injecting proxy, cloud metadata `169.254.169.254`). In the gateway setup from the issue, a tool can call the local injecting proxy and spend the operator's key without ever seeing it. Network policy is therefore part of the fix, not optional.

### 2.4 Swarm / server architecture

One shared server process (`~/.jcode/builds/shared-server/jcode`) serves many sessions and swarm workers; all of their tools are its children. A compromise in one session reaches credentials and sockets of all of them. Any broker design must be per-server (one broker, many executors), and executors must be per session (or per tenant) so one session cannot read another's workspace or env.

## 3. Existing scrubbing and redaction

- MCP stdio env denylist (#771): `mcp/client.rs:597-619`. Partial, see gaps above.
- Session transcript redaction: `crates/jcode-base/src/session_redaction.rs:1` (`redact_json_value`), used from `session.rs`, `message.rs`.
- Outbound discovery text secret filter: `crates/jcode-app-core/src/tool/discover_secrets.rs`.
- Jev error messages avoid naming the key env (`jev.rs:914-918` test).
- Credential files written owner-only (`jcode-storage/src/lib.rs:569-614`).
- Copilot avoids `gh auth token` unless opted in (`auth/copilot.rs:217,287`).
- Nothing scrubs bash, browser, osascript or selfdev children. No sandbox, no uid separation, no network policy.

## 4. Gaps for Proposal 2 (gateway mode)

Hosts not governed by a per-provider base URL (non-exhaustive, from grep of `https://` literals):
- Jev decisions: `jev.rs:144` (OpenRouter), `:147` (AIMLAPI). `JCODE_BROWSER_JEV_PROVIDER` picks provider, not host.
- Usage / balance probes: `usage/api_keys.rs:140,181,338,442,699`; `usage/provider_fetch.rs:740`; `usage.rs:63`.
- Anthropic side APIs: `jcode-provider-anthropic-runtime/src/lib.rs:386,396,406,438`; OAuth profile `auth/oauth.rs:23`.
- Copilot token exchange `auth/copilot.rs:45,48,1032`; Muse key `auth/muse.rs:75`; Cursor `agent_transport.rs:1694,1740`.
- Web search engines `tool/websearch.rs:298`, Kagi; Google OAuth token URL `auth/google.rs:7`.
- Placeholder key: startup refuses without credentials (`src/cli/provider_init.rs:1871-1882`, "No credentials configured"). Deferred-auth boot exists for onboarding (`:1871`) and could be reused for "gateway set, no key".
- Precedent for safe overrides: `trusted_gateway_base` (`jev.rs:593-...`, https or loopback) and Laya URL checks (#1869).

## 5. Gaps for Proposal 3 (credential helper)

No `api_key_command` / `apiKeyHelper` equivalent exists (grep for `api_key_command|apiKeyHelper|credential_helper|key_command`: no hits). Keys are static strings from env or files. A helper would naturally live in the broker ([DESIGN-SKETCH.md](DESIGN-SKETCH.md) section 1), with TTL caching; it must never run inside the executor.

## 6. Platform notes

- Linux container (operator use case): easiest to fix. Run the broker as uid A and the executor as uid B in the same container, or the executor in a sibling container sharing only the workspace volume and a broker socket. Add `hidepid=2` on `/proc` (or a PID namespace via bubblewrap `--unshare-pid`), a private mount namespace without `~/.jcode` and `~/.config/jcode`, `no_new_privs`, seccomp, and `--unshare-net` plus a proxy veth or the broker as the only egress. Landlock (5.13+) can restrict paths without root.
- macOS: no uid switch without root or a helper; use Seatbelt (`sandbox-exec` profile, deprecated but used by Codex and Claude Code) to deny reads of credential paths and restrict network to a local proxy; env scrubbing at spawn. Keychain items read via `/usr/bin/security` are reachable by any same-uid process unless the item ACL restricts it; jcode should not copy them into env.
- Windows: out of scope for the first iteration (AppContainer / restricted tokens).

## 7. Reproducing each exposure with a canary (fake) key

Use a key that cannot authenticate anywhere, e.g. `JCODE_CANARY_API_KEY=canary-2052-0000` and `OPENROUTER_API_KEY=sk-or-canary-2052-0000`. Run an isolated server with `JCODE_HOME=$(mktemp -d)` and `JCODE_SOCKET=$JCODE_HOME/test.sock` so the real daemon is untouched.

1. Env inheritance (bash): start the isolated server with the canary in env, ask the model (or drive via the harness API) to run `env | grep -c canary-2052`. Expect `1` today; target `0`. Local sanity check done here with a nested shell: inheritance confirmed (`grep -c` printed 1).
2. Env set at runtime: `jcode login` with the canary into the temp `JCODE_HOME`, without restarting, then run bash `env`. Expect the canary (via `jcode-provider-env/src/lib.rs:226`).
3. `/proc` (Linux only): bash `tr '\0' '\n' < /proc/$PPID/environ | grep canary` and `grep -a canary-2052 /proc/$PPID/mem` via a small python reader of `/proc/$PPID/maps`. Expect hits today.
4. Files: bash `grep -r canary-2052 "$JCODE_HOME"`; also the `read` tool on `$JCODE_HOME/config/jcode/openrouter.env`. Expect hits.
5. MCP scrub gaps: configure an MCP stdio server that is `sh -c 'env > $OUT'`, export `CANARY_TOKEN=canary-2052` and `CANARY_SECRET=canary-2052`. Expect both present (denylist misses them), while `CANARY_API_KEY` is absent.
6. Socket spend: from bash, connect to `$JCODE_SOCKET` with `jcode` client commands (or `socat`) and send a message; point the provider base at a local fake HTTP server (`JCODE_OPENROUTER_API_BASE=http://127.0.0.1:PORT`) that logs the `Authorization` header. Expect the canary header in the log for a request initiated from the tool.
7. Debug socket toggle: bash `touch $JCODE_HOME/debug_control`, then `jcode debug ...` against the test socket. Expect commands accepted.
8. Direct egress: with the fake server above, bash `curl -H "Authorization: Bearer $OPENROUTER_API_KEY" http://127.0.0.1:PORT/` shows the tool can spend the key directly.
9. Jev host: set `JCODE_OPENROUTER_API_BASE` to the fake server, trigger a browser handoff; observe the decisions call does not arrive at the fake server (it goes to the literal openrouter.ai URL). Do this with networking blocked or DNS pointed at a sink so the canary never leaves the machine.
