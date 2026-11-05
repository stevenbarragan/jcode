# Credential-free tool execution: design sketch (issue #2052)

Short sketch, as offered in the issue, to agree on the approach before code. Evidence and file:line references are in [FINDINGS.md](FINDINGS.md). No security guarantee is claimed until reviewed.

## Goal and threat model

The model, and any code it runs through tools, must not be able to read provider credentials, or spend them except through the narrow, metered path jcode itself uses for the conversation. Attacker = model-chosen tool code running with the user's workspace. Out of scope: a malicious local user with root, kernel bugs, the provider itself.

## 1. Process / UID isolation

Split today's single server into two roles:

- **Broker** (trusted): today's `jcode serve` minus tool execution of untrusted code. Holds all credentials (env, `*.env` files, OAuth tokens and refresh, Keychain, MCP remote headers, Google tokens, credential helper). Runs every credentialed HTTP call: chat, catalog, Jev decisions, Laya, usage probes, web search, compile_remote, gmail/calendar, remote MCP, telemetry.
- **Executor** (untrusted, credential-free): runs bash, background bash, MCP stdio servers, browser bridge CLI, osascript, and the file tools (read/write/edit/apply_patch/agentgrep) so path policy is enforced in one place. One executor per session (or per tenant).

IPC: one Unix socket (or inherited socketpair fd, preferred: no path to find) per executor, framed JSON with a closed request enum: `Exec`, `Kill`, `ReadFile`, `WriteFile`, `Stat`, `Stdin`, and streamed `Output`/`Exit`. The executor never sends requests to the broker except replies; it cannot ask for "a provider call". Tools that need credentials (websearch, gmail) stay in the broker and only return results.

Isolation backends, chosen by a config `tool_isolation = off | env | sandbox | uid | container`:

| Mode | Linux | macOS |
|---|---|---|
| `env` (step 0, weak) | `env_clear` + allowlist at every spawn | same |
| `sandbox` | bubblewrap (`--unshare-pid --unshare-ipc`, optional `--unshare-net`, `--die-with-parent`, ro binds), plus Landlock and a seccomp filter (deny `ptrace`, `process_vm_readv`) | Seatbelt profile via `sandbox-exec` (deny read of credential paths, deny network except proxy, deny `mach-lookup` of Keychain services) |
| `uid` | broker runs as `jcode`, executor as `jcode-tool`; spawned via a tiny setuid-free launcher started by the container entrypoint | not supported without root; use `sandbox` |
| `container` | executor in a sibling container sharing only `/workspace`, broker socket bind-mounted | Docker Desktop, same idea |

Env allowlist (all modes): `PATH HOME LANG LC_* TERM TMPDIR USER SHELL JCODE_SESSION_ID JCODE_SCRATCH_DIR` plus explicit per-session/cloud env the user opted into. Never `JCODE_SOCKET`. Replace the MCP denylist (`mcp/client.rs:597`) with the same allowlist.

## 2. Filesystem and process visibility

- Executor sees: the workspace (rw), scratch dir (rw), system dirs (ro), a fresh `$HOME` (tmpfs or `~/.jcode/executor-home/<session>`).
- Executor must not see: `~/.jcode`, `~/.config/jcode`, `~/.claude`, `~/.codex`, `~/.config/github-copilot`, `~/.aws`, `~/.config/gcloud`, `~/.ssh` (configurable), the runtime dir holding sockets, other sessions' workspaces.
- `/proc`: PID namespace (bwrap) or `hidepid=2` with a different uid; the broker sets `PR_SET_DUMPABLE=0` so even same-uid fallback modes cannot read `/proc/<broker>/mem` or `environ`.
- Broker hygiene, independent of mode: stop exporting keys into its own env (`jcode-core/src/env.rs:21` callers listed in FINDINGS 1.1); hold them in a `SecretStore` in memory; zeroize on drop.
- Remove the file toggle `~/.jcode/debug_control` (`server/util.rs:25-29`) or require it to be root/broker-owned and outside the executor's view.

## 3. Network policy

- The executor has no route to the broker's client socket or debug socket (not mounted, not in env, different uid or mount namespace).
- Default: executor network on (tools need git, package managers), but provider hosts and the local gateway are denied. Implementation: in `sandbox`/`container` mode, executor egress goes through an HTTP(S) CONNECT proxy run by the broker with a deny list (provider hosts from the catalog, `169.254.169.254`, loopback ports of the gateway and Laya) and an optional allowlist mode. Same pattern as Claude Code's sandbox proxy.
- Optional `network = none` (bwrap `--unshare-net`, Seatbelt deny network) like Codex's default.
- Note: a credential-free executor that can still reach an injecting gateway can still spend the key; the proxy deny list closes that.

## 4. Every credential-using path, routed through the broker

| Path | Today | After |
|---|---|---|
| Chat (all providers) | in server, key in process env | broker, key in `SecretStore` only |
| OAuth refresh (Anthropic, Codex, Copilot, Google, Antigravity, Muse) | in server, tokens on disk same uid | broker only; files unreadable by executor |
| Model catalog fetch (`catalog_fetch.rs`, `provider_catalog.rs:838`) | in server | broker; honour provider base URL |
| Jev decisions (`jev.rs:144,147`) | in server, literal openrouter/aimlapi hosts | broker; new `JCODE_JEV_API_BASE` (or provider base) with `trusted_gateway_base` checks |
| Laya (`jev.rs:18`) | in server, optional `LAYA_API_KEY` | broker; executor denied the Laya port |
| Usage / balance probes (`usage/*.rs`) | in server, hard-coded hosts | broker; skip or route via gateway when gateway mode |
| Web search (`websearch.rs:276`) | in server | broker (unchanged location), key out of env |
| Gmail / Calendar | in server, `google_oauth.json` same uid | broker; file hidden from executor |
| compile_remote (`compile_remote.rs:114`) | in server, `JCODE_API_KEY` | broker; executor only supplies the file list |
| Remote MCP (headers, OAuth) | in server | broker |
| Stdio MCP servers | child, denylist scrub | executor, allowlist env; per-server explicit env only |
| bash / background bash | child, full env | executor |
| browser bridge CLI, osascript | child, full env | executor; Jev decisions stay in broker |
| Telemetry, discovery, cloud-managed | in server | broker |
| Credential helper (Proposal 3, new) | absent | broker runs `api_key_command`, TTL cache |
| Gateway mode (Proposal 2) | partial base URLs, placeholder key needed | separate, documented, explicitly non-isolating; boot with `gateway set, no key` via deferred-auth path (`provider_init.rs:1871`) |

## 5. Migration plan (small PRs)

1. **Canary leak test harness** (no behaviour change): integration test that boots an isolated server (`JCODE_HOME` tmp, own socket) with canary keys and asserts, per path in FINDINGS section 7, whether the canary is visible. Initially marked `expected_leak` so it documents today's state.
2. **Env allowlist at every spawn site** (`tool_isolation = env`, default on): bash, background bash, browser, osascript, selfdev, MCP (replace denylist). Drop `JCODE_SOCKET` from tool env. Flip tests 1, 2, 5 to `must_not_leak`.
3. **Stop exporting secrets into the server env**: `SecretStore`, change the `set_var` callers. `PR_SET_DUMPABLE=0` on Linux. Remove/lock the `debug_control` file toggle.
4. **Executor process + IPC** (still same uid, mode `env`): move spawning into a `jcode tool-executor` child talking over a socketpair. Pure refactor, tests unchanged.
5. **Linux `sandbox` mode** (bubblewrap + Landlock + seccomp), filesystem view and PID namespace. Flip tests 3, 4, 6, 7.
6. **Egress proxy** with provider-host deny list; flip test 8.
7. **`uid` and `container` modes** for headless Docker (the operator's case), with a documented Dockerfile.
8. **macOS Seatbelt profile.**
9. Separate track, non-isolating: gateway mode (Jev base URL, keyless boot, docs) and the credential helper.

Tests: for each row of the table in section 4, a canary test that runs the corresponding tool in the executor and greps env, `/proc`, files, sockets and a local fake provider log for the canary; plus a negative test that the broker's own call still carries it.

## 6. Open questions for the maintainer

1. Is splitting the server into broker + executor acceptable, or do you prefer sandboxing the existing children only (cheaper, weaker: file tools stay in-process)?
2. Should file tools (read/edit/write) move to the executor, or stay in the broker with a path policy?
3. Default mode: `env` everywhere and `sandbox` opt-in at first, or `sandbox` default on Linux when bubblewrap is present?
4. Is a hard dependency on bubblewrap acceptable, or should we embed namespace setup (like Codex's Linux sandbox helper)?
5. Selfdev and `debug_socket` intentionally reach the server; should they be disabled under isolation?
6. Cloud and session env (`bash.rs:919-920`) are user-chosen secrets for tools; keep passing them through?
7. One executor per session or per server? (Per session is safer for swarms.)

## Prior art (from the issue, fetched 2026-11-02)

- Claude Code sandboxing (Seatbelt, bubblewrap, network proxy, `credentials.envVars`, `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`): https://docs.anthropic.com/en/docs/claude-code/sandboxing
- Codex CLI sandbox (Seatbelt, bubblewrap, network off by default): https://developers.openai.com/codex/agent-approvals-security, https://developers.openai.com/codex/concepts/sandboxing
- OpenHands separate runtime container: https://docs.all-hands.dev/openhands/usage/architecture/runtime
- Gateways and helpers: Claude Code `apiKeyHelper` and LLM gateway docs, Codex `[model_providers.<id>.auth] command`, Gemini CLI base URLs with https-or-loopback, Aider, Goose, LiteLLM virtual keys (links in the issue); jcode #325, #771, #1869.
- OWASP LLM02 Sensitive Information Disclosure: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
