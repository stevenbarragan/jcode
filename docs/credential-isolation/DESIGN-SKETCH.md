# Credential-free tool execution: design sketch (issue #2052)

Short sketch, as offered in the issue, to agree on the approach before code. Phase 1 ([PHASE-1.md](PHASE-1.md)) is the fix; sections 1-4 describe the end state that the optional hardening phases (section 5) build toward. Evidence and file:line references are in [FINDINGS.md](FINDINGS.md). No security guarantee is claimed until reviewed.

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
| `env` (PR 1, weak alone) | `env_clear` + allowlist at every spawn | same |
| `sandbox` | bubblewrap (`--unshare-pid --unshare-ipc`, optional `--unshare-net`, `--die-with-parent`, ro binds), plus Landlock and a seccomp filter (deny `ptrace`, `process_vm_readv`) | Seatbelt profile via `sandbox-exec` (deny read of credential paths, deny network except proxy, deny `mach-lookup` of Keychain services) |
| `uid` (PR 2) | broker runs as `jcode`, executor as `jcode-tool`; spawned via a tiny setuid-free launcher started by the container entrypoint | not supported without root; use `sandbox` |
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

## 5. Phases: one fix, then optional hardening

**Phase 1 is the fix** for the issue's use case (headless Linux containers): PR 1 + PR 2, specified in [PHASE-1.md](PHASE-1.md) together with the threat-by-threat residual table. PR 1 alone is not the fix: same-uid tools can still read credential files and drive the socket. Everything after phase 1 is **optional hardening**: each item adds a boundary for a different audience, and none is needed to close the container case.

| Phase | What | Adds | Who needs it | Why it can wait | Flips canary tests |
|---|---|---|---|---|---|
| **1 (the fix)** | PR 1 env allowlist, socket/debug hygiene, `PR_SET_DUMPABLE`. PR 2 opt-in `JCODE_TOOL_UID`, credential-dir check, file-tool denylist, webfetch private-range block, egress recipe | key not readable or spendable by tools in a root-run container | headless / container operators (the issue) | - | 1-7; 8 with the recipe |
| 2, optional | `SecretStore` replaces `set_var` of keys (10 call sites); per-connection socket capability token | key out of server env; socket needs a token, so laptops gain socket protection | defence in depth; same-uid laptop users | phase 1 already keeps the key from children; large diff across every provider | 6 without uid |
| 3, optional | executor split: `jcode tool-executor` per session over an inherited socketpair; bash, MCP stdio, browser, osascript and file tools move there | file-tool denylist becomes a real boundary; per-session isolation in the shared server | multi-tenant servers, swarms | pure refactor, big; phase 1 denylist covers the known paths | 4b, cross-session |
| 4, optional | Linux sandbox: bubblewrap + Landlock + seccomp, fresh `$HOME`, PID namespace | phase 1 guarantees without root or a second uid | Linux desktop users | containers already have the uid boundary | 3, 4 without root |
| 5, optional | egress: broker CONNECT proxy, provider hosts and gateway ports denied | built-in network policy, replaces the operator's iptables recipe | anyone with a reachable gateway who can't set firewall rules | container operators can use the recipe today | 8 |
| 6, optional | macOS Seatbelt profile (deny credential paths, Keychain lookups, network except proxy) | same as phase 4 on macOS | macOS users | not the container case | 4, 8 on macOS |
| 7, separate track | gateway mode (Jev base URL, keyless boot) and `api_key_command` | key off the jcode host; short-lived tokens | gateway operators | non-isolating by itself, as triage suggested | 9 |

Test numbers refer to FINDINGS section 7. The harness lands in PR 1 with every test `expected_leak` until its phase flips it. Out of scope: root in the container, kernel bugs, the provider, secrets in the workspace, Windows.

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
