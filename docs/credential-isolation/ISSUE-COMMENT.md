Thanks for the careful triage. Below is the design sketch you asked for, covering process/UID isolation, filesystem and process visibility, network policy and every credential-using provider path, with what I found in the current code. Nothing here asks for approval or implies a guarantee yet: I'd like us to agree on the boundary first. Gateway configuration is tracked separately in section 8, explicitly as a non-isolating improvement, as you recommended.

All file:line references are against upstream `master` at `c725fa315`. No real credential was read or printed while investigating: only variable names and paths, and the repros use a fake key (`sk-canary-2052-0000`).

## 1. Trust boundary and threat model

**What we protect:** provider credentials (API keys, OAuth access and refresh tokens, client secrets) and their spending power.

**From whom:** model-chosen tool execution, which includes anything a prompt injection in a web page, repo file or MCP result can get the model to run. The attacker can run arbitrary code with the workspace, as a tool.

**Goal:** a tool can neither **read** a credential nor **spend** it, other than through the metered conversation jcode itself drives.

<details><summary>In scope, out of scope, deployment modes</summary>

In scope: bash (foreground and background), MCP stdio servers, browser bridge, osascript, desktop selfdev, the in-process file tools and webfetch, local sockets, `/proc`, credential files, egress.

Out of scope: root inside the container, kernel bugs, a malicious provider, secrets the user puts in the workspace (tools are meant to read the workspace), Windows for now.

Two deployment modes, with honestly different ceilings:

- **Headless Linux container** (my case: I run jcode headless in containers for cookyour.app). The server can run as root or a dedicated uid and tools as a second uid. This can be made a real boundary with ordinary file permissions.
- **Laptop, same user, no root** (macOS or Linux desktop). Tools run as the user who owns the credentials. Against same-uid code without a sandbox, credentials cannot be fully protected. Env scrubbing helps, but a real boundary needs a sandbox (bubblewrap/Landlock on Linux, Seatbelt on macOS).

</details>

## 2. Findings (current state)

In one line: jcode has a single trust domain. `jcode serve` holds every credential in its own env and memory and runs model-chosen tools as plain children with the same uid. Keys loaded from `*.env` files are copied into the process env on purpose, so every child inherits them. Only MCP stdio scrubs, and only by a denylist.

In my own session, `env | cut -d= -f1` inside the bash tool listed a dozen provider key names plus `JCODE_SOCKET` (values not printed). The parent was the shared server, same user.

Repro setup for every row: an isolated server, `JCODE_HOME=$(mktemp -d)`, `JCODE_SOCKET=$JCODE_HOME/test.sock`, fake keys only, so the real daemon is never touched.

| # | Path | Exposure | Repro (canary) |
|---|---|---|---|
| 1 | Env inheritance: bash spawn `crates/jcode-app-core/src/tool/bash.rs:918` (bg: `:706`, `:1160`, `:1321`), browser `tool/browser.rs:982`, osascript `tool/computer/osa.rs:97`, selfdev `tool/desktop_selfdev.rs:448` | No `env_clear`, full server env inherited | Start with `OPENROUTER_API_KEY=sk-or-canary-2052-0000`, bash tool `env \| grep -c canary-2052` prints `1` |
| 2 | Runtime export: `crates/jcode-provider-env/src/lib.rs:221-226` (`save_env_value_to_env_file` then `set_var`), choke point `crates/jcode-core/src/env.rs:21`; other callers `jcode-base/src/provider/activation.rs:285`, `auth/lifecycle.rs:1148`, `provider/openai.rs:328`, `provider_activity.rs:411`, `copilot_usage.rs:121`, `sidecar.rs:1311`, `src/cli/commands/provider_setup.rs:624`, `jcode-app-core/src/server/lifecycle.rs:311`, `tool/selfdev/reload.rs:549` | A key saved or activated later is inherited by every later child | `jcode login` the canary into the temp home without restarting, then bash `env` shows it |
| 3 | MCP stdio scrub `crates/jcode-base/src/mcp/client.rs:597-619` (spawn `:216`) | Suffix denylist (`*_API_KEY`, `*_ACCESS_TOKEN`, `*_AUTH_TOKEN`, cloud names) misses `*_TOKEN` (for example `GITHUB_TOKEN`), `*_SECRET`, `*_PASSWORD`, `*_KEY` | MCP server `sh -c 'env > $OUT'` with `CANARY_TOKEN`, `CANARY_SECRET`, `CANARY_API_KEY` set: first two present, third absent |
| 4 | Credential files, same uid (list below) | Readable by bash and by the in-process read/edit/agentgrep tools | `grep -r canary-2052 "$JCODE_HOME"`, and the `read` tool on `$JCODE_HOME/config/jcode/openrouter.env` |
| 5 | `/proc/<server>/environ` and `/proc/<server>/mem` (Linux) | Same uid and an ancestor, so even Yama `ptrace_scope=1` allows it. `environ` holds the initial env, `mem` holds keys set later | `tr '\0' '\n' < /proc/$PPID/environ \| grep canary`, and a small reader over `/proc/$PPID/maps` grepping `mem` |
| 6 | `JCODE_SOCKET` exported: `crates/jcode-app-core/src/server/socket.rs:331-332` (`set_socket_path` calls `set_var`, so children inherit it) | Socket is `0600` in a `0700` dir, which stops other uids but not the tool. A tool can speak the client protocol and have the server make authenticated calls: the key is spent, not seen | Point the provider base at a local fake server that logs `Authorization`, drive a prompt from bash over `$JCODE_SOCKET`, canary header appears |
| 7 | Runtime debug toggle: `crates/jcode-app-core/src/server/util.rs:13-31`, file check at `:25-29` | `touch ~/.jcode/debug_control` enables debug socket commands with no restart | Touch the file in the temp home from bash, then `jcode debug ...` against the test socket is accepted |
| 8 | Direct egress | Nothing restricts tool network. With the key, `curl` spends it. Without the key, a tool can still call an injecting gateway or loopback proxy. Webfetch reaches loopback and `169.254.169.254` | bash `curl -H "Authorization: Bearer $OPENROUTER_API_KEY" http://127.0.0.1:PORT/` against the fake server |
| 9 | Hard-coded hosts: Jev decisions `crates/jcode-base/src/jev.rs:144` (`https://openrouter.ai/api/alpha/decisions`), `:147` (aimlapi), others in section 6 | Bypasses any per-provider base URL, so a gateway setup still needs a real key for these and sends it to the vendor | Set `JCODE_OPENROUTER_API_BASE` to the fake server, trigger a browser handoff, the decisions call never arrives (do this with DNS sunk) |
| 10 | Other local endpoints: browser session daemon sockets, `crates/jcode-harness-api-server` | Same-uid reachable. Not yet verified per endpoint | To check in PR 2 |
| 11 | Shared server across sessions and swarm workers | One session's tools see every other session's env, workspace and processes (`ps eww`, `/proc/*/cmdline`) | `ps eww` from bash |

<details><summary>Every credential file readable by the tool uid today</summary>

- `~/.jcode/` (`crates/jcode-storage/src/lib.rs:163-169`, `JCODE_HOME` override) and `~/.config/jcode/` (`:221-227`), including `<provider>.env` written by `jcode login` (`src/cli/login.rs:598` openai, `:656` anthropic, `:701` openrouter, `:739`). Files are written owner-only (`jcode-storage/src/lib.rs:569-614`), which does not help against the same uid.
- `auth.json`, `openai-auth.json`, `anthropic.env`, `openai.env`, `config.toml` (`crates/jcode-base/src/auth/transfer.rs:48-49`).
- Google: `~/.jcode/google_credentials.json` (client secret) and `~/.jcode/google_oauth.json` (access and refresh token) (`crates/jcode-base/src/auth/google.rs:225-229`).
- Claude Code reuse: `~/.claude/.credentials.json`, and the macOS Keychain via `/usr/bin/security find-generic-password -w` (`crates/jcode-base/src/auth/claude.rs:165`, `:756-765`, `:836`).
- Copilot: `~/.config/github-copilot/hosts.json`, optional `gh auth token` (`crates/jcode-base/src/auth/copilot.rs:86`, `:152-155`, `:465`).
- Codex/OpenAI OAuth (`auth/codex.rs`), Antigravity (`auth/antigravity.rs`), Muse (`auth/muse.rs`), Cursor (`crates/jcode-provider-cursor-runtime`), Bedrock AWS creds (`~/.aws`), Azure (`crates/jcode-azure-auth`), external auth and keyring helpers (`crates/jcode-base/src/external_auth.rs`, `jcode-storage/src/lib.rs:309-394`).
- MCP remote OAuth tokens and static headers (`crates/jcode-base/src/mcp/oauth.rs`), plus per-server stdio `env` in MCP config.
- `laya.env` with optional `LAYA_API_KEY` (`crates/jcode-base/src/config/default_file.rs:633`).

</details>

<details><summary>What already exists</summary>

MCP stdio denylist (#771), transcript redaction (`crates/jcode-base/src/session_redaction.rs`), the outbound discovery secret filter (`tool/discover_secrets.rs`), owner-only credential files, Copilot not calling `gh auth token` unless opted in, and URL checks for Jev's gateway base and Laya (`trusted_gateway_base`, #1869). Nothing scrubs bash, browser, osascript or selfdev children, and there is no uid separation, sandbox or network policy.

</details>

## 3. Process/UID isolation

Target design, two roles:

- **Broker** (trusted): today's `jcode serve` minus untrusted execution. Holds every credential and makes every credentialed call (section 6), including OAuth refresh and, later, a credential helper.
- **Executor** (credential-free): runs bash, background bash, MCP stdio servers, the browser bridge CLI, osascript and the file tools. One per session (or tenant), so sessions are isolated from each other too.

<details><summary>IPC and per-OS uid modes</summary>

**IPC:** an inherited `socketpair` fd per executor (no path to discover), framed JSON with a closed request enum: `Exec`, `Kill`, `Stdin`, `ReadFile`, `WriteFile`, `Stat`, and streamed `Output`/`Exit` back. The executor only replies. There is no "make a provider call" request, so tools that need credentials (websearch, gmail, compile_remote) stay in the broker and return results only.

**Env:** every spawn does `env_clear()` and an allowlist: `PATH HOME USER LOGNAME SHELL LANG LC_* TERM COLORTERM TMPDIR TZ JCODE_SESSION_ID JCODE_SCRATCH_DIR`, plus a `tools.env_passthrough` list (names or `PREFIX_*`, `["*"]` restores today's behaviour), plus explicit extras (cloud env, session env, MCP server `env`). Never `JCODE_SOCKET` by default.

**Modes** (`tool_isolation = off | env | uid | sandbox | container`):

| Mode | Linux | macOS |
|---|---|---|
| `env` | allowlist at every spawn. Hygiene only, same uid | same |
| `uid` | containers: server as root or `jcode`, tools as `jcode-tool` via `setgroups([])`, `setgid`, `setuid`, `PR_SET_NO_NEW_PRIVS` in `pre_exec` | not possible without root |
| `sandbox` | no root needed: bubblewrap (`--unshare-pid --unshare-ipc`, optional `--unshare-net`, `--die-with-parent`, ro binds) plus Landlock and seccomp (deny `ptrace`, `process_vm_readv`) | Seatbelt profile: deny credential paths, Keychain `mach-lookup`, network except a local proxy |
| `container` | executor in a sibling container sharing only `/workspace` | same with Docker Desktop |

**Honest limit:** on a laptop in `env` mode the tool is still the user, so it can read files and drive the socket. Only `sandbox` closes that there.

</details>

## 4. Filesystem and process visibility

<details><summary>What the executor sees, per mode</summary>

- **Sees:** the workspace (rw), the scratch dir (rw), system dirs (ro), a fresh `$HOME` (tmpfs or a per-session dir).
- **Denied:** `~/.jcode`, `~/.config/jcode`, `~/.claude`, `~/.codex`, `~/.config/github-copilot`, `~/.aws`, `~/.config/gcloud`, `~/.ssh` (configurable), the socket runtime dir, other sessions' workspaces.
- **`uid` mode:** denial is plain permissions. Startup refuses to run if any of those dirs is readable by the tool uid, naming the path. In-process file tools still run as the server until the executor split, so they get a denylist of the same dirs resolved after symlinks: a denylist, not a boundary.
- **`sandbox` mode:** a private mount namespace without those dirs, Landlock as a second layer, PID namespace.
- **Process visibility:** the server calls `prctl(PR_SET_DUMPABLE, 0)` at startup on Linux (opt out `JCODE_ALLOW_DUMP=1`), which blocks same-uid `/proc/<server>/{environ,mem}`, `ptrace` and `process_vm_readv`, and holds for root-in-container because Docker drops `CAP_SYS_PTRACE`. In `uid` mode `/proc` is cross-uid anyway, and `hidepid=2` or a PID namespace hides other sessions. macOS has no equivalent for `ps -E`, so there env scrubbing is what keeps keys out.
- **Broker hygiene:** stop `set_var`-ing keys (the callers in row 2), keep them in an in-memory `SecretStore`, zeroize on drop. The debug file toggle only counts if it existed at server start (or is removed).

</details>

## 5. Network policy

<details><summary>Egress, webfetch and the container recipe</summary>

- The executor has no route to the broker's client or debug socket: not in env, not mounted, other uid or mount namespace.
- Tools keep network by default (git, package managers), but provider hosts, the local injecting gateway, Laya's port and cloud metadata are denied. A credential-free tool that can reach an injecting gateway can still spend the key, so this is part of the fix, not an extra.
- Built-in option (later): a broker-run HTTP(S) CONNECT proxy for the executor, with a deny list from the provider catalog plus gateway/metadata addresses and an optional allowlist mode. Optional `network = none`.
- Webfetch runs in-process, so in `uid` mode it refuses loopback, link-local (`169.254.0.0/16`) and private ranges unless `tools.webfetch_allow_private` lists the host, using the same checks as `trusted_gateway_base` / #1869.
- Container recipe until the proxy exists (needs `NET_ADMIN` at start, or the equivalent pod network policy):

  ```sh
  # tools run as uid 1001: no injecting gateway on :8787, no cloud metadata
  iptables -A OUTPUT -m owner --uid-owner 1001 -p tcp --dport 8787 -j REJECT
  iptables -A OUTPUT -m owner --uid-owner 1001 -d 169.254.169.254 -j REJECT
  ```

</details>

## 6. Every credential-using provider path

<details><summary>Complete table</summary>

| Path | Where the credential lives today | Who calls it today | After the broker | Notes |
|---|---|---|---|---|
| Chat providers (all) | process env, `~/.config/jcode/*.env`, OAuth json | server | broker, `SecretStore` only | |
| OAuth refresh (Anthropic `auth/oauth.rs:23`, Codex, Copilot, Google `auth/google.rs:7`, Antigravity, Muse) | refresh tokens in memory and on disk | server | broker, files hidden from executor | refresh must move with the credential |
| Model catalog (`jcode-provider-openrouter-runtime/src/catalog_fetch.rs:14,273`, `jcode-base/src/provider_catalog.rs:838`, `jcode-provider-metadata/src/catalog.rs`) | env / catalog `env_file` (`src/cli/provider_init.rs:838-842`) | server | broker, honours base URL | |
| Jev decisions (`jcode-base/src/jev.rs:115` key, `:144` openrouter, `:147` aimlapi, `:148` jcode gateway via `trusted_gateway_base`) | env or env file | server (browser handoff, memory, voice) | broker | hosts hard-coded (gateway track) |
| Laya (`jev.rs:18-19`, default `http://127.0.0.1:8080`) | optional `LAYA_API_KEY` in `laya.env` | server | broker, executor denied the port | |
| Web search (`tool/websearch.rs:276` `api_key_env`, `:298` Bing, `:385` SearXNG, `websearch_kagi.rs`) | env | server | broker, key out of env | |
| Gmail / Calendar (`tool/gmail.rs`, `tool/calendar.rs`) | `google_credentials.json`, `google_oauth.json` | server | broker, files hidden | |
| compile_remote (`tool/compile_remote.rs:114,233,292`) | `JCODE_API_KEY`, `JCODE_API_BASE` | server | broker, executor supplies only the file list | |
| Discovery (`jcode-config-types/src/lib.rs:985`), cloud managed (`src/cli/cloud_managed.rs:23`, `jcode-sdk/src/cloud.rs:213`) | jcode key / account | server | broker | |
| Telemetry (`jcode-telemetry-core/src/lib.rs:43-44`, `usage_outbox.rs:267`, `oauth_account.rs:185,213`) | OAuth account label | server | broker | no provider key observed |
| Usage / balance probes (`jcode-base/src/usage/api_keys.rs:140,181,338,442,699`, `usage/provider_fetch.rs:740`, `usage.rs:63`) | env / OAuth | server | broker; skipped or via gateway in gateway mode | hard-coded hosts |
| Anthropic side endpoints (`jcode-provider-anthropic-runtime/src/lib.rs:63-66,386,396,406,438`) | OAuth / key | server | broker | hard-coded |
| Copilot (`auth/copilot.rs:45` token exchange, `:48`, `:1032`) | `hosts.json`, optional `gh auth token` | server | broker | |
| Muse (`auth/muse.rs:18,75`), Cursor (`jcode-provider-cursor-runtime/src/lib.rs:29`, `agent_transport.rs:1694,1740`), Bedrock, Azure | files / AWS / Azure creds | server | broker | |
| Claude Code reuse (`auth/claude.rs:165,756-765,836`) | `~/.claude/.credentials.json`, macOS Keychain | server | broker; never copied into env | Keychain is same-uid reachable on macOS without Seatbelt |
| MCP remote (`mcp/oauth.rs`, static headers) | config and token files | server | broker | |
| MCP stdio servers (`mcp/client.rs:216`) | denylist-scrubbed env + per-server `env` | child, same uid | executor, allowlist env plus explicit per-server env only | |
| Browser bridge CLI (`tool/browser.rs:982`) | full env inherited | child | executor; Jev decisions stay in broker | |
| bash, osascript, selfdev | full env inherited | child | executor | cloud/session env (`bash.rs:919-920`) is user-chosen and stays opt-in |
| Credential helper (`api_key_command`) | does not exist | | broker, TTL cache, never in executor | gateway track |
| Update checks (`update.rs:207,270`) | none | server | unchanged | unauthenticated |

</details>

## 7. Proposed delivery, small reviewable PRs

**Phase 1 is two PRs, and both are needed for the container case.**

- **PR 1, every platform (~250 lines): env allowlist, socket and debug hygiene, non-dumpable.** New `crates/jcode-core/src/child_env.rs` with the allowlist from section 3, called at every spawn in rows 1 and 3 (replacing the MCP denylist). `JCODE_SOCKET` not in the default allowlist (swarm-from-bash users add it). Debug file toggle only if present at start. `PR_SET_DUMPABLE=0` on Linux. **Closes** rows 1, 2, 3, 7, and 5 on Linux. **Stays open:** a same-uid tool can still `cat ~/.config/jcode/openrouter.env` and drive the socket (the path is guessable). PR 1 alone is hygiene, not the fix: it moves the leak from `env` to `cat`, and I wouldn't describe it as closing this issue.
- **PR 2, Linux, opt-in (~150 lines): tool uid for containers.** `JCODE_TOOL_UID`/`JCODE_TOOL_GID` when the server runs as root: drop to that uid at every spawn, refuse if it equals the server's, startup check that credential dirs are unreadable by it, file-tool denylist after symlinks, webfetch private-range block, the egress recipe in docs, and a check of each local endpoint in row 10. **Closes** rows 4, 5, 6 and the webfetch half of row 8 in containers, and the rest of row 8 with the recipe. **Stays open:** the file-tool denylist is a list, not a boundary, all sessions share one tool uid, laptops get nothing beyond PR 1.

<details><summary>Optional hardening, PRs 3-7</summary>

| PR | What | Adds | Who needs it |
|---|---|---|---|
| 3 | `SecretStore` replaces `set_var` of keys at the ~10 call sites; per-connection socket capability token | keys out of server env; the socket needs a token, so same-uid laptops gain socket protection | defence in depth, laptop users |
| 4 | broker/executor split: `jcode tool-executor` per session over an inherited socketpair; bash, MCP stdio, browser, osascript and file tools move there | file-tool policy becomes a real boundary; per-session isolation in the shared server | multi-tenant servers, swarms |
| 5 | Linux sandbox: bubblewrap + Landlock + seccomp, fresh `$HOME`, PID namespace | phase 1 guarantees without root or a second uid | Linux desktop users |
| 6 | egress proxy run by the broker, provider hosts and gateway ports denied | built-in network policy, replaces the iptables recipe | anyone who can't set firewall rules |
| 7 | macOS Seatbelt profile (credential paths, Keychain lookups, network except proxy) | PR 5 equivalent on macOS | macOS users |

</details>

<details><summary>Tests: canary harness first</summary>

The harness lands first, in PR 1: `crates/jcode-app-core/tests/credential_canary.rs`, isolated `JCODE_HOME` tempdir, socket inside it, fake key `sk-canary-2052-0000` only, never the real `~/.jcode` or a running server. One test per row in section 2, each `#[ignore = "expected_leak"]` until its PR flips it, so every PR shows exactly which leak it closes.

- PR 1 unit: `child_env_drops_secrets` (`OPENAI_API_KEY`, `HUGGINGFACE_TOKEN`, `FOO_SECRET`, `JCODE_SOCKET` absent, `PATH`/`HOME` kept), `passthrough_glob_and_star`.
- PR 1 integration: `bash_tool_env_has_no_canary`, `runtime_set_var_not_inherited`, `mcp_stdio_env_has_no_token_or_secret`, `debug_control_file_after_start_ignored`, Linux `proc_environ_and_mem_denied`.
- PR 2, Linux root CI job: `tool_uid_cannot_read_env_files`, `tool_uid_cannot_connect_socket`, `file_tool_denies_credential_dir` (incl. symlink), `webfetch_denies_loopback_in_tool_uid_mode`, `egress_recipe_blocks_gateway` (fake gateway logs `Authorization`, expects no request from the tool).

</details>

## 8. Gateway configuration (separate, non-isolating)

Kept apart as you suggested. It moves the key off the jcode host, but it is **not a security boundary**: without section 5, a tool can still spend through the gateway.

<details><summary>Proposed items</summary>

- Per-provider base URLs everywhere a host is hard-coded today, including Jev (`jev.rs:144,147`, e.g. `JCODE_JEV_API_BASE`), usage probes and Anthropic side endpoints, with the existing https-or-loopback checks from `trusted_gateway_base` / #1869.
- Keyless boot when a gateway is set: reuse the deferred-auth path (`src/cli/provider_init.rs:1871`, "No credentials configured") instead of needing a placeholder key, and skip usage/balance probes.
- `api_key_command` with a TTL cache (nothing like it exists today), run by the server or later the broker, never inside a tool.

</details>

## 9. Residual risk

<details><summary>Threat by threat, assuming a Linux container with PR 1 + PR 2 and the egress recipe</summary>

| Threat (row) | Closed by | Residual after phase 1 |
|---|---|---|
| Key in tool env (1) | PR 1 | none |
| Runtime-set key inherited (2) | PR 1 | none for children; key still in server memory until PR 3 |
| `/proc` environ and mem (5) | PR 1 non-dumpable, PR 2 other uid | none |
| MCP stdio misses `*_TOKEN`, `*_SECRET` (3) | PR 1 | none |
| Credential files via bash (4) | PR 2 | none; secrets in the workspace stay readable (out of scope) |
| Credential files via in-process file tools (4) | PR 2 denylist | a missed path leaks; PR 4 makes it a boundary |
| Tool drives the server socket (6) | PR 2 | none in containers; laptops open until PR 3 or PR 5 |
| Other local endpoints (10) | PR 2, if uid-protected Unix sockets | unverified until PR 2 checks each |
| Debug file toggle (7) | PR 1 | none |
| Direct egress or injecting gateway (8) | PR 1 + 2 plus recipe | relies on operator firewall config until PR 6 |
| Webfetch to loopback or metadata (8) | PR 2 | none in tool uid mode |
| Cross-session visibility (11) | not phase 1 | one session's tools can read another's workspace until PR 4 |
| Hard-coded hosts (9) | gateway track | config gap, not a leak to the model |
| macOS Keychain | PR 7 | n/a in containers |
| Root in container, kernel, provider, Windows | out of scope | |

</details>

## 10. Open questions

1. Is a broker/executor split acceptable as the long-term shape, or would you rather only sandbox the existing children (cheaper, weaker: file tools stay in-process)?
2. Is an opt-in `JCODE_TOOL_UID` for root-in-container an acceptable first boundary, given it does nothing on laptops?
3. Should `JCODE_SOCKET` leave the default tool env (swarm-from-bash would need passthrough), and should selfdev and `debug_socket` be disabled under isolation?
4. For Linux sandboxing later, is a dependency on bubblewrap fine, or would you prefer embedded namespace setup?
5. Executors per session or per server? Per session is safer for swarms.

If the boundary above looks right to you, I'm happy to send PR 1 (harness first, every leak test marked `expected_leak`) and then PR 2. I won't start on implementation until you've reviewed this and we agree on the approach.
