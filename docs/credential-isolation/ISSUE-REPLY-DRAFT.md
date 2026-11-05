<!-- DRAFT, not posted. Operator approves posting. -->
Thanks for the triage! Here is the sketch you asked for, plus a small first step.

Files (branch `docs/credential-isolation-2052` on my fork):
- Findings with file:line: https://github.com/stevenbarragan/jcode/blob/docs/credential-isolation-2052/docs/credential-isolation/FINDINGS.md
- Simplest fix and first PR: https://github.com/stevenbarragan/jcode/blob/docs/credential-isolation-2052/docs/credential-isolation/SIMPLEST-FIX.md
- Phased design sketch (process/UID isolation, filesystem and process visibility, network policy, every credential path): https://github.com/stevenbarragan/jcode/blob/docs/credential-isolation-2052/docs/credential-isolation/DESIGN-SKETCH.md

Top findings:
1. Saving a key also exports it into the server's own env (`jcode-provider-env/src/lib.rs:226`), and bash, browser and osascript children inherit the full env (`tool/bash.rs:918`). Only MCP stdio scrubs, and its denylist misses `*_TOKEN` and `*_SECRET` (`mcp/client.rs:597`).
2. Tools run as the same uid, so they can read `~/.jcode` and `~/.config/jcode` `*.env`, `google_oauth.json`, `~/.claude/.credentials.json`, and on Linux `/proc/<server>/environ` and `mem`.
3. `JCODE_SOCKET` is in the tool env (`server/socket.rs:331`), so a tool can drive the server and spend the key, and `touch ~/.jcode/debug_control` turns on the debug socket at runtime (`server/util.rs:25`).
4. Jev decision URLs are hard-coded (`jev.rs:144,147`), so a gateway can't cover them yet. No `api_key_command` exists.

Proposed first PR (~250 lines, no architecture change): env allowlist at every tool spawn (replacing the MCP denylist, with a passthrough setting as escape hatch), stop passing `JCODE_SOCKET` by default, only honour the debug file toggle if it existed at start, and `PR_SET_DUMPABLE=0` on Linux. It comes with a canary-key test harness. To be clear about limits: it stops env and `/proc` leaks, but same-uid code can still read credential files and reach the socket. Closing that needs a different uid or a sandbox, which is PR 2 (opt-in tool uid for containers) and later the broker/executor split in the sketch. Gateway mode stays a separate, non-isolating track as you suggested.

Questions:
1. Is an env allowlist by default OK, given it can break users relying on inherited vars (`tools.env_passthrough = ["*"]` would opt out)? Or would you prefer it opt-in first?
2. Long term: broker + executor split, or sandbox the existing children only?
3. Is an opt-in `JCODE_TOOL_UID` for root-in-container acceptable before the general sandbox work?

Happy to send PR 1 if this direction works for you. We run jcode headless in containers for cookyour.app, so I can test the container path end to end.
