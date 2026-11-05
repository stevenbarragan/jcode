<!-- DRAFT, not posted. Operator approves posting. -->
Thanks for the triage! Here's the sketch you asked for. I split it into one fix plus optional hardening, so it's clear what closes this issue and what is extra.

**Phase 1, the fix (two PRs, both needed for our case):**
- **PR 1** (~250 lines, all platforms): env allowlist at every tool spawn (replacing the MCP denylist, with `tools.env_passthrough` as an escape hatch), stop passing `JCODE_SOCKET` by default, only honour `~/.jcode/debug_control` if it existed at start, and `PR_SET_DUMPABLE=0` on Linux. Ships with a canary-key test harness.
- **PR 2** (~150 lines, Linux, opt-in): `JCODE_TOOL_UID` so tools run as a second uid when the server is root in a container, plus a denylist of credential dirs for the in-process file tools and a private-range block for webfetch.

To be upfront: PR 1 alone is not the fix. Tools would still run as the same user, so they could `cat ~/.config/jcode/*.env` or drive the server socket to spend the key. PR 2 is what puts a real boundary there. One gap is left after both: a tool could still reach an injecting gateway over the network. For containers the docs cover that with a per-uid egress rule. On a laptop without root, phase 1 is only hygiene, and full protection needs a sandbox.

Docs (my fork, branch `docs/credential-isolation-2052`):
- [PHASE-1.md](https://github.com/stevenbarragan/jcode/blob/docs/credential-isolation-2052/docs/credential-isolation/PHASE-1.md): both PRs, tests, and a table mapping each threat to its phase and what's still open
- [DESIGN-SKETCH.md](https://github.com/stevenbarragan/jcode/blob/docs/credential-isolation-2052/docs/credential-isolation/DESIGN-SKETCH.md): process/uid isolation, fs and process visibility, network policy, every credential path
- [FINDINGS.md](https://github.com/stevenbarragan/jcode/blob/docs/credential-isolation-2052/docs/credential-isolation/FINDINGS.md): evidence with file:line and canary repros

**Optional hardening, take or leave any of it:**
2. `SecretStore` instead of exporting keys to env, plus a socket capability token (helps same-uid laptops)
3. Broker / executor split, one executor per session (real boundary for file tools, multi-tenant)
4. Linux sandbox: bubblewrap, Landlock, seccomp (phase 1 guarantees without root)
5. Built-in egress proxy (replaces the firewall recipe)
6. macOS Seatbelt profile
7. Gateway mode (Jev base URL, keyless boot) and `api_key_command`, kept separate and non-isolating as you suggested

Questions:
1. Is an env allowlist by default OK, or would you prefer it opt-in first? (`tools.env_passthrough = ["*"]` keeps today's behaviour.)
2. Is an opt-in `JCODE_TOOL_UID` for root-in-container acceptable before any general sandbox work?
3. Longer term, if you want the hardening: broker / executor split, or sandbox the existing children only?

Happy to send PR 1 and PR 2 if this direction works for you. We run jcode headless in containers for cookyour.app, so I can test the container path end to end.
