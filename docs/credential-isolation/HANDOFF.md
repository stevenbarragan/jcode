# Handoff for the build agent (#2052)

Wait for the maintainer's answer on the issue before opening an upstream PR.

## PR order
Phase 1 (the fix, both PRs required for the container case; spec in PHASE-1.md):
1. Tool env allowlist + socket/debug hygiene + `PR_SET_DUMPABLE`. Harness first. Not a fix on its own: do not describe it upstream as closing #2052.
2. Opt-in `JCODE_TOOL_UID` for Linux root-in-container: credential-dir startup check, file-tool denylist (after symlinks), webfetch private-range block, egress recipe in docs. Also verify browser daemon sockets and the harness API server are not reachable cross-uid (PHASE-1 table row 6b).

Optional hardening, only if the maintainer asks (DESIGN-SKETCH.md section 5): 2 `SecretStore` + socket token, 3 executor split, 4 bwrap sandbox, 5 egress proxy, 6 Seatbelt, 7 gateway track.

## Write first: canary harness
`crates/jcode-app-core/tests/credential_canary.rs`: isolated `JCODE_HOME=tempdir`, `JCODE_SOCKET` inside it, fake key `sk-canary-2052-0000` only. One test per FINDINGS section 7 item, `#[ignore = "expected_leak"]` until its PR flips it. Never touch the real `~/.jcode` or the running server.

## Files to touch (PR 1)
- new `crates/jcode-core/src/child_env.rs` (allowlist + passthrough), export in `lib.rs`
- `crates/jcode-app-core/src/tool/bash.rs` (:661/678 build, :706, :918, :1160, :1321)
- `crates/jcode-app-core/src/tool/browser.rs:982`, `tool/computer/osa.rs:97`, `tool/desktop_selfdev.rs:448`
- `crates/jcode-base/src/mcp/client.rs:216, 597-619` (replace denylist)
- `crates/jcode-app-core/src/server/util.rs:13-31` (snapshot file toggle at start)
- `jcode serve` startup (`server/lifecycle.rs`): `prctl(PR_SET_DUMPABLE, 0)` on Linux unless `JCODE_ALLOW_DUMP=1`
- config: `tools.env_passthrough` in `jcode-config-types`, default file docs
- swarm/communicate tests set `JCODE_SOCKET` on the server env, not the child's: confirm they still pass
