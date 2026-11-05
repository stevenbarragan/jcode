# Handoff for the build agent (#2052)

Wait for the maintainer's answer on the issue before opening an upstream PR.

## PR order
1. Tool env allowlist + socket/debug hygiene + `PR_SET_DUMPABLE` (SIMPLEST-FIX.md). Harness first.
2. Opt-in `JCODE_TOOL_UID` for Linux root-in-container; file tools deny credential dirs.
3. `SecretStore` + socket capability token. Then executor split, bwrap sandbox, egress proxy, Seatbelt (DESIGN-SKETCH.md section 5).

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
