# Security policy

arkup verifies Ed25519 signatures and unpacks attacker-controllable archives as
root. A bug in `src/archive.rs` (framing, size limits, extension handling) or
`src/install.rs` (path resolution, protected-path checks, rollback) is a local
or remote root compromise on every system that applies an update. Please treat
such bugs as security issues rather than ordinary defects.

## Reporting a vulnerability

Do **not** open a public GitHub issue for a security bug.

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**), or email the maintainers directly.

Please include:

1. The affected commit or release, and `arkup --version`.
2. Which trust boundary is crossed. In particular, say whether the attack
   needs (a) a valid signature from a trusted key, (b) only an unsigned
   `.aup` file, (c) local write access to the target root, or (d) nothing but
   the pack file.
3. A minimal reproducer. For pack-format bugs, the smallest `.aup` that
   triggers it, or the `arkup pack` invocation plus the tar/gzip bytes that
   were rewritten (see `rewrite_archive` in `src/archive.rs` tests for the
   existing pattern).
4. Whether the failure is in verification (`verify_archive*`) or in the
   second, payload-streaming pass (`for_each_payload`). Both must reject the
   same inputs; a divergence between them is itself a reportable bug.

## Scope

In scope, among others:

- Signature or manifest validation bypasses, including manifest fields that
  are checked in one code path but not another.
- Path traversal, symlink redirection, or writes outside the target root.
- Writes to protected paths, including through directory aliases
  (`PROTECTED_PATHS` in `src/manifest.rs`, `resolve_protected_path` in
  `src/install.rs`).
- Unbounded resource use while parsing a pack: decompressed size, extension
  metadata, manifest size, or entry count.
- Trust-store bypasses, or a way to make `arkup` accept a key that is not in
  `etc/arkup/trustedkeys.d`.
- Key-generation weakness or private-key disclosure.
- Rollback that leaves a system in a worse state than before the update.

Out of scope:

- Attacks that require an already-trusted signing key. That key is the root of
  trust; anything it signs is by design installable.
- Behavior that requires root on the target system already.
- Denial of service against a machine applying a pack it chose to apply,
  unless it is triggered by merely inspecting a pack with `verify` or `list`.

## What to expect

- Acknowledgement within five business days.
- A fix on a private branch, followed by a public advisory and a release.
- Credit in the advisory for reporters who want it.

Until a fix ships, mitigate by keeping release signing keys offline, only
trusting keys distributed through a channel you control, and verifying packs
on a separate machine before applying them.
