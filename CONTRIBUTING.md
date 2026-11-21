# Contributing to arkup

arkup installs signed system updates as root. Reviewers will read a change
assuming it is hostile input until the tests prove otherwise, so please write
the tests first and mention them in the PR description.

## Development setup

Rust 1.85 or newer (the crate uses edition 2024):

```sh
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

Use `CARGO_BUILD_JOBS=1` on memory-limited hosts. CI runs all four commands
plus an MSRV build on 1.85, so a change that only passes locally on `stable`
will still fail.

One test needs root and is `#[ignore]`d:

```sh
sudo -E env "PATH=$PATH" cargo test -- --ignored
```

It covers ownership restoration during rollback. CI runs it in the
`rollback-ownership-as-root` job; please keep it passing if you touch
`restore_change`.

## Where things live

| Path | Responsibility |
| --- | --- |
| `src/main.rs` | CLI parsing and output only. No filesystem logic. |
| `src/manifest.rs` | Manifest schema and validation, `PROTECTED_PATHS`. |
| `src/archive.rs` | Packing, signature checking, bounded tar/gzip framing. |
| `src/install.rs` | Trust store, path resolution, apply, rollback, records. |
| `src/install/destination.rs` | `openat`-relative staging bound to a checked parent. |
| `src/key.rs` | Ed25519 key loading, generation, signing, verification. |
| `tests/cli.rs` | End-to-end CLI tests through the real binary. |

## Rules that a change must not break

These are invariants the existing tests assert. If your change weakens one,
say so explicitly in the PR description and explain why it is still safe.

1. **Verification happens twice.** `verify_archive_with_key` checks the whole
   archive, then `for_each_payload` streams it again during apply and re-checks
   that the embedded manifest still equals the verified one. Both passes must
   reject the same inputs. A new entry type or header form needs handling in
   both.
2. **Nothing resolves a path twice.** `Destination` keeps the checked parent
   directory open and every later operation is `openat`-relative to it. Do not
   reintroduce pathname-based staging, install, delete, or restore.
3. **Every payload bound is enforced before the body is read.** Sizes, entry
   counts, extension metadata, and decompressed totals are checked in
   `BoundedArchiveReader::next_header`, before tar can buffer a body.
4. **Protected paths are protected physically, not lexically.** A pack may
   reach a protected location through a directory symlink. New resolution code
   must go through `check_destination`.
5. **Failures roll back.** Any change that mutates the target root must push
   onto `changes` (or `created_directories`) before it can fail, so
   `rollback` can undo it.
6. **No new `unsafe` without a reason.** The existing `unsafe` blocks wrap
   `libc` syscalls that `rustix` does not expose. Prefer `rustix`; if you must
   add one, add a `// SAFETY:` comment naming what stays valid.

## Adding tests

- Pack-format and traversal attacks belong in `src/archive.rs` tests next to
  `rewrite_archive`, and must assert rejection in *every* pass that reads the
  archive. See `rejects_nonempty_symlink_bodies_in_every_archive_pass` and
  `rejects_oversized_extensions_in_every_archive_pass` for the shape.
- Install-time behavior belongs in `src/install.rs` tests, using
  `tempfile::tempdir()` roots. Never write to a real `/`.
- CLI surface, exit codes, and stdout/stderr wording belong in `tests/cli.rs`.
- Diagnostics echo attacker-controlled strings. Assert that control characters
  cannot escape into a terminal; see
  `rejects_unsigned_manifest_path_control_characters_in_diagnostics`.

## Pull requests

- One concern per PR. Security fixes go through `SECURITY.md` first.
- Keep `cargo fmt` clean; CI enforces it.
- Update `README.md` when you change operator-visible behavior: CLI flags,
  protected paths, backup or rollback semantics, or anything an operator has to
  clean up by hand.
