# arkup

arkup applies signed system and feature update packs for arkanaOS. Core system
updates use `.aup` packs; arkpkg remains the package manager for optional
applications. A `.aup` is a gzip-compressed tar archive containing a signed
manifest and its payload.

## Build and test

Install Rust 1.85 or newer, then run:

```sh
cargo build --release
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

Use `CARGO_BUILD_JOBS=1` on memory-limited build hosts.

## Create and apply an update

Generate a release keypair once. Keep the private key offline and out of Git:

```sh
arkup keygen --output-dir release-keys
KEY_ID='replace-with-the-printed-key-id'
sudo arkup trust "release-keys/$KEY_ID.pub"
```

Stage the files to install beneath a root directory, then create a signed pack.
The sequence must increase for each successive pack with the same name.

```sh
arkup pack \
  --source staging/root \
  --name arkanaos-system \
  --version 'arkanaOS 1.0 (alpha 1) build 891' \
  --sequence 891 \
  --base-sequence 890 \
  --system-update \
  --arch x86_64 \
  --system-file etc/os-release \
  --system-file etc/arkana-build-number \
  --delete usr/bin/retired-tool \
  --description 'arkanaOS system update' \
  --signing-key "release-keys/$KEY_ID.key" \
  --output arkanaOS-1.0-a1-891.aup

arkup verify arkanaOS-1.0-a1-891.aup
arkup list arkanaOS-1.0-a1-891.aup
sudo arkup apply arkanaOS-1.0-a1-891.aup
```

For a test root, pass `--root /path/to/root` to `trust`, `verify`, `list`, or
`apply`. `--key` can verify a pack with a public key without installing it in a
trust store. Applying an older sequence requires the explicit
`--allow-downgrade` option.

System update packs must set `--system-update` and `--base-sequence` to the
installed build from which the delta was created. arkup requires the signed
`etc/arkana-build-number` entry to be a system-managed regular file whose
content matches the manifest sequence, then checks the installed build before
applying payload changes. This prevents applying a weekly delta after skipping
its matching base release or leaving the installed build identity stale.

Trust import requires directory ancestry owned by root or the invoking user,
without group or other write access. Sticky directories above the target root
(such as `/tmp`) are allowed.

## Pack format and safety

Each pack contains `arkup.json`, `arkup.sig`, and `payload/` files. The Ed25519
signature covers the manifest; the manifest records paths, modes, sizes,
SHA-256 hashes, symlink targets, architecture, version, and sequence. arkup
checks the signature and every payload before accepting an update. It rejects
traversal, duplicate paths, unsafe symlinks, unsupported archive entries, and
protected mutable paths, including `/etc/ld.so.cache`, `/var/lib`, `/root`, and
local timezone and resolver links.

The optional signed `base_sequence` manifest field binds a delta to an exact
installed system build. The explicit `system_update` marker adds the OS build
identity contract. Unmarked base-bound feature packs retain their existing
behavior, and older packs without these fields remain applicable.

Repeat `--delete PATH` to remove retired files. Existing files are backed up;
edited configuration files are retained when a deletion is applied. Repeat
`--system-file PATH` for exact paths that the operating system owns, such as
release identity files under `/etc`; these are replaced as managed system
files, while other `/etc` configuration remains protected.

Applying an update takes a system lock, saves replaced files under
`/var/lib/arkup/backups/`, preserves locally edited configuration by writing
the new default as `.arkup-new`, and restores changed files if any step fails.
Update packs cannot run install scripts or arbitrary hooks. Keep release
signing keys offline and distribute trusted public keys through a trusted
channel.

## Scope

arkup handles core system and feature updates. arkpkg handles optional
applications. This separation avoids using two package databases to update the
same system files.
