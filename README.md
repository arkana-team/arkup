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

## Command reference

| Command | Purpose | Root required |
| --- | --- | --- |
| `arkup keygen` | Create a release signing keypair | No |
| `arkup trust KEY.pub` | Add a public key to a trust store | Only with `--root /` |
| `arkup pack` | Build a signed `.aup` from a staged tree | No |
| `arkup verify PACK` | Check the signature, manifest, and every payload hash | No |
| `arkup list PACK` | Print the entries of a verified pack | No |
| `arkup apply PACK` | Install a verified pack, backing up replaced files | Only with `--root /` |

`trust`, `verify`, `list`, and `apply` accept `--root DIR` to select the target
system; the default is `/`. `verify`, `list`, and `apply` also accept
`--key KEY.pub` to check a pack against one public key instead of the trust
store. `pack` signs with `--signing-key KEY.key` instead.

`--key` skips the trust store entirely, including the ownership and permission
checks that protect `etc/arkup/trustedkeys.d`. Use it to inspect a pack on a
build machine. Do not use it to install an update on a production root: it
reduces "signed by a key this system trusts" to "signed by a key the caller
handed to arkup".

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

## Operational behavior

Apply is transactional with respect to errors. Each replaced file is copied
into `/var/lib/arkup/backups/<name>-<sequence>-<timestamp>-<pid>/` before it
changes, and a failure in any later step restores every snapshot in reverse
order, including file ownership and setuid, setgid, and sticky bits. The
installed record is written last, so a rolled-back update leaves the previous
sequence in place and the pack can be applied again.

A process that is killed, or a machine that loses power mid-apply, is not
rolled back: the snapshot list lives in memory. The backup directory still
holds the previous copies, and `var/lib/arkup/installed/<name>.json` shows
whether the record advanced. Recovery is manual.

Backup directories are never removed, and every apply creates one even when it
replaces nothing. On a long-lived system `/var/lib/arkup/backups/` grows
without bound, holding a full copy of each replaced or deleted file. Prune it
with your own retention policy; arkup has no pruning command.

File modes come verbatim from the staged tree, so setuid, setgid, and sticky
bits are reproduced on the target. `arkup pack` therefore needs the same care
as a release build directory. New files are owned by the user running
`arkup apply`.

## Known limitations

- **A stale `.arkup-new` sidecar blocks all later updates to that file.** When
  a locally edited configuration file is updated, arkup writes the new default
  to `<path>.arkup-new` and keeps the local file. If that sidecar is still
  present when a later update touches the same file, arkup refuses to
  overwrite it and the whole update rolls back. Resolve the pending sidecar
  before applying further updates.
- **Trusted keys cannot be revoked.** There is no `arkup distrust`. Removing a
  key means deleting `etc/arkup/trustedkeys.d/<key-id>.pub` by hand.
- **An update is bound to the trust store, not to a specific key.** The
  installed record stores the signing key id but arkup does not compare it, so
  a pack signed by any trusted key can replace state installed by another
  trusted key. Trust only keys whose holders you would let update the system.
- **The packer drops protected paths silently.** Anything under a protected
  prefix in the staging tree is omitted from the pack with no warning, so a
  release build that stages `/var/lib` or `usr/local` content produces a pack
  that is quietly missing those files. Check `arkup list` against the staging
  tree before publishing.
- **Updates are only as trustworthy as the signing key.** A signed pack can
  replace any non-protected file, install setuid binaries, and delete files.
  arkup's guarantees are about integrity and containment, not about limiting
  what a release may contain.

## Scope

arkup handles core system and feature updates. arkpkg handles optional
applications. This separation avoids using two package databases to update the
same system files.
