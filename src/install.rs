mod destination;

use crate::archive::{for_each_payload, verify_archive};
use crate::key;
use crate::manifest::{
    EntryKind, FORMAT_VERSION, MAX_MANIFEST_BYTES, PROTECTED_PATHS, UpdateEntry, UpdateManifest,
    is_protected_destination, is_protected_path, valid_name, valid_version,
};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use destination::{Destination, create_directory, open_directory};
use rustix::fs::{AtFlags, FileType, Stat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, fchown};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const RECORD_FORMAT: u32 = 1;

#[derive(Debug, Clone)]
pub struct ApplyOptions {
    pub archive: PathBuf,
    pub root: PathBuf,
    pub supplied_key: Option<PathBuf>,
    pub architecture: Option<String>,
    pub allow_downgrade: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledRecord {
    format_version: u32,
    name: String,
    version: String,
    sequence: u64,
    key_id: String,
    entries: Vec<UpdateEntry>,
}

struct AppliedChange {
    destination: Destination,
    backup: Option<Snapshot>,
}

// Retain recovery data independently of the mutable backup pathname.
enum Snapshot {
    Symlink(PathBuf),
    File {
        backup_root: Arc<BackupDirectory>,
        relative: PathBuf,
        metadata: fs::Metadata,
    },
}

struct BackupDirectory {
    path: PathBuf,
    directory: File,
}

impl BackupDirectory {
    fn open(path: &Path) -> Result<Arc<Self>> {
        let directory = File::options()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        Ok(Arc::new(Self {
            path: path.into(),
            directory,
        }))
    }

    fn destination(&self, relative: &Path, create_parents: bool) -> Result<Destination> {
        ensure!(
            relative
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
            "invalid backup path"
        );
        let name = relative
            .file_name()
            .context("backup path has no filename")?;
        let mut parent = self.directory.try_clone()?;
        let mut current = self.path.clone();
        for component in relative
            .parent()
            .context("backup path has no parent")?
            .components()
        {
            let name = component.as_os_str();
            let candidate = Destination {
                parent: parent.try_clone()?,
                name: name.into(),
                path: current.join(name),
            };
            parent = if create_parents && candidate.metadata()?.is_none() {
                create_directory(&parent, name.to_str().context("invalid backup directory")?)?
            } else {
                open_directory(&parent, Path::new(name))?
            };
            current = candidate.path;
        }
        Ok(Destination {
            parent,
            name: name.into(),
            path: current.join(name),
        })
    }
}

pub fn apply(options: &ApplyOptions) -> Result<UpdateManifest> {
    let root = options
        .root
        .canonicalize()
        .with_context(|| format!("cannot access target root {}", options.root.display()))?;
    ensure!(root.is_dir(), "target root must be a directory");
    if root == Path::new("/") {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "applying to / requires root privileges"
        );
    }

    let verified = verify_archive(&options.archive, &root, options.supplied_key.as_deref())?;
    let manifest = verified.manifest;
    let architecture = options
        .architecture
        .as_deref()
        .unwrap_or(std::env::consts::ARCH);
    ensure!(
        manifest.architecture == "any" || manifest.architecture == architecture,
        "update pack targets {}, but this system is {}",
        manifest.architecture,
        architecture
    );

    ensure_state_directory(&root, "var/lib/arkup")?;
    ensure_state_directory(&root, "var/lib/arkup/installed")?;
    ensure_state_directory(&root, "var/lib/arkup/backups")?;
    let _lock = acquire_lock(&root)?;

    let record_path = root
        .join("var/lib/arkup/installed")
        .join(format!("{}.json", manifest.name));
    let previous = read_record(&record_path, &manifest.name)?;
    if let Some(record) = &previous {
        ensure!(
            options.allow_downgrade || manifest.sequence > record.sequence,
            "update sequence {} is not newer than installed sequence {}; use --allow-downgrade to override",
            manifest.sequence,
            record.sequence
        );
    }

    let backup_id = unique_backup_id(&manifest);
    let backup_root = root.join("var/lib/arkup/backups").join(&backup_id);
    fs::create_dir(&backup_root)
        .with_context(|| format!("cannot create backup directory {}", backup_root.display()))?;
    fs::set_permissions(&backup_root, fs::Permissions::from_mode(0o700))?;
    let backup_root = BackupDirectory::open(&backup_root)?;

    let mut changes = Vec::new();
    let mut created_directories = Vec::new();
    let result = (|| {
        for_each_payload(&options.archive, &manifest, |entry, reader| {
            match entry.kind {
                EntryKind::File => apply_file(
                    &root,
                    entry,
                    reader,
                    previous.as_ref(),
                    &backup_root,
                    &mut changes,
                    &mut created_directories,
                ),
                EntryKind::Symlink => apply_symlink(
                    &root,
                    entry,
                    reader,
                    &backup_root,
                    &mut changes,
                    &mut created_directories,
                ),
                EntryKind::Delete => apply_delete(
                    &root,
                    entry,
                    reader,
                    previous.as_ref(),
                    &backup_root,
                    &mut changes,
                ),
            }
        })?;

        let record = InstalledRecord {
            format_version: RECORD_FORMAT,
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            sequence: manifest.sequence,
            key_id: manifest.key_id.clone(),
            entries: manifest.entries.clone(),
        };
        write_record(
            &root,
            &record_path,
            &record,
            &backup_root,
            &mut changes,
            &mut created_directories,
        )?;
        backup_root.directory.sync_all()?;
        Ok::<(), anyhow::Error>(())
    })();

    if let Err(error) = result {
        let rollback_result = rollback(&changes, &created_directories);
        return match rollback_result {
            Ok(()) => Err(error.context("update failed; all changed files were rolled back")),
            Err(rollback_error) => Err(error.context(format!(
                "update failed and rollback also failed: {rollback_error:#}; recovery files remain in {}",
                backup_root.path.display()
            ))),
        };
    }

    Ok(manifest)
}

pub fn trust_key(public_key: &Path, root: &Path) -> Result<PathBuf> {
    let root = root
        .canonicalize()
        .with_context(|| format!("cannot access target root {}", root.display()))?;
    if root == Path::new("/") {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "trusting a key in / requires root privileges"
        );
    }
    let verifying_key = key::load_verifying_key(public_key)?;
    let id = key::key_id(&verifying_key.to_bytes());
    let directory = trust_directory(&root)?;
    let filename = format!("{id}.pub");
    let destination = root.join("etc/arkup/trustedkeys.d").join(&filename);
    let encoded = STANDARD.encode(verifying_key.to_bytes());
    match open_at(
        &directory,
        OsStr::new(&filename),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o644,
    ) {
        Ok(mut file) => {
            file.write_all(encoded.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = key::read_verifying_key(open_at(
                &directory,
                OsStr::new(&filename),
                libc::O_RDONLY | libc::O_NONBLOCK,
                0,
            )?)?;
            ensure!(
                existing.to_bytes() == verifying_key.to_bytes(),
                "a different key already exists at {}",
                destination.display()
            );
        }
        Err(error) => return Err(error.into()),
    }
    Ok(destination)
}

fn open_at(directory: &File, name: &OsStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    let name = CString::new(name.as_bytes())?;
    // SAFETY: the directory descriptor and NUL-terminated name remain valid for the call.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor owned by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn check_trust_directory(directory: &File, allow_sticky: bool) -> Result<()> {
    let metadata = directory.metadata()?;
    let mode = metadata.permissions().mode();
    ensure!(
        metadata.is_dir()
            && (metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() })
            && (mode & 0o022 == 0 || (allow_sticky && mode & 0o1000 != 0)),
        "trust directory ancestry must be owned by root or the current user and not writable by other users"
    );
    Ok(())
}

fn open_trust_path(mut directory: File, path: &Path, allow_sticky: bool) -> Result<File> {
    check_trust_directory(&directory, allow_sticky)?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            bail!("invalid trust directory path");
        };
        directory = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        check_trust_directory(&directory, allow_sticky)?;
    }
    Ok(directory)
}

fn trust_directory(root: &Path) -> Result<File> {
    // Check ancestors above the root as well: an untrusted owner could otherwise
    // rename the selected tree. Sticky ancestors such as /tmp protect owned entries.
    let root_directory = open_trust_path(File::open("/")?, root.strip_prefix("/")?, true)?;
    check_trust_directory(&root_directory, false)?;
    let mut directory = root_directory.try_clone()?;
    let mut current = root.to_path_buf();
    for name in ["etc", "arkup", "trustedkeys.d"] {
        let candidate = current.join(name);
        match candidate.canonicalize() {
            Ok(resolved) => {
                // Preserve directory symlinks within the root, but reopen their
                // resolved components without following symlinks and check each handle.
                let relative = resolved
                    .strip_prefix(root)
                    .context("trust directory symlink escapes the target root")?;
                directory = open_trust_path(root_directory.try_clone()?, relative, false)?;
                current = resolved;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let component = CString::new(name)?;
                // SAFETY: both arguments remain valid; name is a single fixed component.
                let result =
                    unsafe { libc::mkdirat(directory.as_raw_fd(), component.as_ptr(), 0o755) };
                if result != 0 {
                    return Err(io::Error::last_os_error().into());
                }
                directory = open_at(
                    &directory,
                    OsStr::new(name),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
                check_trust_directory(&directory, false)?;
                current = candidate;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(directory)
}

fn apply_file(
    root: &Path,
    entry: &UpdateEntry,
    reader: &mut dyn Read,
    previous: Option<&InstalledRecord>,
    backup_root: &Arc<BackupDirectory>,
    changes: &mut Vec<AppliedChange>,
    created_directories: &mut Vec<Destination>,
) -> Result<()> {
    let mut destination = resolve_destination(root, &entry.path, created_directories, false)?;
    let metadata = destination.existing_metadata()?;
    if entry.config && is_modified_config(&destination, metadata.as_ref(), entry, previous)? {
        let sidecar = format!("{}.arkup-new", entry.path);
        destination = resolve_destination(root, &sidecar, created_directories, false)?;
        ensure!(
            destination.existing_metadata()?.is_none(),
            "refusing to overwrite existing configuration update {}",
            destination.path.display()
        );
    }

    let (staged, mut file) = destination.stage_file()?;
    let (size, digest) = copy_and_hash(reader, &mut file)?;
    ensure!(
        Some(size) == entry.size,
        "size mismatch for '{}'",
        entry.path
    );
    ensure!(
        Some(digest.as_str()) == entry.sha256.as_deref(),
        "SHA-256 mismatch for '{}'",
        entry.path
    );
    file.set_permissions(fs::Permissions::from_mode(entry.mode))?;
    file.sync_all()?;
    let backup = snapshot_existing(root, &destination, &entry.path, backup_root)?;
    staged.persist(&destination)?;
    changes.push(AppliedChange {
        destination,
        backup,
    });
    Ok(())
}

fn apply_symlink(
    root: &Path,
    entry: &UpdateEntry,
    reader: &mut dyn Read,
    backup_root: &Arc<BackupDirectory>,
    changes: &mut Vec<AppliedChange>,
    created_directories: &mut Vec<Destination>,
) -> Result<()> {
    let mut remaining = [0_u8; 1];
    ensure!(
        reader.read(&mut remaining)? == 0,
        "symlink payload must be empty"
    );
    let destination = resolve_destination(root, &entry.path, created_directories, false)?;
    let target = entry
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("symlink '{}' has no target", entry.path))?;
    let staged = destination.stage_symlink(Path::new(target))?;
    let backup = snapshot_existing(root, &destination, &entry.path, backup_root)?;
    staged.persist(&destination)?;
    changes.push(AppliedChange {
        destination,
        backup,
    });
    Ok(())
}

fn apply_delete(
    root: &Path,
    entry: &UpdateEntry,
    reader: &mut dyn Read,
    previous: Option<&InstalledRecord>,
    backup_root: &Arc<BackupDirectory>,
    changes: &mut Vec<AppliedChange>,
) -> Result<()> {
    let mut remaining = [0_u8; 1];
    ensure!(
        reader.read(&mut remaining)? == 0,
        "delete entry must have no payload"
    );
    let Some(destination) = resolve_existing_destination(root, &entry.path)? else {
        return Ok(());
    };
    let Some(metadata) = destination.existing_metadata()? else {
        return Ok(());
    };
    if entry.config && is_modified_deleted_config(&destination, &metadata, entry, previous)? {
        return Ok(());
    }
    let backup = snapshot_existing(root, &destination, &entry.path, backup_root)?;
    destination
        .remove(AtFlags::empty())
        .with_context(|| format!("cannot remove update path {}", destination.path.display()))?;
    changes.push(AppliedChange {
        destination,
        backup,
    });
    Ok(())
}

fn is_modified_deleted_config(
    destination: &Destination,
    current_metadata: &Stat,
    deleted: &UpdateEntry,
    previous: Option<&InstalledRecord>,
) -> Result<bool> {
    if !FileType::from_raw_mode(current_metadata.st_mode).is_file() {
        return Ok(true);
    }
    let Some(installed_hash) = previous
        .and_then(|record| {
            record
                .entries
                .iter()
                .find(|entry| entry.path == deleted.path)
        })
        .filter(|entry| entry.kind == EntryKind::File)
        .and_then(|entry| entry.sha256.as_deref())
    else {
        return Ok(true);
    };
    Ok(sha256_file(destination)? != installed_hash)
}

fn is_modified_config(
    destination: &Destination,
    current_metadata: Option<&Stat>,
    incoming: &UpdateEntry,
    previous: Option<&InstalledRecord>,
) -> Result<bool> {
    let Some(metadata) = current_metadata else {
        return Ok(false);
    };
    if !FileType::from_raw_mode(metadata.st_mode).is_file() {
        return Ok(true);
    }
    let current_hash = sha256_file(destination)?;
    if Some(current_hash.as_str()) == incoming.sha256.as_deref() {
        return Ok(false);
    }
    let installed_hash = previous
        .and_then(|record| {
            record
                .entries
                .iter()
                .find(|entry| entry.path == incoming.path)
        })
        .filter(|entry| entry.kind == EntryKind::File)
        .and_then(|entry| entry.sha256.as_deref());
    Ok(installed_hash != Some(current_hash.as_str()))
}

fn resolve_protected_path(
    root: &Path,
    relative: &str,
    aliases: &mut Vec<PathBuf>,
) -> Result<Vec<PathBuf>> {
    let path = root.join(relative);
    let mut pending: VecDeque<OsString> = path
        .components()
        .map(|component| component.as_os_str().to_owned())
        .collect();
    let mut current = PathBuf::new();
    let mut locations = Vec::new();
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        match Path::new(&part).components().next() {
            Some(Component::ParentDir) => {
                current.pop();
            }
            Some(Component::CurDir) => {}
            _ => current.push(&part),
        }
        if pending.is_empty() {
            locations.push(current.clone());
            // A protected leaf symlink reserves its entry, but its target is
            // protected only when it aliases a directory (e.g. /var/lib).
            if !fs::metadata(&current).is_ok_and(|metadata| metadata.is_dir()) {
                break;
            }
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_symlink() => {
                links += 1;
                ensure!(links <= 40, "too many protected directory symlinks");
                // Keep each hop: canonicalize alone hides aliases whose
                // replacement could redirect the protected namespace.
                aliases.push(current.clone());
                let target = fs::read_link(&current)?;
                current.pop();
                for component in target.components().rev() {
                    pending.push_front(component.as_os_str().to_owned());
                }
            }
            Ok(_) => {}
            // Missing paths still reserve their location under resolved parents.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    locations.push(current);
    Ok(locations)
}

fn check_destination(root: &Path, path: &Path, protected: Option<&[PathBuf]>) -> Result<()> {
    let relative = path
        .strip_prefix(root)
        .context("update path escaped target root")?;
    if let Some(protected) = protected {
        ensure!(
            !is_protected_path(&relative.to_string_lossy())
                && !protected.iter().any(|prefix| path.starts_with(prefix)),
            "update pack may not write protected path '{}'",
            relative.display()
        );
    }
    Ok(())
}

fn resolve_destination(
    root: &Path,
    relative: &str,
    created_directories: &mut Vec<Destination>,
    allow_protected: bool,
) -> Result<Destination> {
    resolve_path(root, relative, Some(created_directories), allow_protected)?
        .ok_or_else(|| anyhow::anyhow!("missing update destination parent"))
}

fn resolve_existing_destination(root: &Path, relative: &str) -> Result<Option<Destination>> {
    resolve_path(root, relative, None, false)
}

fn resolve_path(
    root: &Path,
    relative: &str,
    mut created_directories: Option<&mut Vec<Destination>>,
    allow_protected: bool,
) -> Result<Option<Destination>> {
    ensure!(
        allow_protected || !is_protected_destination(relative),
        "update pack may not write protected path '{}'",
        relative
    );
    let components: Vec<_> = relative.split('/').collect();
    ensure!(!components.is_empty(), "empty update path");
    // Protected state may itself live under a directory alias (e.g. /var).
    // Protect both its logical path and its physical location.
    let mut protected_aliases = Vec::new();
    let protected: Vec<_> = if allow_protected {
        Vec::new()
    } else {
        PROTECTED_PATHS
            .iter()
            .map(|path| resolve_protected_path(root, path, &mut protected_aliases))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect()
    };
    let protected = (!allow_protected).then_some(protected.as_slice());
    let root_directory = File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let mut parent = root_directory.try_clone()?;
    let mut current = root.to_path_buf();
    for component in &components[..components.len() - 1] {
        let candidate = Destination {
            parent: parent.try_clone()?,
            name: (*component).into(),
            path: current.join(component),
        };
        check_destination(root, &candidate.path, protected)?;
        match candidate.metadata()? {
            Some(metadata) if FileType::from_raw_mode(metadata.st_mode).is_symlink() => {
                let resolved = candidate.path.canonicalize().with_context(|| {
                    format!(
                        "cannot resolve update directory {}",
                        candidate.path.display()
                    )
                })?;
                ensure!(
                    resolved.starts_with(root),
                    "update path traverses a directory symlink outside the target root: {}",
                    candidate.path.display()
                );
                check_destination(root, &resolved, protected)?;
                // Open every resolved component without following symlinks. A
                // concurrent replacement after canonicalize must fail closed.
                parent = root_directory.try_clone()?;
                for part in resolved.strip_prefix(root)?.components() {
                    parent = open_directory(&parent, Path::new(part.as_os_str()))?;
                }
                current = resolved;
            }
            Some(metadata) if FileType::from_raw_mode(metadata.st_mode).is_dir() => {
                parent = open_directory(&parent, Path::new(component))?;
                current = candidate.path;
            }
            Some(_) => bail!(
                "update path parent is not a directory: {}",
                candidate.path.display()
            ),
            None => {
                let Some(created) = created_directories.as_mut() else {
                    return Ok(None);
                };
                parent = create_directory(&parent, component).with_context(|| {
                    format!(
                        "cannot create update directory {}",
                        candidate.path.display()
                    )
                })?;
                current = candidate.path.clone();
                created.push(candidate);
            }
        }
    }
    let destination = Destination {
        parent,
        name: components[components.len() - 1].into(),
        path: current.join(components[components.len() - 1]),
    };
    check_destination(root, &destination.path, protected)?;
    if let Some(protected) = protected {
        ensure!(
            !protected
                .iter()
                .chain(&protected_aliases)
                .any(|path| path.starts_with(&destination.path)),
            "update pack may not write protected path '{}'",
            relative
        );
    }
    Ok(Some(destination))
}

fn snapshot_existing(
    _root: &Path,
    destination: &Destination,
    relative: &str,
    backup_root: &Arc<BackupDirectory>,
) -> Result<Option<Snapshot>> {
    let Some(metadata) = destination.existing_metadata()? else {
        return Ok(None);
    };
    let backup = backup_root.destination(Path::new(relative), true)?;
    if FileType::from_raw_mode(metadata.st_mode).is_symlink() {
        let target = destination.read_link()?;
        rustix::fs::symlinkat(&target, &backup.parent, &backup.name)?;
        Ok(Some(Snapshot::Symlink(target)))
    } else {
        let mut source = destination.open_file()?;
        // Save ownership and mode from the same inode as the backed-up bytes.
        let metadata = source.metadata()?;
        ensure!(metadata.is_file(), "backup source must be a regular file");
        let mut saved = open_at(
            &backup.parent,
            &backup.name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        io::copy(&mut source, &mut saved)?;
        saved.set_permissions(metadata.permissions())?;
        saved.sync_all()?;
        Ok(Some(Snapshot::File {
            backup_root: Arc::clone(backup_root),
            relative: relative.into(),
            metadata,
        }))
    }
}

fn write_record(
    root: &Path,
    record_path: &Path,
    record: &InstalledRecord,
    backup_root: &Arc<BackupDirectory>,
    changes: &mut Vec<AppliedChange>,
    created_directories: &mut Vec<Destination>,
) -> Result<()> {
    let relative = record_path
        .strip_prefix(root)
        .context("installed record is outside the target root")?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let destination = resolve_destination(root, &relative, created_directories, true)?;
    let bytes = serde_json::to_vec_pretty(record)?;
    let (staged, mut file) = destination.stage_file()?;
    file.write_all(&bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o644))?;
    file.sync_all()?;
    let backup = snapshot_existing(root, &destination, &relative, backup_root)?;
    staged.persist(&destination)?;
    changes.push(AppliedChange {
        destination,
        backup,
    });
    Ok(())
}

fn rollback(changes: &[AppliedChange], created_directories: &[Destination]) -> Result<()> {
    let mut errors = Vec::new();
    for change in changes.iter().rev() {
        if let Err(error) = restore_change(change) {
            errors.push(format!("{}: {error:#}", change.destination.path.display()));
        }
    }
    for directory in created_directories.iter().rev() {
        if let Err(error) = directory.remove(AtFlags::REMOVEDIR) {
            if error.kind() != io::ErrorKind::NotFound
                && error.kind() != io::ErrorKind::DirectoryNotEmpty
            {
                errors.push(format!("{}: {error}", directory.path.display()));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("{}", errors.join("; "))
    }
}

fn restore_change(change: &AppliedChange) -> Result<()> {
    restore_change_with_owner(change, |file, metadata| {
        fchown(file, Some(metadata.uid()), Some(metadata.gid())).context("cannot restore ownership")
    })
}

fn restore_change_with_owner(
    change: &AppliedChange,
    restore_owner: impl FnOnce(&File, &fs::Metadata) -> Result<()>,
) -> Result<()> {
    if let Some(metadata) = change.destination.metadata()? {
        if FileType::from_raw_mode(metadata.st_mode).is_dir() {
            bail!(
                "cannot remove directory while rolling back {}",
                change.destination.path.display()
            );
        }
    }
    if let Some(backup) = &change.backup {
        match backup {
            Snapshot::Symlink(target) => {
                let staged = change.destination.stage_symlink(target)?;
                staged.persist(&change.destination)?;
            }
            Snapshot::File {
                backup_root,
                relative,
                metadata,
            } => {
                let (staged, mut file) = change.destination.stage_file()?;
                let mut source = backup_root.destination(relative, false)?.open_file()?;
                io::copy(&mut source, &mut file)?;
                // Keep the staged file private until ownership is restored.
                // chown can clear setuid/setgid bits, so apply the saved mode last.
                restore_owner(&file, metadata)?;
                file.set_permissions(metadata.permissions())?;
                file.sync_all()?;
                staged.persist(&change.destination)?;
            }
        }
    } else if change.destination.metadata()?.is_some() {
        change.destination.remove(AtFlags::empty())?;
    }
    Ok(())
}

fn read_record(path: &Path, expected_name: &str) -> Result<Option<InstalledRecord>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= MAX_MANIFEST_BYTES,
        "installed record must be a regular file: {}",
        path.display()
    );
    let bytes = fs::read(path)?;
    let record: InstalledRecord = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid installed record {}", path.display()))?;
    ensure!(
        record.format_version == RECORD_FORMAT
            && valid_name(&record.name)
            && valid_version(&record.version)
            && record.name == expected_name,
        "installed record identity or format is invalid"
    );
    UpdateManifest {
        format_version: FORMAT_VERSION,
        name: record.name.clone(),
        version: record.version.clone(),
        sequence: record.sequence,
        architecture: "any".into(),
        description: "installed state".into(),
        key_id: record.key_id.clone(),
        entries: record.entries.clone(),
    }
    .validate()
    .context("installed record contents are invalid")?;
    Ok(Some(record))
}

fn ensure_state_directory(root: &Path, relative: &str) -> Result<()> {
    let mut created = Vec::new();
    let marker = format!("{relative}/.arkup-directory-marker");
    let marker_path = resolve_destination(root, &marker, &mut created, true)?;
    ensure!(
        marker_path.parent.metadata()?.is_dir(),
        "cannot create arkup state directory"
    );
    Ok(())
}

fn acquire_lock(root: &Path) -> Result<File> {
    let lock_path = root.join("var/lib/arkup/arkup.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)
        .with_context(|| format!("cannot open arkup lock {}", lock_path.display()))?;
    let result = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
    ensure!(
        result == 0,
        "cannot lock arkup state: {}",
        io::Error::last_os_error()
    );
    Ok(file)
}

fn unique_backup_id(manifest: &UpdateManifest) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{}-{}-{}-{}",
        manifest.name,
        manifest.sequence,
        nanos,
        std::process::id()
    )
}

fn copy_and_hash(reader: &mut dyn Read, writer: &mut File) -> Result<(u64, String)> {
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| anyhow::anyhow!("update payload size overflow"))?;
        digest.update(&buffer[..count]);
        writer.write_all(&buffer[..count])?;
    }
    Ok((total, hex::encode(digest.finalize())))
}

fn sha256_file(destination: &Destination) -> Result<String> {
    let mut file = destination.open_file()?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{PackOptions, create_pack};
    use crate::key::generate_keypair;
    use std::os::unix::fs::symlink;

    #[test]
    fn failed_owner_restore_keeps_destination_and_recovery_backup() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let destination_path = root.join("installed-file");
        let backup_path = temp.path().join("original-file");
        fs::write(&destination_path, b"updated file").unwrap();
        fs::write(&backup_path, b"original file").unwrap();
        let backup = Snapshot::File {
            backup_root: BackupDirectory::open(temp.path()).unwrap(),
            relative: "original-file".into(),
            metadata: fs::metadata(&backup_path).unwrap(),
        };
        let change = AppliedChange {
            destination: resolve_destination(&root, "installed-file", &mut Vec::new(), false)
                .unwrap(),
            backup: Some(backup),
        };

        let result = restore_change_with_owner(&change, |_, _| {
            bail!("simulated ownership restoration failure")
        });

        assert!(result.is_err());
        assert_eq!(fs::read(destination_path).unwrap(), b"updated file");
        assert_eq!(fs::read(backup_path).unwrap(), b"original file");
    }

    #[test]
    fn trust_creates_keys_and_checks_existing_contents() {
        let temp = tempfile::tempdir().unwrap();
        let (_, _, public_key) = generate_keypair(&temp.path().join("keys")).unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let destination = trust_key(&public_key, &root).unwrap();
        assert_eq!(
            fs::read(&destination).unwrap(),
            fs::read(&public_key).unwrap()
        );
        assert_eq!(trust_key(&public_key, &root).unwrap(), destination);

        let (_, _, other_key) = generate_keypair(&temp.path().join("other-keys")).unwrap();
        fs::copy(other_key, &destination).unwrap();
        assert!(
            trust_key(&public_key, &root)
                .unwrap_err()
                .to_string()
                .contains("a different key already exists")
        );
        fs::remove_file(&destination).unwrap();
        symlink(&public_key, &destination).unwrap();
        assert!(trust_key(&public_key, &root).is_err());
    }

    #[test]
    fn trust_rejects_directory_escapes_and_preserves_contained_symlinks() {
        for component in ["etc", "etc/arkup", "etc/arkup/trustedkeys.d"] {
            let temp = tempfile::tempdir().unwrap();
            let (_, _, public_key) = generate_keypair(&temp.path().join("keys")).unwrap();
            let root = temp.path().join("root");
            let outside = temp.path().join("outside");
            let link = root.join(component);
            fs::create_dir_all(link.parent().unwrap()).unwrap();
            fs::create_dir(&outside).unwrap();
            symlink(&outside, &link).unwrap();
            assert!(trust_key(&public_key, &root).is_err());
            assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);

            fs::remove_file(&link).unwrap();
            let contained = root.join("contained");
            fs::create_dir(&contained).unwrap();
            symlink(&contained, &link).unwrap();
            let destination = trust_key(&public_key, &root).unwrap();
            assert_eq!(
                fs::read(destination).unwrap(),
                fs::read(public_key).unwrap()
            );
        }
    }

    #[test]
    fn trust_rejects_writable_directory_ancestry_before_creating_keys() {
        for component in ["", "etc", "etc/arkup", "etc/arkup/trustedkeys.d"] {
            for mode in [0o775, 0o777, 0o1777] {
                let temp = tempfile::tempdir().unwrap();
                let (_, _, public_key) = generate_keypair(&temp.path().join("keys")).unwrap();
                let root = temp.path().join("root");
                let directory = root.join(component);
                fs::create_dir_all(&directory).unwrap();
                fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).unwrap();
                assert!(trust_key(&public_key, &root).is_err());
                assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let (_, _, public_key) = generate_keypair(&temp.path().join("keys")).unwrap();
        let parent = temp.path().join("writable-parent");
        let root = parent.join("root");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(trust_key(&public_key, &root).is_err());
        assert!(!root.join("etc").exists());
    }

    #[test]
    fn trust_directory_handle_pins_creation_and_existing_key_reads() {
        let temp = tempfile::tempdir().unwrap();
        let (_, _, public_key) = generate_keypair(&temp.path().join("keys")).unwrap();
        let verifying_key = key::load_verifying_key(&public_key).unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir_all(outside.join("arkup/trustedkeys.d")).unwrap();
        let directory = trust_directory(&root).unwrap();
        fs::rename(root.join("etc"), root.join("saved-etc")).unwrap();
        symlink(&outside, root.join("etc")).unwrap();

        let name = OsStr::new("test.pub");
        let encoded = STANDARD.encode(verifying_key.to_bytes());
        let mut file = open_at(
            &directory,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o644,
        )
        .unwrap();
        file.write_all(encoded.as_bytes()).unwrap();
        assert!(!outside.join("arkup/trustedkeys.d/test.pub").exists());
        assert!(
            root.join("saved-etc/arkup/trustedkeys.d/test.pub")
                .is_file()
        );
        fs::write(outside.join("arkup/trustedkeys.d/test.pub"), b"invalid").unwrap();
        let existing = key::read_verifying_key(
            open_at(&directory, name, libc::O_RDONLY | libc::O_NONBLOCK, 0).unwrap(),
        )
        .unwrap();
        assert_eq!(existing.to_bytes(), verifying_key.to_bytes());
    }

    #[test]
    fn apply_preserves_modified_config_and_records_install() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let root = temp.path().join("root");
        let key_dir = temp.path().join("keys");
        let package = temp.path().join("system.aup");
        fs::create_dir_all(source.join("etc")).unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(source.join("etc/arkana.conf"), b"new=1\n").unwrap();
        fs::write(root.join("etc/arkana.conf"), b"local=1\n").unwrap();
        fs::write(source.join("etc/os-release"), b"VERSION=2\n").unwrap();
        fs::write(root.join("etc/os-release"), b"VERSION=1\n").unwrap();
        let (key_id, _, public_key) = generate_keypair(&key_dir).unwrap();
        create_pack(&PackOptions {
            source,
            deletions: Vec::new(),
            system_files: vec!["etc/os-release".into()],
            name: "arkanaos-system".into(),
            version: "arkanaOS 1.0 (alpha 1) build 10".into(),
            sequence: 10,
            architecture: "any".into(),
            description: "test system update".into(),
            signing_key: key_dir.join(format!("{key_id}.key")),
            output: package.clone(),
        })
        .unwrap();
        fs::create_dir_all(root.join("etc/arkup/trustedkeys.d")).unwrap();
        fs::copy(
            public_key,
            root.join(format!("etc/arkup/trustedkeys.d/{key_id}.pub")),
        )
        .unwrap();

        apply(&ApplyOptions {
            archive: package,
            root: root.clone(),
            supplied_key: None,
            architecture: Some("x86_64".into()),
            allow_downgrade: false,
        })
        .unwrap();

        assert_eq!(
            fs::read(root.join("etc/arkana.conf")).unwrap(),
            b"local=1\n"
        );
        assert_eq!(
            fs::read(root.join("etc/arkana.conf.arkup-new")).unwrap(),
            b"new=1\n"
        );
        assert_eq!(
            fs::read(root.join("etc/os-release")).unwrap(),
            b"VERSION=2\n"
        );
        assert!(!root.join("etc/os-release.arkup-new").exists());
        let record = root.join("var/lib/arkup/installed/arkanaos-system.json");
        assert!(record.exists());
    }

    #[test]
    fn failed_update_restores_files_and_rejects_replay() {
        check_failed_update_restores_files(None);
    }

    #[test]
    #[ignore = "requires root to create a file owned by another user and group"]
    fn failed_update_restores_unprivileged_file_ownership() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
        check_failed_update_restores_files(Some((65534, 65533)));
    }

    fn check_failed_update_restores_files(owner: Option<(u32, u32)>) {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let root = temp.path().join("root");
        let key_dir = temp.path().join("keys");
        let package1 = temp.path().join("first.aup");
        let package2 = temp.path().join("second.aup");
        fs::create_dir_all(source.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::write(source.join("usr/bin/a-tool"), b"version one").unwrap();
        let (key_id, signing, public) = generate_keypair(&key_dir).unwrap();
        create_pack(&PackOptions {
            source: source.clone(),
            deletions: Vec::new(),
            system_files: Vec::new(),
            name: "arkanaos-system".into(),
            version: "1.0.1".into(),
            sequence: 1,
            architecture: "any".into(),
            description: "first test update".into(),
            signing_key: signing.clone(),
            output: package1.clone(),
        })
        .unwrap();
        fs::create_dir_all(root.join("etc/arkup/trustedkeys.d")).unwrap();
        fs::copy(
            public,
            root.join(format!("etc/arkup/trustedkeys.d/{key_id}.pub")),
        )
        .unwrap();
        let options = |archive| ApplyOptions {
            archive,
            root: root.clone(),
            supplied_key: None,
            architecture: Some("x86_64".into()),
            allow_downgrade: false,
        };
        apply(&options(package1.clone())).unwrap();
        assert!(apply(&options(package1)).is_err());

        let destination = root.join("usr/bin/a-tool");
        let original = File::open(&destination).unwrap();
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&original, Some(uid), Some(gid)).unwrap();
        }
        original
            .set_permissions(fs::Permissions::from_mode(0o6755))
            .unwrap();
        let original_metadata = original.metadata().unwrap();

        fs::write(source.join("usr/bin/a-tool"), b"version two").unwrap();
        fs::write(source.join("usr/bin/z-blocked"), b"blocked file").unwrap();
        fs::create_dir(root.join("usr/bin/z-blocked")).unwrap();
        create_pack(&PackOptions {
            source,
            deletions: Vec::new(),
            system_files: Vec::new(),
            name: "arkanaos-system".into(),
            version: "1.0.2".into(),
            sequence: 2,
            architecture: "any".into(),
            description: "second test update".into(),
            signing_key: signing,
            output: package2.clone(),
        })
        .unwrap();
        let error = apply(&options(package2)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("all changed files were rolled back")
        );
        assert_eq!(
            fs::read(root.join("usr/bin/a-tool")).unwrap(),
            b"version one"
        );
        let restored = fs::metadata(&destination).unwrap();
        assert_eq!(restored.uid(), original_metadata.uid());
        assert_eq!(restored.gid(), original_metadata.gid());
        assert_eq!(restored.permissions().mode() & 0o7777, 0o6755);
        let record: InstalledRecord = serde_json::from_slice(
            &fs::read(root.join("var/lib/arkup/installed/arkanaos-system.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(record.sequence, 1);
    }

    #[test]
    fn apply_rejects_deleting_installed_record_through_directory_alias() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let source = temp.path().join("source");
        let package = temp.path().join("system.aup");
        let deletion = temp.path().join("delete.aup");
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::create_dir_all(source.join("usr/bin")).unwrap();
        fs::write(source.join("usr/bin/tool"), b"installed version").unwrap();
        let (_, signing_key, public_key) = generate_keypair(&temp.path().join("keys")).unwrap();
        trust_key(&public_key, &root).unwrap();
        let mut pack_options = PackOptions {
            source: source.clone(),
            deletions: Vec::new(),
            system_files: Vec::new(),
            name: "system".into(),
            version: "1".into(),
            sequence: 10,
            architecture: "any".into(),
            description: "replay protection test".into(),
            signing_key,
            output: package.clone(),
        };
        create_pack(&pack_options).unwrap();
        let options = |archive| ApplyOptions {
            archive,
            root: root.clone(),
            supplied_key: None,
            architecture: Some("x86_64".into()),
            allow_downgrade: false,
        };
        apply(&options(package.clone())).unwrap();
        let record_path = root.join("var/lib/arkup/installed/system.json");
        let original_record = fs::read(&record_path).unwrap();
        symlink("../var/lib/arkup/installed", root.join("usr/records")).unwrap();

        // This signed pack passes lexical path validation. Its deletion resolves
        // to another pack's replay record through an existing directory alias.
        fs::write(source.join("usr/bin/tool"), b"replacement").unwrap();
        pack_options.name = "other".into();
        pack_options.sequence = 1;
        pack_options.deletions = vec!["usr/records/system.json".into()];
        pack_options.output = deletion.clone();
        create_pack(&pack_options).unwrap();
        let error = apply(&options(deletion)).unwrap_err();
        assert!(format!("{error:#}").contains("protected path"));
        assert_eq!(fs::read(&record_path).unwrap(), original_record);
        assert_eq!(
            fs::read(root.join("usr/bin/tool")).unwrap(),
            b"installed version"
        );
        assert!(!root.join("var/lib/arkup/installed/other.json").exists());
        let replay_error = apply(&options(package)).unwrap_err();
        assert!(format!("{replay_error:#}").contains("not newer than installed sequence"));
    }

    #[test]
    fn payload_operations_reject_aliases_to_protected_paths() {
        for (directory, name) in [
            ("etc", "ld.so.cache"),
            ("etc/arkup", "key"),
            ("etc/arkpkg", "key"),
            ("var/lib/arkup/installed", "system.json"),
            ("var/lib/arkpkg", "record"),
            ("dev", "record"),
            ("proc", "record"),
            ("sys", "record"),
            ("run", "record"),
            ("tmp", "record"),
            ("home", "record"),
            ("var/cache", "record"),
            ("var/log", "record"),
            ("var/tmp", "record"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let backup = temp.path().join("backup");
            fs::create_dir_all(root.join(directory)).unwrap();
            fs::create_dir_all(root.join("usr")).unwrap();
            fs::create_dir(&backup).unwrap();
            let backup_directory = BackupDirectory::open(&backup).unwrap();
            let protected = root.join(directory).join(name);
            fs::write(&protected, b"protected content").unwrap();
            symlink(root.join(directory), root.join("usr/alias")).unwrap();
            for (kind, config) in [
                (EntryKind::File, false),
                (EntryKind::File, true),
                (EntryKind::Symlink, false),
                (EntryKind::Delete, false),
            ] {
                let entry = UpdateEntry {
                    path: format!("usr/alias/{name}"),
                    kind,
                    mode: 0o644,
                    size: Some(3),
                    sha256: Some(hex::encode(Sha256::digest(b"new"))),
                    target: Some("tool".into()),
                    config,
                };
                let mut changes = Vec::new();
                let mut directories = Vec::new();
                let result = match kind {
                    EntryKind::File => apply_file(
                        &root,
                        &entry,
                        &mut &b"new"[..],
                        None,
                        &backup_directory,
                        &mut changes,
                        &mut directories,
                    ),
                    EntryKind::Symlink => apply_symlink(
                        &root,
                        &entry,
                        &mut io::empty(),
                        &backup_directory,
                        &mut changes,
                        &mut directories,
                    ),
                    EntryKind::Delete => apply_delete(
                        &root,
                        &entry,
                        &mut io::empty(),
                        None,
                        &backup_directory,
                        &mut changes,
                    ),
                };
                let error = result.expect_err("protected alias must be rejected");
                assert!(format!("{error:#}").contains("protected path"), "{error:#}");
                assert_eq!(fs::read(&protected).unwrap(), b"protected content");
                assert!(
                    !protected
                        .with_file_name(format!("{name}.arkup-new"))
                        .exists()
                );
                assert!(changes.is_empty());
                assert!(directories.is_empty());
            }
            if directory != "etc" {
                assert!(
                    resolve_destination(&root, "usr/alias/missing/tool", &mut Vec::new(), false)
                        .is_err()
                );
                assert!(!root.join(directory).join("missing").exists());
            }
        }
    }

    #[test]
    fn payload_operations_reject_protected_ancestor_mutations() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let backup = temp.path().join("backup");
        fs::create_dir_all(root.join("layout/config/arkup")).unwrap();
        fs::create_dir_all(root.join("layout/state/lib/arkup")).unwrap();
        fs::create_dir_all(root.join("layout/system/local")).unwrap();
        fs::create_dir(&backup).unwrap();
        let backup_directory = BackupDirectory::open(&backup).unwrap();
        // Multiple alias hops must remain protected even though canonicalize
        // hides the intermediate symlinks from the final physical path.
        for (logical, bridge, target) in [
            ("etc", "config-link", "config"),
            ("var", "state-link", "state"),
            ("usr", "system-link", "system"),
        ] {
            symlink(target, root.join("layout").join(bridge)).unwrap();
            symlink(format!("layout/{bridge}"), root.join(logical)).unwrap();
        }
        for path in [
            "etc",
            "var",
            "usr",
            "layout/config-link",
            "layout/state-link",
            "layout/system-link",
        ] {
            let original = fs::read_link(root.join(path)).unwrap();
            for kind in [EntryKind::File, EntryKind::Symlink, EntryKind::Delete] {
                let entry = UpdateEntry {
                    path: path.into(),
                    kind,
                    mode: 0o644,
                    size: Some(3),
                    sha256: Some(hex::encode(Sha256::digest(b"new"))),
                    target: Some("replacement".into()),
                    config: false,
                };
                let mut changes = Vec::new();
                let mut directories = Vec::new();
                let result = match kind {
                    EntryKind::File => apply_file(
                        &root,
                        &entry,
                        &mut &b"new"[..],
                        None,
                        &backup_directory,
                        &mut changes,
                        &mut directories,
                    ),
                    EntryKind::Symlink => apply_symlink(
                        &root,
                        &entry,
                        &mut io::empty(),
                        &backup_directory,
                        &mut changes,
                        &mut directories,
                    ),
                    EntryKind::Delete => apply_delete(
                        &root,
                        &entry,
                        &mut io::empty(),
                        None,
                        &backup_directory,
                        &mut changes,
                    ),
                };
                let error = result.expect_err("ancestor mutation must be rejected");
                assert!(
                    format!("{error:#}").contains("protected path"),
                    "{path}: {error:#}"
                );
                assert_eq!(fs::read_link(root.join(path)).unwrap(), original);
                assert!(changes.is_empty());
                assert!(directories.is_empty());
                assert!(fs::read_dir(&backup).unwrap().next().is_none());
            }
        }
        for path in [
            "etc/os-release",
            "var/update/version",
            "usr/bin/tool",
            "layout/config/default.conf",
        ] {
            assert!(
                resolve_destination(&root, path, &mut Vec::new(), false).is_ok(),
                "{path}"
            );
        }
        for path in ["layout", "layout/config", "layout/state", "layout/system"] {
            assert!(
                resolve_destination(&root, path, &mut Vec::new(), false).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn snapshots_share_a_directory_under_descriptor_limit() {
        use std::os::unix::process::CommandExt;
        use std::process::Command;
        const CHILD: &str = "ARKUP_SNAPSHOT_LIMIT_TEST";
        if std::env::var_os(CHILD).is_none() {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command.args([
                "--exact",
                "install::tests::snapshots_share_a_directory_under_descriptor_limit",
            ]);
            command.env(CHILD, "1");
            // SAFETY: this child-only pre-exec hook calls setrlimit and creates
            // an io::Error on failure; it does not touch shared Rust state.
            unsafe {
                command.pre_exec(|| {
                    let limit = libc::rlimit {
                        rlim_cur: 64,
                        rlim_max: 64,
                    };
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let backup = temp.path().join("backup");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&backup).unwrap();
        let backup_directory = BackupDirectory::open(&backup).unwrap();
        fs::write(root.join("tool"), b"original").unwrap();
        let destination = resolve_destination(&root, "tool", &mut Vec::new(), false).unwrap();
        let mut snapshots = Vec::new();
        // The same destination handle is reused to isolate snapshot descriptor
        // growth from the existing retained install destination handles.
        for index in 0..256 {
            snapshots.push(
                snapshot_existing(
                    &root,
                    &destination,
                    &format!("saved/{index}"),
                    &backup_directory,
                )
                .unwrap(),
            );
        }
        fs::write(root.join("tool"), b"updated").unwrap();
        restore_change(&AppliedChange {
            destination,
            backup: snapshots.pop().unwrap(),
        })
        .unwrap();
        assert_eq!(fs::read(root.join("tool")).unwrap(), b"original");
    }

    #[test]
    fn rollback_rejects_symlinks_in_backup_ancestry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let backup = temp.path().join("backup");
        let decoy = temp.path().join("decoy");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir(&backup).unwrap();
        fs::create_dir(&decoy).unwrap();
        let backup_directory = BackupDirectory::open(&backup).unwrap();
        fs::write(root.join("bin/tool"), b"original").unwrap();
        fs::write(decoy.join("tool"), b"attacker").unwrap();
        let destination = resolve_destination(&root, "bin/tool", &mut Vec::new(), false).unwrap();
        let saved = snapshot_existing(&root, &destination, "bin/tool", &backup_directory).unwrap();
        fs::write(root.join("bin/tool"), b"updated").unwrap();
        fs::rename(backup.join("bin"), backup.join("saved-bin")).unwrap();
        symlink(&decoy, backup.join("bin")).unwrap();
        let change = AppliedChange {
            destination,
            backup: saved,
        };
        assert!(restore_change(&change).is_err());
        assert_eq!(fs::read(root.join("bin/tool")).unwrap(), b"updated");
        assert_eq!(
            fs::read(backup.join("saved-bin/tool")).unwrap(),
            b"original"
        );
        fs::remove_file(backup.join("bin")).unwrap();
        fs::rename(backup.join("saved-bin"), backup.join("bin")).unwrap();
        restore_change(&change).unwrap();
        assert_eq!(fs::read(root.join("bin/tool")).unwrap(), b"original");
    }

    #[test]
    fn rollback_retains_snapshots_when_backup_namespace_changes() {
        for is_link in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let backup = temp.path().join("backup");
            let moved = temp.path().join("moved-backup");
            let decoy = temp.path().join("decoy");
            fs::create_dir(&root).unwrap();
            fs::create_dir(&backup).unwrap();
            let backup_directory = BackupDirectory::open(&backup).unwrap();
            fs::create_dir(&decoy).unwrap();
            if is_link {
                symlink("original-target", root.join("tool")).unwrap();
                symlink("attacker-target", decoy.join("tool")).unwrap();
            } else {
                fs::write(root.join("tool"), b"original").unwrap();
                fs::write(decoy.join("tool"), b"attacker").unwrap();
            }
            let destination = resolve_destination(&root, "tool", &mut Vec::new(), false).unwrap();
            let saved = snapshot_existing(&root, &destination, "tool", &backup_directory).unwrap();
            destination
                .stage_symlink(Path::new("updated"))
                .unwrap()
                .persist(&destination)
                .unwrap();
            fs::rename(&backup, &moved).unwrap();
            symlink(&decoy, &backup).unwrap();
            restore_change(&AppliedChange {
                destination,
                backup: saved,
            })
            .unwrap();
            if is_link {
                assert_eq!(
                    fs::read_link(root.join("tool")).unwrap(),
                    Path::new("original-target")
                );
            } else {
                assert_eq!(fs::read(root.join("tool")).unwrap(), b"original");
            }
        }
    }

    #[test]
    fn protected_leaf_symlinks_do_not_protect_their_targets() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let zoneinfo = root.join("usr/share/zoneinfo/UTC");
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(zoneinfo.parent().unwrap()).unwrap();
        fs::write(&zoneinfo, b"timezone data").unwrap();
        symlink("../usr/share/zoneinfo/UTC", root.join("etc/localtime")).unwrap();

        let destination =
            resolve_destination(&root, "usr/share/zoneinfo/UTC", &mut Vec::new(), false).unwrap();

        assert_eq!(destination.path, zoneinfo);
    }

    #[test]
    fn protected_state_remains_protected_when_var_is_a_directory_alias() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let state = root.join("usr/state/lib/arkup/installed");
        fs::create_dir_all(&state).unwrap();
        symlink("usr/state", root.join("var")).unwrap();
        fs::write(state.join("system.json"), b"replay record").unwrap();
        symlink("state/lib/arkup/installed", root.join("usr/records")).unwrap();
        fs::create_dir(root.join("usr/config")).unwrap();
        symlink("usr/config", root.join("etc")).unwrap();
        for path in [
            "usr/config/ld.so.cache",
            "usr/state/lib/arkup/installed/system.json",
            "usr/records/system.json",
            "usr/state/lib/arkup/missing/tool",
        ] {
            let error = match resolve_destination(&root, path, &mut Vec::new(), false) {
                Err(error) => error,
                Ok(_) => panic!("physical state must remain protected"),
            };
            assert!(format!("{error:#}").contains("protected path"));
            assert!(resolve_existing_destination(&root, path).is_err());
        }
        assert!(!root.join("var/lib/arkup/missing").exists());
        assert_eq!(
            fs::read(state.join("system.json")).unwrap(),
            b"replay record"
        );
    }

    #[test]
    fn file_and_config_sidecar_remain_bound_to_checked_parent() {
        struct SwapDirectoryReader {
            content: io::Cursor<&'static [u8]>,
            directory: PathBuf,
            moved: PathBuf,
            redirect: PathBuf,
        }
        impl Read for SwapDirectoryReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.content.position() == 0 {
                    fs::rename(&self.directory, &self.moved)?;
                    symlink(&self.redirect, &self.directory)?;
                }
                self.content.read(buffer)
            }
        }
        for config in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let directory = root.join("usr/config");
            let moved = root.join("usr/moved");
            let protected = root.join("var/lib/arkup/installed");
            let backup = temp.path().join("backup");
            fs::create_dir_all(&directory).unwrap();
            fs::create_dir_all(&protected).unwrap();
            fs::create_dir(&backup).unwrap();
            let backup_directory = BackupDirectory::open(&backup).unwrap();
            fs::write(directory.join("tool"), b"local content").unwrap();
            fs::write(protected.join("tool"), b"protected content").unwrap();
            fs::write(protected.join("tool.arkup-new"), b"protected sidecar").unwrap();
            let entry = UpdateEntry {
                path: "usr/config/tool".into(),
                kind: EntryKind::File,
                mode: 0o644,
                size: Some(3),
                sha256: Some(hex::encode(Sha256::digest(b"new"))),
                target: None,
                config,
            };
            let mut reader = SwapDirectoryReader {
                content: io::Cursor::new(b"new"),
                directory,
                moved: moved.clone(),
                redirect: protected.clone(),
            };
            let mut changes = Vec::new();
            let mut directories = Vec::new();
            apply_file(
                &root,
                &entry,
                &mut reader,
                None,
                &backup_directory,
                &mut changes,
                &mut directories,
            )
            .unwrap();
            let installed_name = if config { "tool.arkup-new" } else { "tool" };
            assert_eq!(fs::read(moved.join(installed_name)).unwrap(), b"new");
            assert_eq!(
                fs::read(protected.join("tool")).unwrap(),
                b"protected content"
            );
            assert_eq!(
                fs::read(protected.join("tool.arkup-new")).unwrap(),
                b"protected sidecar"
            );
            rollback(&changes, &directories).unwrap();
            assert_eq!(fs::read(moved.join("tool")).unwrap(), b"local content");
            assert!(!moved.join("tool.arkup-new").exists());
            assert_eq!(
                fs::read(protected.join("tool")).unwrap(),
                b"protected content"
            );
        }
    }

    #[test]
    fn allowed_alias_supports_replacement_deletion_and_rollback_after_parent_swap() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let original = root.join("usr/lib");
        let moved = root.join("usr/moved");
        let protected = root.join("var/lib/arkup/installed");
        let backup = temp.path().join("backup");
        fs::create_dir_all(&original).unwrap();
        fs::create_dir_all(&protected).unwrap();
        fs::create_dir(&backup).unwrap();
        let backup_directory = BackupDirectory::open(&backup).unwrap();
        fs::write(original.join("tool"), b"original").unwrap();
        fs::write(protected.join("tool"), b"protected").unwrap();
        symlink("usr/lib", root.join("lib")).unwrap();
        let destination = resolve_existing_destination(&root, "lib/tool")
            .unwrap()
            .unwrap();
        let saved = snapshot_existing(&root, &destination, "lib/tool", &backup_directory).unwrap();
        fs::rename(&original, &moved).unwrap();
        symlink(&protected, &original).unwrap();
        let staged = destination.stage_symlink(Path::new("other-tool")).unwrap();
        staged.persist(&destination).unwrap();
        assert_eq!(
            fs::read_link(moved.join("tool")).unwrap(),
            Path::new("other-tool")
        );
        destination.remove(AtFlags::empty()).unwrap();
        assert!(fs::symlink_metadata(moved.join("tool")).is_err());
        restore_change(&AppliedChange {
            destination,
            backup: saved,
        })
        .unwrap();
        assert_eq!(fs::read(moved.join("tool")).unwrap(), b"original");
        assert_eq!(fs::read(protected.join("tool")).unwrap(), b"protected");
    }

    #[test]
    fn install_rejects_directory_symlink_escape() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("usr")).unwrap();
        assert!(resolve_destination(&root, "usr/bin/tool", &mut Vec::new(), false).is_err());
    }

    #[test]
    fn apply_replaces_final_symlink_without_writing_through_it() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let root = temp.path().join("root");
        let outside = temp.path().join("outside-file");
        let key_dir = temp.path().join("keys");
        let package = temp.path().join("system.aup");
        fs::create_dir_all(source.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("etc/arkup/trustedkeys.d")).unwrap();
        fs::write(source.join("usr/bin/tool"), b"updated system file").unwrap();
        fs::write(&outside, b"outside file must stay unchanged").unwrap();
        symlink(&outside, root.join("usr/bin/tool")).unwrap();
        let (id, signing_key, public_key) = generate_keypair(&key_dir).unwrap();
        create_pack(&PackOptions {
            source,
            deletions: Vec::new(),
            system_files: Vec::new(),
            name: "arkanaos-system".into(),
            version: "arkanaOS 1.0 (alpha 1) build 1".into(),
            sequence: 1,
            architecture: "any".into(),
            description: "replace a symlink safely".into(),
            signing_key,
            output: package.clone(),
        })
        .unwrap();
        fs::copy(
            public_key,
            root.join(format!("etc/arkup/trustedkeys.d/{id}.pub")),
        )
        .unwrap();

        apply(&ApplyOptions {
            archive: package,
            root: root.clone(),
            supplied_key: None,
            architecture: Some("x86_64".into()),
            allow_downgrade: false,
        })
        .unwrap();

        assert_eq!(
            fs::read(&outside).unwrap(),
            b"outside file must stay unchanged"
        );
        assert_eq!(
            fs::read(root.join("usr/bin/tool")).unwrap(),
            b"updated system file"
        );
        assert!(
            fs::symlink_metadata(root.join("usr/bin/tool"))
                .unwrap()
                .file_type()
                .is_file()
        );
    }

    #[test]
    fn apply_rejects_wrong_architecture_before_creating_state() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let root = temp.path().join("root");
        let key_dir = temp.path().join("keys");
        let package = temp.path().join("system.aup");
        fs::create_dir_all(source.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("etc/arkup/trustedkeys.d")).unwrap();
        fs::write(source.join("usr/bin/tool"), b"x86_64 update").unwrap();
        let (id, signing_key, public_key) = generate_keypair(&key_dir).unwrap();
        create_pack(&PackOptions {
            source,
            deletions: Vec::new(),
            system_files: Vec::new(),
            name: "arkanaos-system".into(),
            version: "1.0.1".into(),
            sequence: 1,
            architecture: "x86_64".into(),
            description: "x86_64 update".into(),
            signing_key,
            output: package.clone(),
        })
        .unwrap();
        fs::copy(
            public_key,
            root.join(format!("etc/arkup/trustedkeys.d/{id}.pub")),
        )
        .unwrap();

        let result = apply(&ApplyOptions {
            archive: package,
            root: root.clone(),
            supplied_key: None,
            architecture: Some("aarch64".into()),
            allow_downgrade: false,
        });
        assert!(result.is_err());
        assert!(!root.join("var/lib/arkup").exists());
    }

    #[test]
    fn delete_entries_remove_managed_files_but_keep_edited_config() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let empty_source = temp.path().join("empty-source");
        let root = temp.path().join("root");
        let key_dir = temp.path().join("keys");
        let first_package = temp.path().join("first.aup");
        let delete_package = temp.path().join("delete.aup");
        fs::create_dir_all(source.join("etc")).unwrap();
        fs::create_dir_all(source.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("etc/arkup/trustedkeys.d")).unwrap();
        fs::write(source.join("etc/local.conf"), b"default=1\n").unwrap();
        fs::write(source.join("etc/unchanged.conf"), b"keep=no\n").unwrap();
        fs::write(source.join("usr/bin/obsolete"), b"old binary").unwrap();
        let (id, signing, public) = generate_keypair(&key_dir).unwrap();
        create_pack(&PackOptions {
            source,
            deletions: Vec::new(),
            system_files: Vec::new(),
            name: "arkanaos-system".into(),
            version: "1.0.1".into(),
            sequence: 1,
            architecture: "any".into(),
            description: "initial files".into(),
            signing_key: signing.clone(),
            output: first_package.clone(),
        })
        .unwrap();
        fs::copy(
            public,
            root.join(format!("etc/arkup/trustedkeys.d/{id}.pub")),
        )
        .unwrap();
        let options = |archive| ApplyOptions {
            archive,
            root: root.clone(),
            supplied_key: None,
            architecture: Some("x86_64".into()),
            allow_downgrade: false,
        };
        apply(&options(first_package)).unwrap();
        fs::write(root.join("etc/local.conf"), b"local=1\n").unwrap();

        fs::create_dir(&empty_source).unwrap();
        create_pack(&PackOptions {
            source: empty_source,
            deletions: vec![
                "etc/local.conf".into(),
                "etc/unchanged.conf".into(),
                "usr/bin/obsolete".into(),
            ],
            system_files: Vec::new(),
            name: "arkanaos-system".into(),
            version: "1.0.2".into(),
            sequence: 2,
            architecture: "any".into(),
            description: "remove retired files".into(),
            signing_key: signing,
            output: delete_package.clone(),
        })
        .unwrap();
        apply(&options(delete_package)).unwrap();

        assert_eq!(fs::read(root.join("etc/local.conf")).unwrap(), b"local=1\n");
        assert!(!root.join("etc/unchanged.conf").exists());
        assert!(!root.join("usr/bin/obsolete").exists());
        let backup_root = root.join("var/lib/arkup/backups");
        let saved_binary = fs::read_dir(backup_root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path().join("usr/bin/obsolete"))
            .find(|path| path.exists())
            .expect("deleted binary should remain in the update backup");
        assert_eq!(fs::read(saved_binary).unwrap(), b"old binary");
    }
}
