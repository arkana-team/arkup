use crate::archive::{for_each_payload, verify_archive};
use crate::key;
use crate::manifest::{
    EntryKind, FORMAT_VERSION, MAX_MANIFEST_BYTES, UpdateEntry, UpdateManifest, valid_name,
    valid_version,
};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::symlink;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

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
    destination: PathBuf,
    backup: Option<PathBuf>,
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
        File::open(&backup_root)?.sync_all()?;
        Ok::<(), anyhow::Error>(())
    })();

    if let Err(error) = result {
        let rollback_result = rollback(&changes, &created_directories);
        return match rollback_result {
            Ok(()) => Err(error.context("update failed; all changed files were rolled back")),
            Err(rollback_error) => Err(error.context(format!(
                "update failed and rollback also failed: {rollback_error:#}; recovery files remain in {}",
                backup_root.display()
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
    ensure_state_directory(&root, "etc/arkup/trustedkeys.d")?;
    let destination = root
        .join("etc/arkup/trustedkeys.d")
        .join(format!("{id}.pub"));
    let encoded = STANDARD.encode(verifying_key.to_bytes());
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&destination)
    {
        Ok(mut file) => {
            file.write_all(encoded.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = key::load_verifying_key(&destination)?;
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

fn apply_file(
    root: &Path,
    entry: &UpdateEntry,
    reader: &mut dyn Read,
    previous: Option<&InstalledRecord>,
    backup_root: &Path,
    changes: &mut Vec<AppliedChange>,
    created_directories: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut destination = resolve_destination(root, &entry.path, created_directories)?;
    let metadata = existing_metadata(&destination)?;
    if entry.config && is_modified_config(&destination, metadata.as_ref(), entry, previous)? {
        let sidecar = format!("{}.arkup-new", entry.path);
        destination = resolve_destination(root, &sidecar, created_directories)?;
        ensure!(
            existing_metadata(&destination)?.is_none(),
            "refusing to overwrite existing configuration update {}",
            destination.display()
        );
    }

    let parent = destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("update destination has no parent"))?;
    let mut staged = NamedTempFile::new_in(parent)?;
    let (size, digest) = copy_and_hash(reader, staged.as_file_mut())?;
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
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(entry.mode))?;
    staged.as_file().sync_all()?;
    let backup = snapshot_existing(root, &destination, &entry.path, backup_root)?;
    staged.persist(&destination).map_err(|error| {
        anyhow::anyhow!("cannot install {}: {}", destination.display(), error.error)
    })?;
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
    backup_root: &Path,
    changes: &mut Vec<AppliedChange>,
    created_directories: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut remaining = [0_u8; 1];
    ensure!(
        reader.read(&mut remaining)? == 0,
        "symlink payload must be empty"
    );
    let destination = resolve_destination(root, &entry.path, created_directories)?;
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("update destination has no parent"))?;
    let target = entry
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("symlink '{}' has no target", entry.path))?;
    let temporary_directory = tempfile::Builder::new()
        .prefix(".arkup-link-")
        .tempdir_in(parent)?;
    let temporary_link = temporary_directory.path().join("link");
    symlink(target, &temporary_link)?;
    let backup = snapshot_existing(root, &destination, &entry.path, backup_root)?;
    fs::rename(&temporary_link, &destination)?;
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
    backup_root: &Path,
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
    let Some(metadata) = existing_metadata(&destination)? else {
        return Ok(());
    };
    if entry.config && is_modified_deleted_config(&destination, &metadata, entry, previous)? {
        return Ok(());
    }
    let backup = snapshot_existing(root, &destination, &entry.path, backup_root)?;
    fs::remove_file(&destination)
        .with_context(|| format!("cannot remove update path {}", destination.display()))?;
    changes.push(AppliedChange {
        destination,
        backup,
    });
    Ok(())
}

fn is_modified_deleted_config(
    destination: &Path,
    current_metadata: &fs::Metadata,
    deleted: &UpdateEntry,
    previous: Option<&InstalledRecord>,
) -> Result<bool> {
    if !current_metadata.file_type().is_file() {
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
    destination: &Path,
    current_metadata: Option<&fs::Metadata>,
    incoming: &UpdateEntry,
    previous: Option<&InstalledRecord>,
) -> Result<bool> {
    let Some(metadata) = current_metadata else {
        return Ok(false);
    };
    if !metadata.file_type().is_file() {
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

fn resolve_destination(
    root: &Path,
    relative: &str,
    created_directories: &mut Vec<PathBuf>,
) -> Result<PathBuf> {
    let components: Vec<_> = relative.split('/').collect();
    ensure!(!components.is_empty(), "empty update path");
    let mut current = root.to_path_buf();
    for component in &components[..components.len() - 1] {
        let candidate = current.join(component);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let resolved = candidate.canonicalize().with_context(|| {
                    format!("cannot resolve update directory {}", candidate.display())
                })?;
                ensure!(
                    resolved.starts_with(root) && resolved.is_dir(),
                    "update path traverses a directory symlink outside the target root: {}",
                    candidate.display()
                );
                current = resolved;
            }
            Ok(metadata) if metadata.is_dir() => current = candidate,
            Ok(_) => bail!(
                "update path parent is not a directory: {}",
                candidate.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&candidate).with_context(|| {
                    format!("cannot create update directory {}", candidate.display())
                })?;
                fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755))?;
                created_directories.push(candidate.clone());
                current = candidate;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(current.join(components[components.len() - 1]))
}

fn resolve_existing_destination(root: &Path, relative: &str) -> Result<Option<PathBuf>> {
    let components: Vec<_> = relative.split('/').collect();
    ensure!(!components.is_empty(), "empty update path");
    let mut current = root.to_path_buf();
    for component in &components[..components.len() - 1] {
        let candidate = current.join(component);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let resolved = candidate.canonicalize().with_context(|| {
                    format!("cannot resolve update directory {}", candidate.display())
                })?;
                ensure!(
                    resolved.starts_with(root) && resolved.is_dir(),
                    "update path traverses a directory symlink outside the target root: {}",
                    candidate.display()
                );
                current = resolved;
            }
            Ok(metadata) if metadata.is_dir() => current = candidate,
            Ok(_) => bail!(
                "update path parent is not a directory: {}",
                candidate.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
    }
    let destination = current.join(components[components.len() - 1]);
    Ok(existing_metadata(&destination)?.map(|_| destination))
}

fn existing_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file() || metadata.file_type().is_symlink(),
                "refusing to replace unsupported destination {}",
                path.display()
            );
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn snapshot_existing(
    _root: &Path,
    destination: &Path,
    relative: &str,
    backup_root: &Path,
) -> Result<Option<PathBuf>> {
    let Some(metadata) = existing_metadata(destination)? else {
        return Ok(None);
    };
    let backup = backup_root.join(relative);
    let backup_parent = backup
        .parent()
        .ok_or_else(|| anyhow::anyhow!("backup path has no parent"))?;
    fs::create_dir_all(backup_parent)?;
    ensure!(
        backup.starts_with(backup_root),
        "backup path escaped backup directory"
    );
    if metadata.file_type().is_symlink() {
        symlink(fs::read_link(destination)?, &backup)?;
    } else {
        fs::copy(destination, &backup)?;
        fs::set_permissions(
            &backup,
            fs::Permissions::from_mode(metadata.permissions().mode()),
        )?;
        File::open(&backup)?.sync_all()?;
    }
    Ok(Some(backup))
}

fn write_record(
    root: &Path,
    record_path: &Path,
    record: &InstalledRecord,
    backup_root: &Path,
    changes: &mut Vec<AppliedChange>,
    created_directories: &mut Vec<PathBuf>,
) -> Result<()> {
    let relative = record_path
        .strip_prefix(root)
        .context("installed record is outside the target root")?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let destination = resolve_destination(root, &relative, created_directories)?;
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("installed record has no parent"))?;
    let bytes = serde_json::to_vec_pretty(record)?;
    let mut staged = NamedTempFile::new_in(parent)?;
    staged.write_all(&bytes)?;
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))?;
    staged.as_file().sync_all()?;
    let backup = snapshot_existing(root, &destination, &relative, backup_root)?;
    staged
        .persist(&destination)
        .map_err(|error| anyhow::anyhow!("cannot write installed record: {}", error.error))?;
    changes.push(AppliedChange {
        destination,
        backup,
    });
    Ok(())
}

fn rollback(changes: &[AppliedChange], created_directories: &[PathBuf]) -> Result<()> {
    let mut errors = Vec::new();
    for change in changes.iter().rev() {
        if let Err(error) = restore_change(change) {
            errors.push(format!("{}: {error:#}", change.destination.display()));
        }
    }
    for directory in created_directories.iter().rev() {
        if let Err(error) = fs::remove_dir(directory) {
            if error.kind() != io::ErrorKind::NotFound
                && error.kind() != io::ErrorKind::DirectoryNotEmpty
            {
                errors.push(format!("{}: {error}", directory.display()));
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
    match fs::symlink_metadata(&change.destination) {
        Ok(metadata) if metadata.is_dir() => bail!(
            "cannot remove directory while rolling back {}",
            change.destination.display()
        ),
        Ok(_) => fs::remove_file(&change.destination)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Some(backup) = &change.backup {
        let metadata = fs::symlink_metadata(backup)?;
        if metadata.file_type().is_symlink() {
            symlink(fs::read_link(backup)?, &change.destination)?;
        } else {
            let parent = change
                .destination
                .parent()
                .ok_or_else(|| anyhow::anyhow!("restore destination has no parent"))?;
            let staged = NamedTempFile::new_in(parent)?;
            fs::copy(backup, staged.path())?;
            fs::set_permissions(
                staged.path(),
                fs::Permissions::from_mode(metadata.permissions().mode()),
            )?;
            staged
                .persist(&change.destination)
                .map_err(|error| error.error)?;
        }
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
    let marker_path = resolve_destination(root, &marker, &mut created)?;
    let parent = marker_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("state directory has no parent"))?;
    ensure!(parent.is_dir(), "cannot create arkup state directory");
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

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
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
        assert!(apply(&options(package2)).is_err());
        assert_eq!(
            fs::read(root.join("usr/bin/a-tool")).unwrap(),
            b"version one"
        );
        let record: InstalledRecord = serde_json::from_slice(
            &fs::read(root.join("var/lib/arkup/installed/arkanaos-system.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(record.sequence, 1);
    }

    #[test]
    fn install_rejects_directory_symlink_escape() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("usr")).unwrap();
        assert!(resolve_destination(&root, "usr/bin/tool", &mut Vec::new()).is_err());
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
