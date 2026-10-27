use crate::key;
use crate::manifest::{
    EntryKind, MAX_MANIFEST_BYTES, MAX_MANIFEST_ENTRIES, MAX_PACKAGE_BYTES, UpdateEntry,
    UpdateManifest, is_protected_path, safe_symlink_target, valid_atom, valid_name, valid_version,
    validate_path,
};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::VerifyingKey;
use flate2::read::GzDecoder;
use flate2::{Compression, GzBuilder};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder, EntryType, Header};
use tempfile::NamedTempFile;
use walkdir::{DirEntry, WalkDir};

const MANIFEST_NAME: &str = "arkup.json";
const SIGNATURE_NAME: &str = "arkup.sig";
const PAYLOAD_PREFIX: &str = "payload/";
const MAX_SIGNATURE_BYTES: u64 = 256;
const MAX_ARCHIVE_BYTES: u64 = MAX_PACKAGE_BYTES;
const MAX_EXTENSION_BYTES: u64 = 64 * 1024;
// Include headers and padding, with room for GNU extensions on 100,000 entries.
// Empty extensions also consume budget.
const MAX_METADATA_BYTES: u64 = 256 * 1024 * 1024;
// Payloads, manifest, extensions, and at most one header/padding block per entry.
const MAX_DECOMPRESSED_BYTES: u64 = MAX_PACKAGE_BYTES
    + MAX_MANIFEST_BYTES
    + MAX_METADATA_BYTES
    + (MAX_MANIFEST_ENTRIES as u64 + 2) * 1024
    + 1024;

#[derive(Debug, Clone)]
pub struct PackOptions {
    pub source: PathBuf,
    pub deletions: Vec<String>,
    /// Exact target paths managed by the system, not treated as local config.
    pub system_files: Vec<String>,
    pub name: String,
    pub version: String,
    pub sequence: u64,
    pub architecture: String,
    pub description: String,
    pub signing_key: PathBuf,
    pub output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct VerifiedPackage {
    pub manifest: UpdateManifest,
}

pub fn create_pack(options: &PackOptions) -> Result<UpdateManifest> {
    ensure!(valid_name(&options.name), "invalid update pack name");
    ensure!(
        valid_version(&options.version),
        "invalid update pack version"
    );
    ensure!(
        valid_atom(&options.architecture),
        "invalid update pack architecture"
    );
    ensure!(
        options.output.extension().and_then(|ext| ext.to_str()) == Some("aup"),
        "update pack output must use the .aup extension"
    );
    let mut system_files = HashSet::new();
    for path in &options.system_files {
        validate_path(path)?;
        ensure!(
            !is_protected_path(path),
            "system-managed path '{}' is protected",
            path
        );
        ensure!(
            system_files.insert(path.as_str()),
            "duplicate system-managed path '{}'",
            path
        );
    }
    let source = options
        .source
        .canonicalize()
        .with_context(|| format!("cannot access source root {}", options.source.display()))?;
    ensure!(source.is_dir(), "source root must be a directory");
    let signing_key = key::load_signing_key(&options.signing_key)?;
    let verifying_key = signing_key.verifying_key();
    let key_id = key::key_id(&verifying_key.to_bytes());

    let mut sources = BTreeMap::<String, PathBuf>::new();
    let walker = WalkDir::new(&source)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| should_visit(source.as_path(), entry));

    for item in walker {
        let item = item?;
        if item.path() == source {
            continue;
        }
        let relative_path = item.path().strip_prefix(&source)?;
        let relative = relative_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("update paths must be valid UTF-8"))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        validate_path(&relative)?;
        if is_protected_path(&relative) {
            continue;
        }
        let metadata = fs::symlink_metadata(item.path())?;
        if metadata.file_type().is_dir() {
            continue;
        }
        ensure!(
            metadata.file_type().is_file() || metadata.file_type().is_symlink(),
            "unsupported file type at {}",
            item.path().display()
        );
        sources.insert(relative, item.path().to_path_buf());
    }

    for path in &options.system_files {
        if let Some(source_path) = sources.get(path) {
            ensure!(
                fs::symlink_metadata(source_path)?.file_type().is_file(),
                "system-managed path '{}' must be a regular file",
                path
            );
        } else {
            ensure!(
                options.deletions.iter().any(|deleted| deleted == path),
                "system-managed path '{}' is missing from the source",
                path
            );
        }
    }

    let mut entries = Vec::with_capacity(sources.len());
    for (path, source_path) in &sources {
        let metadata = fs::symlink_metadata(source_path)?;
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(source_path)?
                .into_os_string()
                .into_string()
                .map_err(|_| anyhow::anyhow!("symlink targets must be valid UTF-8"))?;
            ensure!(
                safe_symlink_target(path, &target),
                "symlink {} points outside the source root",
                path
            );
            entries.push(UpdateEntry {
                path: path.clone(),
                kind: EntryKind::Symlink,
                mode,
                size: None,
                sha256: None,
                target: Some(target),
                config: false,
            });
        } else {
            let sha256 = sha256_file(source_path)?;
            let config = (path == "etc" || path.starts_with("etc/"))
                && !system_files.contains(path.as_str());
            entries.push(UpdateEntry {
                path: path.clone(),
                kind: EntryKind::File,
                mode,
                size: Some(metadata.size()),
                sha256: Some(sha256),
                target: None,
                config,
            });
        }
    }
    for path in &options.deletions {
        validate_path(path)?;
        entries.push(UpdateEntry {
            path: path.clone(),
            kind: EntryKind::Delete,
            mode: 0,
            size: None,
            sha256: None,
            target: None,
            config: (path == "etc" || path.starts_with("etc/"))
                && !system_files.contains(path.as_str()),
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    let manifest = UpdateManifest {
        format_version: crate::manifest::FORMAT_VERSION,
        name: options.name.clone(),
        version: options.version.clone(),
        sequence: options.sequence,
        architecture: options.architecture.clone(),
        description: options.description.clone(),
        key_id,
        entries,
    };
    manifest.validate()?;

    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let signature = key::sign(&signing_key, &manifest_bytes);
    let signature_text = STANDARD.encode(signature);

    let output_parent = options
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(output_parent)?;
    let temporary = NamedTempFile::new_in(output_parent)?;
    write_archive(
        temporary.reopen()?,
        &sources,
        &manifest_bytes,
        signature_text.as_bytes(),
    )?;

    verify_archive_with_key(temporary.path(), &verifying_key)?;
    temporary
        .persist_noclobber(&options.output)
        .map_err(|error| {
            anyhow::anyhow!(
                "cannot create {}: {}",
                options.output.display(),
                error.error
            )
        })?;
    Ok(manifest)
}

pub fn verify_archive(
    archive_path: &Path,
    root: &Path,
    supplied_key: Option<&Path>,
) -> Result<VerifiedPackage> {
    let manifest = read_manifest_and_signature(archive_path)?;
    let trusted_key_path = match supplied_key {
        Some(path) => path.to_path_buf(),
        None => root
            .join("etc/arkup/trustedkeys.d")
            .join(format!("{}.pub", manifest.key_id)),
    };
    if supplied_key.is_none() {
        let canonical_root = root
            .canonicalize()
            .with_context(|| format!("cannot access trusted-key root {}", root.display()))?;
        let metadata = fs::symlink_metadata(&trusted_key_path)
            .with_context(|| format!("no trusted signing key for key id {}", manifest.key_id))?;
        ensure!(
            metadata.file_type().is_file() && metadata.permissions().mode() & 0o022 == 0,
            "trusted key must be a non-writable regular file"
        );
        let canonical_key = trusted_key_path.canonicalize()?;
        ensure!(
            canonical_key.starts_with(&canonical_root),
            "trusted key path escapes the target root"
        );
        let mut directory = canonical_key.parent();
        while let Some(path) = directory {
            if !path.starts_with(&canonical_root) {
                break;
            }
            let metadata = fs::metadata(path)?;
            ensure!(
                metadata.is_dir() && metadata.permissions().mode() & 0o022 == 0,
                "trusted key directory must not be writable by group or other users: {}",
                path.display()
            );
            if path == canonical_root {
                break;
            }
            directory = path.parent();
        }
    }
    let verifying_key = key::load_verifying_key(&trusted_key_path)
        .with_context(|| format!("no trusted signing key for key id {}", manifest.key_id))?;
    let verified = verify_archive_with_key(archive_path, &verifying_key)?;
    ensure!(
        key::key_id(&verifying_key.to_bytes()) == manifest.key_id,
        "trusted key does not match the update pack key id"
    );
    Ok(verified)
}

pub fn verify_archive_with_key(
    archive_path: &Path,
    verifying_key: &VerifyingKey,
) -> Result<VerifiedPackage> {
    let mut archive = open_archive(archive_path)?;
    let mut entries = archive.entries()?;
    let manifest_entry = entries
        .next()
        .ok_or_else(|| anyhow::anyhow!("update pack is empty"))??;
    ensure!(
        archive_path_string(&manifest_entry)? == MANIFEST_NAME,
        "arkup.json must be the first archive entry"
    );
    ensure!(
        manifest_entry.header().entry_type().is_file(),
        "arkup.json must be a regular file"
    );
    ensure!(
        manifest_entry.size() <= MAX_MANIFEST_BYTES,
        "update manifest exceeds the size limit"
    );
    let manifest_bytes = read_limited(manifest_entry, MAX_MANIFEST_BYTES)?;
    let manifest: UpdateManifest =
        serde_json::from_slice(&manifest_bytes).context("invalid arkup.json manifest")?;
    manifest.validate()?;

    let signature_entry = entries
        .next()
        .ok_or_else(|| anyhow::anyhow!("update pack is missing arkup.sig"))??;
    ensure!(
        archive_path_string(&signature_entry)? == SIGNATURE_NAME,
        "arkup.sig must be the second archive entry"
    );
    ensure!(
        signature_entry.header().entry_type().is_file()
            && signature_entry.size() <= MAX_SIGNATURE_BYTES,
        "invalid update signature entry"
    );
    let signature_text = read_limited(signature_entry, MAX_SIGNATURE_BYTES)?;
    let signature = STANDARD
        .decode(std::str::from_utf8(&signature_text)?.trim())
        .context("invalid base64 update signature")?;
    ensure!(
        key::key_id(&verifying_key.to_bytes()) == manifest.key_id,
        "trusted key does not match the update pack key id"
    );
    key::verify(verifying_key, &manifest_bytes, &signature)?;

    let manifest_entries: BTreeMap<&str, &UpdateEntry> = manifest
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let mut seen = HashSet::new();
    let mut total_bytes = 0_u64;
    for entry in entries {
        let mut entry = entry?;
        let archive_path = archive_path_string(&entry)?;
        ensure!(
            archive_path.starts_with(PAYLOAD_PREFIX),
            "unexpected update archive entry '{}'",
            archive_path
        );
        let relative = &archive_path[PAYLOAD_PREFIX.len()..];
        validate_path(relative)?;
        ensure!(
            seen.insert(relative.to_string()),
            "duplicate update archive entry '{}'",
            relative
        );
        let expected = manifest_entries
            .get(relative)
            .ok_or_else(|| anyhow::anyhow!("unlisted update archive entry '{}'", relative))?;
        let mode = entry.header().mode()? & 0o7777;
        ensure!(mode == expected.mode, "mode mismatch for '{}'", relative);

        match expected.kind {
            EntryKind::File => {
                ensure!(
                    entry.header().entry_type().is_file(),
                    "expected regular file at '{}'",
                    relative
                );
                let expected_size = expected.size.expect("validated file size");
                ensure!(
                    entry.size() == expected_size,
                    "size mismatch for '{}'",
                    relative
                );
                total_bytes = total_bytes
                    .checked_add(expected_size)
                    .ok_or_else(|| anyhow::anyhow!("update pack size overflow"))?;
                ensure!(
                    total_bytes <= MAX_PACKAGE_BYTES,
                    "update pack exceeds the unpacked-size limit"
                );
                let actual_hash = sha256_reader(&mut entry)?;
                ensure!(
                    Some(actual_hash.as_str()) == expected.sha256.as_deref(),
                    "SHA-256 mismatch for '{}'",
                    relative
                );
            }
            EntryKind::Symlink => {
                ensure!(
                    entry.header().entry_type().is_symlink(),
                    "expected symlink at '{}'",
                    relative
                );
                let actual_target = archive_link_target(&entry)?;
                ensure!(
                    Some(actual_target.as_str()) == expected.target.as_deref(),
                    "symlink target mismatch for '{}'",
                    relative
                );
            }
            EntryKind::Delete => bail!("delete entry '{}' must not have a payload", relative),
        }
    }
    ensure!(
        seen.len()
            == manifest
                .entries
                .iter()
                .filter(|entry| entry.kind != EntryKind::Delete)
                .count(),
        "update archive is missing payload files"
    );

    Ok(VerifiedPackage { manifest })
}

pub fn for_each_payload(
    archive_path: &Path,
    manifest: &UpdateManifest,
    mut callback: impl FnMut(&UpdateEntry, &mut dyn Read) -> Result<()>,
) -> Result<()> {
    manifest.validate()?;
    let mut archive = open_archive(archive_path)?;
    let mut entries = archive.entries()?;
    let manifest_entry = entries
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing manifest"))??;
    ensure!(
        archive_path_string(&manifest_entry)? == MANIFEST_NAME
            && manifest_entry.header().entry_type().is_file()
            && manifest_entry.size() <= MAX_MANIFEST_BYTES,
        "invalid update manifest entry"
    );
    let archive_manifest: UpdateManifest =
        serde_json::from_slice(&read_limited(manifest_entry, MAX_MANIFEST_BYTES)?)?;
    ensure!(
        archive_manifest == *manifest,
        "update pack changed after verification"
    );
    let signature_entry = entries
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing signature"))??;
    ensure!(
        archive_path_string(&signature_entry)? == SIGNATURE_NAME
            && signature_entry.header().entry_type().is_file()
            && signature_entry.size() <= MAX_SIGNATURE_BYTES,
        "invalid update signature entry"
    );
    let signature = read_limited(signature_entry, MAX_SIGNATURE_BYTES)?;
    ensure!(
        STANDARD
            .decode(std::str::from_utf8(&signature)?.trim())
            .is_ok_and(|bytes| bytes.len() == 64),
        "invalid update signature entry"
    );
    let expected: BTreeMap<&str, &UpdateEntry> = manifest
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let mut seen = HashSet::new();
    for entry in entries {
        let mut entry = entry?;
        let archive_path = archive_path_string(&entry)?;
        let relative = archive_path
            .strip_prefix(PAYLOAD_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("unexpected archive entry '{}'", archive_path))?;
        validate_path(relative)?;
        ensure!(
            seen.insert(relative.to_string()),
            "duplicate update archive entry '{}'",
            relative
        );
        let expected_entry = expected
            .get(relative)
            .ok_or_else(|| anyhow::anyhow!("unlisted update archive entry '{}'", relative))?;
        ensure!(
            entry.header().mode()? & 0o7777 == expected_entry.mode,
            "mode mismatch for '{}'",
            relative
        );
        match expected_entry.kind {
            EntryKind::File => ensure!(
                entry.header().entry_type().is_file() && Some(entry.size()) == expected_entry.size,
                "invalid regular file '{}'",
                relative
            ),
            EntryKind::Symlink => {
                ensure!(
                    entry.header().entry_type().is_symlink(),
                    "expected symlink at '{}'",
                    relative
                );
                let target = archive_link_target(&entry)?;
                ensure!(
                    Some(target.as_str()) == expected_entry.target.as_deref(),
                    "symlink target mismatch for '{}'",
                    relative
                );
            }
            EntryKind::Delete => bail!("delete entry '{}' must not have a payload", relative),
        }
        let mut hashing = HashingReader::new(&mut entry);
        callback(expected_entry, &mut hashing)?;
        io::copy(&mut hashing, &mut io::sink())?;
        if expected_entry.kind == EntryKind::File {
            ensure!(
                Some(hashing.bytes_read) == expected_entry.size,
                "size mismatch for '{}'",
                relative
            );
            ensure!(
                Some(hex::encode(hashing.digest.finalize()).as_str())
                    == expected_entry.sha256.as_deref(),
                "SHA-256 mismatch for '{}'",
                relative
            );
        }
    }
    ensure!(
        seen.len()
            == manifest
                .entries
                .iter()
                .filter(|entry| entry.kind != EntryKind::Delete)
                .count(),
        "update archive is missing payload files"
    );
    for entry in manifest
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Delete)
    {
        callback(entry, &mut io::empty())?;
    }
    Ok(())
}

fn read_manifest_and_signature(archive_path: &Path) -> Result<UpdateManifest> {
    let mut archive = open_archive(archive_path)?;
    let mut entries = archive.entries()?;
    let entry = entries
        .next()
        .ok_or_else(|| anyhow::anyhow!("update pack is empty"))??;
    ensure!(
        archive_path_string(&entry)? == MANIFEST_NAME,
        "missing arkup.json"
    );
    ensure!(
        entry.header().entry_type().is_file() && entry.size() <= MAX_MANIFEST_BYTES,
        "invalid update manifest entry"
    );
    let bytes = read_limited(entry, MAX_MANIFEST_BYTES)?;
    let manifest: UpdateManifest = serde_json::from_slice(&bytes)?;
    manifest.validate()?;
    Ok(manifest)
}

fn open_archive(path: &Path) -> Result<Archive<BoundedArchiveReader<GzDecoder<File>>>> {
    let file = File::open(path)
        .with_context(|| format!("cannot access update pack {}", path.display()))?;
    ensure!(
        file.metadata()?.len() <= MAX_ARCHIVE_BYTES,
        "update pack exceeds the compressed-size limit"
    );
    Ok(Archive::new(BoundedArchiveReader::new(GzDecoder::new(
        file,
    ))))
}

// Check raw headers before tar's iterator can buffer GNU/PAX extensions. File
// bodies stream through; only a bounded local PAX body is buffered here to track
// its size override and keep framing identical to tar's non-raw iterator.
struct BoundedArchiveReader<R> {
    inner: R,
    buffered: io::Cursor<Vec<u8>>,
    remaining: u64,
    metadata_bytes: u64,
    decompressed_bytes: u64,
    pax_size: Option<u64>,
}

impl<R: Read> BoundedArchiveReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buffered: io::Cursor::new(Vec::new()),
            remaining: 0,
            metadata_bytes: 0,
            decompressed_bytes: 0,
            pax_size: None,
        }
    }

    fn next_header(&mut self) -> io::Result<bool> {
        let mut header = Header::new_old();
        let count = self.inner.read(header.as_mut_bytes())?;
        if count == 0 {
            return Ok(false);
        }
        self.inner.read_exact(&mut header.as_mut_bytes()[count..])?;
        if header.as_bytes().iter().all(|byte| *byte == 0) {
            self.buffered = io::Cursor::new(header.as_bytes().to_vec());
            return Ok(true);
        }
        let kind = header.entry_type();
        // Sparse entries are already unsupported; reject before tar allocates
        // its variable-length sparse block map.
        if kind.is_gnu_sparse() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported sparse archive entry",
            ));
        }
        let extension = kind.is_gnu_longname()
            || kind.is_gnu_longlink()
            || kind.is_pax_local_extensions()
            || kind.is_pax_global_extensions();
        let mut size = header.entry_size()?;
        if extension {
            if size > MAX_EXTENSION_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "archive extension exceeds the size limit",
                ));
            }
        } else if let Some(pax_size) = self.pax_size.take() {
            size = pax_size;
        }
        let padded = size
            .checked_add(511)
            .map(|size| size & !511)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "archive size overflow"))?;
        let bytes = padded
            .checked_add(512)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "archive size overflow"))?;
        if extension {
            self.metadata_bytes += bytes;
            if self.metadata_bytes > MAX_METADATA_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "archive extensions exceed the metadata limit",
                ));
            }
        }
        self.decompressed_bytes = self
            .decompressed_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_DECOMPRESSED_BYTES)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "archive exceeds the decompressed-size limit",
                )
            })?;
        self.remaining = padded;
        let mut buffered = header.as_bytes().to_vec();
        if kind.is_pax_local_extensions()
            && (header.as_gnu().is_some() || header.as_ustar().is_some())
        {
            buffered.resize(512 + padded as usize, 0);
            self.inner.read_exact(&mut buffered[512..])?;
            self.remaining = 0;
            // Match tar 0.4's first size record and stop at malformed records.
            self.pax_size = None;
            for field in tar::PaxExtensions::new(&buffered[512..512 + size as usize]) {
                let Ok(field) = field else { break };
                if field.key() == Ok("size") {
                    self.pax_size = field.value().ok().and_then(|value| value.parse().ok());
                    break;
                }
            }
        }
        self.buffered = io::Cursor::new(buffered);
        Ok(true)
    }
}

impl<R: Read> Read for BoundedArchiveReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let count = self.buffered.read(buffer)?;
        if count > 0 {
            return Ok(count);
        }
        if self.remaining > 0 {
            let limit = self.remaining.min(buffer.len() as u64) as usize;
            let count = self.inner.read(&mut buffer[..limit])?;
            self.remaining -= count as u64;
            return Ok(count);
        }
        if !self.next_header()? {
            return Ok(0);
        }
        self.buffered.read(buffer)
    }
}

fn write_archive(
    output: File,
    sources: &BTreeMap<String, PathBuf>,
    manifest: &[u8],
    signature: &[u8],
) -> Result<()> {
    let encoder = GzBuilder::new()
        .mtime(0)
        .write(output, Compression::default());
    let mut builder = Builder::new(encoder);
    append_bytes(&mut builder, MANIFEST_NAME, manifest, 0o644)?;
    append_bytes(&mut builder, SIGNATURE_NAME, signature, 0o644)?;

    for (relative, source_path) in sources {
        let metadata = fs::symlink_metadata(source_path)?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(source_path)?;
            ensure!(
                target.to_str().is_some(),
                "symlink targets must be valid UTF-8"
            );
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Symlink);
            header.set_size(0);
            header.set_mode(metadata.permissions().mode() & 0o7777);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_link_name(&target)?;
            header.set_cksum();
            builder.append_data(&mut header, format!("payload/{relative}"), io::empty())?;
        } else {
            let mut file = File::open(source_path)?;
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Regular);
            header.set_size(metadata.len());
            header.set_mode(metadata.permissions().mode() & 0o7777);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder.append_data(&mut header, format!("payload/{relative}"), &mut file)?;
        }
    }

    let encoder = builder.into_inner()?;
    encoder.finish()?;
    Ok(())
}

fn append_bytes<W: Write>(
    builder: &mut Builder<W>,
    path: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder.append_data(&mut header, path, bytes)?;
    Ok(())
}

fn should_visit(root: &Path, entry: &DirEntry) -> bool {
    if entry.path() == root {
        return true;
    }
    let Ok(relative) = entry.path().strip_prefix(root) else {
        return false;
    };
    let value = relative
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    !is_protected_path(&value)
}

fn archive_path_string<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String> {
    entry
        .path()?
        .into_owned()
        .into_os_string()
        .into_string()
        .map(|path| path.replace(std::path::MAIN_SEPARATOR, "/"))
        .map_err(|_| anyhow::anyhow!("archive paths must be valid UTF-8"))
}

fn archive_link_target<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String> {
    entry
        .link_name()?
        .ok_or_else(|| anyhow::anyhow!("symlink has no target"))?
        .into_owned()
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("archive symlink targets must be valid UTF-8"))
}

fn read_limited(mut reader: impl Read, max_bytes: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= max_bytes,
        "archive metadata exceeds size limit"
    );
    Ok(bytes)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    sha256_reader(&mut file)
}

fn sha256_reader(reader: &mut impl Read) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

struct HashingReader<'a, R> {
    inner: &'a mut R,
    digest: Sha256,
    bytes_read: u64,
}

impl<'a, R> HashingReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes_read: 0,
        }
    }
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        if count > 0 {
            self.digest.update(&buffer[..count]);
            self.bytes_read = self.bytes_read.saturating_add(count as u64);
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::os::unix::fs::symlink;

    #[derive(Clone)]
    struct RepackedEntry {
        path: String,
        kind: EntryType,
        mode: u32,
        data: Vec<u8>,
        link: Option<String>,
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn test_options(source: &Path, output: &Path, private_key: &Path) -> PackOptions {
        PackOptions {
            source: source.to_path_buf(),
            deletions: Vec::new(),
            system_files: Vec::new(),
            name: "desktop-feature".into(),
            version: "1.2.3".into(),
            sequence: 1,
            architecture: "any".into(),
            description: "feature pack test".into(),
            signing_key: private_key.to_path_buf(),
            output: output.to_path_buf(),
        }
    }

    fn write_key(path: &Path, key: &SigningKey) {
        use base64::Engine;
        fs::write(
            path,
            base64::engine::general_purpose::STANDARD.encode(key.to_bytes()),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn rewrite_archive(
        input: &Path,
        output: &Path,
        mutate: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>, &mut Vec<RepackedEntry>),
    ) {
        let decoder = GzDecoder::new(File::open(input).unwrap());
        let mut archive = Archive::new(decoder);
        let mut entries = archive.entries().unwrap();
        let mut manifest = Vec::new();
        entries
            .next()
            .unwrap()
            .unwrap()
            .read_to_end(&mut manifest)
            .unwrap();
        let mut signature = Vec::new();
        entries
            .next()
            .unwrap()
            .unwrap()
            .read_to_end(&mut signature)
            .unwrap();
        let mut payload = Vec::new();
        for item in entries {
            let mut entry = item.unwrap();
            let path = archive_path_string(&entry).unwrap();
            let kind = entry.header().entry_type();
            let mode = entry.header().mode().unwrap();
            let (data, link) = if kind.is_symlink() {
                let target = entry
                    .link_name()
                    .unwrap()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                (Vec::new(), Some(target))
            } else {
                let mut data = Vec::new();
                entry.read_to_end(&mut data).unwrap();
                (data, None)
            };
            payload.push(RepackedEntry {
                path,
                kind,
                mode,
                data,
                link,
            });
        }
        mutate(&mut manifest, &mut signature, &mut payload);

        let output = File::create(output).unwrap();
        let encoder = GzBuilder::new()
            .mtime(0)
            .write(output, Compression::default());
        let mut builder = Builder::new(encoder);
        append_bytes(&mut builder, MANIFEST_NAME, &manifest, 0o644).unwrap();
        append_bytes(&mut builder, SIGNATURE_NAME, &signature, 0o644).unwrap();
        for entry in payload {
            let mut header = Header::new_gnu();
            header.set_mode(entry.mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            if entry.kind.is_symlink() {
                header.set_entry_type(EntryType::Symlink);
                header.set_size(0);
                header.set_link_name(entry.link.unwrap()).unwrap();
                header.set_cksum();
                builder
                    .append_data(&mut header, entry.path, io::empty())
                    .unwrap();
            } else {
                header.set_entry_type(EntryType::Regular);
                header.set_size(entry.data.len() as u64);
                header.set_cksum();
                builder
                    .append_data(&mut header, entry.path, entry.data.as_slice())
                    .unwrap();
            }
        }
        builder.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn packs_and_verifies_regular_files_and_safe_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("feature.aup");
        let signing_path = temp.path().join("signing.key");
        fs::create_dir_all(source.join("usr/bin")).unwrap();
        fs::create_dir_all(source.join("etc")).unwrap();
        fs::write(source.join("usr/bin/tool"), b"hello arkanaOS\n").unwrap();
        fs::write(source.join("etc/settings.conf"), b"theme=solarized\n").unwrap();
        symlink("tool", source.join("usr/bin/tool-link")).unwrap();
        let signing = signing_key();
        write_key(&signing_path, &signing);

        let manifest = create_pack(&test_options(&source, &output, &signing_path)).unwrap();
        assert_eq!(manifest.entries.len(), 3);
        assert!(manifest.entries.iter().any(|entry| entry.config));
        let verified = verify_archive_with_key(&output, &signing.verifying_key()).unwrap();
        assert_eq!(verified.manifest.name, "desktop-feature");
        assert_eq!(verified.manifest.entries.len(), 3);
    }

    #[test]
    fn marks_only_selected_etc_files_as_system_managed() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("system.aup");
        let signing_path = temp.path().join("signing.key");
        fs::create_dir_all(source.join("etc")).unwrap();
        fs::write(source.join("etc/os-release"), b"VERSION=2\n").unwrap();
        fs::write(source.join("etc/local.conf"), b"setting=2\n").unwrap();
        let signing = signing_key();
        write_key(&signing_path, &signing);
        let mut options = test_options(&source, &output, &signing_path);
        options.system_files.push("etc/os-release".into());

        let manifest = create_pack(&options).unwrap();
        let release = manifest
            .entries
            .iter()
            .find(|entry| entry.path == "etc/os-release")
            .unwrap();
        let config = manifest
            .entries
            .iter()
            .find(|entry| entry.path == "etc/local.conf")
            .unwrap();
        assert!(!release.config);
        assert!(config.config);
    }

    #[test]
    fn packer_excludes_linker_cache_and_mutable_state() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("system.aup");
        let signing_path = temp.path().join("signing.key");
        fs::create_dir_all(source.join("etc/arkup/trustedkeys.d")).unwrap();
        fs::create_dir_all(source.join("etc/arkpkg")).unwrap();
        fs::create_dir_all(source.join("etc")).unwrap();
        fs::create_dir_all(source.join("var/lib/dbus")).unwrap();
        fs::create_dir_all(source.join("var/lib/arkup/installed")).unwrap();
        fs::create_dir_all(source.join("root")).unwrap();
        fs::create_dir_all(source.join("srv/site")).unwrap();
        fs::create_dir_all(source.join("usr/local/bin")).unwrap();
        fs::create_dir_all(source.join("usr/lib")).unwrap();
        fs::write(source.join("etc/ld.so.cache"), b"host-specific cache").unwrap();
        fs::write(source.join("etc/machine-id"), b"host machine id").unwrap();
        symlink("/usr/share/zoneinfo/UTC", source.join("etc/localtime")).unwrap();
        symlink(
            "/run/systemd/resolve/stub-resolv.conf",
            source.join("etc/resolv.conf"),
        )
        .unwrap();
        fs::write(source.join("etc/arkpkg/repos.d.json"), b"repository config").unwrap();
        fs::write(source.join("var/lib/dbus/machine-id"), b"machine id").unwrap();
        fs::write(source.join("var/lib/arkup/installed/old.json"), b"state").unwrap();
        fs::write(source.join("root/.bashrc"), b"root configuration").unwrap();
        fs::write(source.join("srv/site/index.html"), b"site data").unwrap();
        fs::write(source.join("usr/local/bin/local-tool"), b"local tool").unwrap();
        fs::write(source.join("usr/lib/library.so"), b"library").unwrap();
        let signing = signing_key();
        write_key(&signing_path, &signing);

        let manifest = create_pack(&test_options(&source, &output, &signing_path)).unwrap();
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].path, "usr/lib/library.so");
    }

    #[test]
    fn rejects_signature_and_payload_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let package = temp.path().join("system.aup");
        let bad_signature = temp.path().join("bad-signature.aup");
        let bad_payload = temp.path().join("bad-payload.aup");
        let signing_path = temp.path().join("signing.key");
        fs::create_dir_all(source.join("usr/bin")).unwrap();
        fs::write(source.join("usr/bin/tool"), b"signed bytes").unwrap();
        let signing = signing_key();
        write_key(&signing_path, &signing);
        create_pack(&test_options(&source, &package, &signing_path)).unwrap();

        rewrite_archive(&package, &bad_signature, |_, signature, _| {
            let mut bytes = STANDARD.decode(signature.as_slice()).unwrap();
            bytes[0] ^= 0x80;
            *signature = STANDARD.encode(bytes).into_bytes();
        });
        assert!(verify_archive_with_key(&bad_signature, &signing.verifying_key()).is_err());

        rewrite_archive(&package, &bad_payload, |_, _, entries| {
            entries[0].data[0] ^= 0x01;
        });
        assert!(verify_archive_with_key(&bad_payload, &signing.verifying_key()).is_err());
    }

    #[test]
    fn rejects_duplicate_archive_entries() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let package = temp.path().join("original.aup");
        let duplicate = temp.path().join("duplicate.aup");
        let signing_path = temp.path().join("signing.key");
        fs::create_dir_all(source.join("usr/bin")).unwrap();
        fs::write(source.join("usr/bin/tool"), b"one entry").unwrap();
        let signing = signing_key();
        write_key(&signing_path, &signing);
        create_pack(&test_options(&source, &package, &signing_path)).unwrap();
        rewrite_archive(&package, &duplicate, |_, _, entries| {
            entries.push(entries[0].clone());
        });

        assert!(verify_archive_with_key(&duplicate, &signing.verifying_key()).is_err());
    }

    #[test]
    fn trusted_key_symlink_cannot_escape_target_root() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let package = temp.path().join("system.aup");
        let signing_path = temp.path().join("signing.key");
        let trusted_root = temp.path().join("root");
        let external_keys = temp.path().join("external-keys");
        fs::create_dir_all(source.join("usr/bin")).unwrap();
        fs::create_dir_all(trusted_root.join("etc/arkup")).unwrap();
        fs::create_dir_all(&external_keys).unwrap();
        fs::write(source.join("usr/bin/tool"), b"signed bytes").unwrap();
        let signing = signing_key();
        write_key(&signing_path, &signing);
        let manifest = create_pack(&test_options(&source, &package, &signing_path)).unwrap();
        fs::write(
            external_keys.join(format!("{}.pub", manifest.key_id)),
            STANDARD.encode(signing.verifying_key().to_bytes()),
        )
        .unwrap();
        symlink(&external_keys, trusted_root.join("etc/arkup/trustedkeys.d")).unwrap();

        assert!(verify_archive(&package, &trusted_root, None).is_err());
    }

    #[test]
    fn rejects_excessive_sizes_before_reading_archive_bodies() {
        for kind in [
            EntryType::GNULongName,
            EntryType::GNULongLink,
            EntryType::XHeader,
            EntryType::XGlobalHeader,
            EntryType::Regular,
            EntryType::GNUSparse,
        ] {
            let mut header = Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(u64::MAX);
            header.set_cksum();
            // No body: the size error must precede any attempt to read it.
            let mut reader = BoundedArchiveReader::new(io::Cursor::new(header.as_bytes()));
            let error = reader.read_exact(&mut [0; 512]).unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "{kind:?}: {error}"
            );
            assert_eq!(reader.inner.position(), 512);
        }
        let mut header = Header::new_gnu();
        header.set_size(MAX_DECOMPRESSED_BYTES);
        header.set_cksum();
        let mut reader = BoundedArchiveReader::new(header.as_bytes().as_slice());
        let error = reader.read_exact(&mut [0; 512]).unwrap_err();
        assert!(error.to_string().contains("decompressed-size limit"));
    }

    #[test]
    fn bounds_cumulative_extensions_even_when_each_extension_is_within_limit() {
        let encoder = GzBuilder::new().write(Vec::new(), Compression::fast());
        let mut builder = Builder::new(encoder);
        let mut extension = Header::new_gnu();
        extension.set_entry_type(EntryType::GNULongName);
        extension.set_size(MAX_EXTENSION_BYTES);
        extension.set_cksum();
        for _ in 0..=MAX_METADATA_BYTES / (512 + MAX_EXTENSION_BYTES) {
            builder
                .append(&extension, io::repeat(b'a').take(MAX_EXTENSION_BYTES))
                .unwrap();
            append_bytes(&mut builder, "payload/file", b"", 0o644).unwrap();
        }
        let compressed = builder.into_inner().unwrap().finish().unwrap();
        let reader = BoundedArchiveReader::new(GzDecoder::new(compressed.as_slice()));
        let mut archive = Archive::new(reader);
        let error = archive.entries().unwrap().find_map(Result::err).unwrap();
        assert!(
            error
                .to_string()
                .contains("extensions exceed the metadata limit")
        );
    }

    #[test]
    fn preserves_pax_size_overrides_across_gnu_extensions() {
        for raw_size in [0, 1024, u64::MAX] {
            let mut builder = Builder::new(Vec::new());
            builder
                .append_pax_extensions([
                    ("size", b"5".as_slice()),
                    ("path", b"payload/file".as_slice()),
                ])
                .unwrap();
            for (kind, body) in [
                (EntryType::GNULongName, b"payload/file\0".as_slice()),
                (EntryType::GNULongLink, b"target\0".as_slice()),
            ] {
                let mut header = Header::new_gnu();
                header.set_entry_type(kind);
                header.set_size(body.len() as u64);
                header.set_cksum();
                builder.append(&header, body).unwrap();
            }
            let mut header = Header::new_gnu();
            header.set_size(raw_size);
            header.set_cksum();
            builder.append(&header, b"hello".as_slice()).unwrap();
            append_bytes(&mut builder, "payload/next", b"ok", 0o644).unwrap();
            let raw = builder.into_inner().unwrap();
            let mut archive = Archive::new(BoundedArchiveReader::new(raw.as_slice()));
            let mut entries = archive.entries().unwrap();
            let mut entry = entries.next().unwrap().unwrap();
            assert_eq!(entry.path().unwrap(), Path::new("payload/file"));
            assert_eq!(entry.size(), 5);
            assert_eq!(entry.link_name().unwrap().unwrap(), Path::new("target"));
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"hello");
            let mut entry = entries.next().unwrap().unwrap();
            assert_eq!(entry.path().unwrap(), Path::new("payload/next"));
            bytes.clear();
            entry.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"ok");
            assert!(entries.next().is_none());
        }
    }

    #[test]
    fn rejects_oversized_extensions_in_every_archive_pass() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let package = temp.path().join("original.aup");
        let malicious = temp.path().join("oversized.aup");
        let signing_path = temp.path().join("signing.key");
        let public_path = temp.path().join("signing.pub");
        fs::create_dir_all(source.join("usr/bin")).unwrap();
        fs::write(source.join("usr/bin/tool"), b"signed bytes").unwrap();
        let signing = signing_key();
        write_key(&signing_path, &signing);
        fs::write(
            &public_path,
            STANDARD.encode(signing.verifying_key().to_bytes()),
        )
        .unwrap();
        let manifest = create_pack(&test_options(&source, &package, &signing_path)).unwrap();
        let mut raw = Vec::new();
        GzDecoder::new(File::open(&package).unwrap())
            .read_to_end(&mut raw)
            .unwrap();
        let mut archive = Archive::new(raw.as_slice());
        let mut positions = Vec::new();
        let mut end = 0;
        for entry in archive.entries().unwrap().raw(true) {
            let entry = entry.unwrap();
            positions.push(entry.raw_header_position() as usize);
            end = entry.raw_file_position() + entry.size().div_ceil(512) * 512;
        }
        positions.push(end as usize);

        for kind in [
            EntryType::GNULongName,
            EntryType::GNULongLink,
            EntryType::XHeader,
        ] {
            for position in &positions {
                // A highly compressible extension, before each logical entry or at EOF.
                let mut extension = Header::new_gnu();
                extension.set_entry_type(kind);
                extension.set_size(64 * 1024 + 1);
                extension.set_cksum();
                let mut encoder = GzBuilder::new()
                    .write(File::create(&malicious).unwrap(), Compression::default());
                encoder.write_all(&raw[..*position]).unwrap();
                encoder.write_all(extension.as_bytes()).unwrap();
                io::copy(&mut io::repeat(0).take(64 * 1024 + 512), &mut encoder).unwrap();
                encoder.write_all(&raw[*position..]).unwrap();
                encoder.finish().unwrap();
                assert!(fs::metadata(&malicious).unwrap().len() < 4096);

                let errors = [
                    verify_archive(&malicious, temp.path(), Some(&public_path)).unwrap_err(),
                    verify_archive_with_key(&malicious, &signing.verifying_key()).unwrap_err(),
                    for_each_payload(&malicious, &manifest, |_, _| Ok(())).unwrap_err(),
                ];
                for error in errors {
                    assert!(
                        format!("{error:#}").contains("archive extension exceeds the size limit"),
                        "{kind:?} at {position}: {error:#}"
                    );
                }
            }
        }
    }

    #[test]
    fn supports_gnu_long_paths_without_accepting_extra_entries() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let package = temp.path().join("long-path.aup");
        let signing_path = temp.path().join("signing.key");
        let long_component = "long-name-".repeat(12);
        let path = PathBuf::from("usr/share")
            .join(&long_component)
            .join("manual.txt");
        fs::create_dir_all(source.join(path.parent().unwrap())).unwrap();
        fs::write(source.join(&path), b"manual").unwrap();
        let signing = signing_key();
        write_key(&signing_path, &signing);

        let manifest = create_pack(&test_options(&source, &package, &signing_path)).unwrap();
        assert!(manifest.entries[0].path.len() > 100);
        verify_archive_with_key(&package, &signing.verifying_key()).unwrap();
        for_each_payload(&package, &manifest, |_, _| Ok(())).unwrap();
    }
}
