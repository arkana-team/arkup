use super::{
    DirectoryCache, FILE_DESCRIPTOR_RESERVE, InstalledRecord, MAX_TRANSACTION_DIRECTORY_FDS,
    check_destination, is_modified_deleted_config, resolve_existing_destination_with_cache,
};
use crate::manifest::{EntryKind, UpdateEntry};
use anyhow::{Context, Result, bail, ensure};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[derive(Clone)]
enum Node {
    Directory(Option<(u64, u64)>),
    Symlink(PathBuf),
    File,
    Missing,
}

// This view only predicts paths and descriptor use. Apply still opens and
// verifies live directories before writing and retains their handles for rollback.
pub(super) struct DescriptorPlan<'a> {
    root: &'a Path,
    changes: HashMap<PathBuf, Node>,
    existing_directories: HashSet<(u64, u64)>,
    new_directories: usize,
}

impl<'a> DescriptorPlan<'a> {
    pub(super) fn new(root: &'a Path) -> Self {
        Self {
            root,
            changes: HashMap::new(),
            existing_directories: HashSet::new(),
            new_directories: 0,
        }
    }

    pub(super) fn required(&self) -> usize {
        self.existing_directories.len() + self.new_directories + FILE_DESCRIPTOR_RESERVE
    }

    pub(super) fn resolve(
        &mut self,
        relative: &str,
        create_parents: bool,
        protected: Option<&[PathBuf]>,
    ) -> Result<Option<PathBuf>> {
        let mut parts = relative.split('/').peekable();
        let mut current = self.root.to_path_buf();
        if let Node::Directory(Some(identity)) = self.node(&current)? {
            self.retain(identity)?;
        } else {
            bail!(
                "target root is no longer a directory: {}",
                current.display()
            );
        }
        while let Some(part) = parts.next() {
            let candidate = current.join(part);
            check_destination(self.root, &candidate, protected)?;
            if parts.peek().is_none() {
                return Ok(Some(candidate));
            }
            match self.node(&candidate)? {
                Node::Directory(identity) => {
                    if let Some(identity) = identity {
                        self.retain(identity)?;
                    }
                    current = candidate;
                }
                Node::Symlink(target) => {
                    let resolved =
                        self.resolve_alias(&current, &target, &mut 0)
                            .with_context(|| {
                                format!("cannot resolve update directory {}", candidate.display())
                            })?;
                    check_destination(self.root, &resolved, protected)?;
                    // Apply reopens every canonical component without following symlinks.
                    let mut ancestor = self.root.to_path_buf();
                    for component in resolved.strip_prefix(self.root)?.components() {
                        ancestor.push(component);
                        match self.node(&ancestor)? {
                            Node::Directory(Some(identity)) => self.retain(identity)?,
                            Node::Directory(None) => {}
                            _ => bail!(
                                "update path parent is not a directory: {}",
                                ancestor.display()
                            ),
                        }
                    }
                    current = resolved;
                }
                Node::Missing if create_parents => {
                    self.changes
                        .insert(candidate.clone(), Node::Directory(None));
                    self.new_directories += 1;
                    self.check_size()?;
                    current = candidate;
                }
                Node::Missing => return Ok(None),
                Node::File => bail!(
                    "update path parent is not a directory: {}",
                    candidate.display()
                ),
            }
        }
        bail!("empty update path")
    }

    pub(super) fn project_entry(
        &mut self,
        entry: &UpdateEntry,
        path: PathBuf,
        previous: Option<&InstalledRecord>,
    ) -> Result<()> {
        let existing = self.node(&path)?;
        if matches!(existing, Node::Directory(_)) {
            // Apply will refuse to replace it. Its directory identity is unchanged.
            return Ok(());
        }
        let node = match entry.kind {
            EntryKind::Symlink => Node::Symlink(PathBuf::from(
                entry
                    .target
                    .as_deref()
                    .context("symlink entry has no target")?,
            )),
            // A config file installed over a symlink goes to a sidecar. The
            // symlink itself remains available for later directory resolution.
            EntryKind::File if entry.config && matches!(existing, Node::Symlink(_)) => {
                return Ok(());
            }
            EntryKind::File => Node::File,
            EntryKind::Delete if matches!(existing, Node::Missing) => return Ok(()),
            EntryKind::Delete if entry.config => {
                // A previous payload operation through an alias may have changed
                // this node; the on-disk hash would no longer predict apply.
                ensure!(
                    !self.changes.contains_key(&path),
                    "cannot preflight config deletion after a projected change: {}",
                    entry.path
                );
                let relative = path
                    .strip_prefix(self.root)?
                    .to_str()
                    .context("non-UTF-8 config path")?;
                let mut cache = DirectoryCache::default();
                let destination =
                    resolve_existing_destination_with_cache(self.root, relative, &mut cache)?
                        .context("config deletion parent changed during preflight")?;
                let metadata = destination
                    .existing_metadata()?
                    .context("config deletion changed during preflight")?;
                if is_modified_deleted_config(&destination, &metadata, entry, previous)? {
                    return Ok(());
                }
                Node::Missing
            }
            EntryKind::Delete => Node::Missing,
        };
        self.changes.insert(path, node);
        Ok(())
    }

    fn retain(&mut self, identity: (u64, u64)) -> Result<()> {
        self.existing_directories.insert(identity);
        self.check_size()
    }

    fn check_size(&self) -> Result<()> {
        ensure!(
            self.required() <= MAX_TRANSACTION_DIRECTORY_FDS,
            "update requires {} directory file descriptors, above the supported limit of {MAX_TRANSACTION_DIRECTORY_FDS}",
            self.required()
        );
        Ok(())
    }

    fn node(&self, path: &Path) -> Result<Node> {
        if let Some(node) = self.changes.get(path) {
            return Ok(node.clone());
        }
        if path
            .parent()
            .is_some_and(|parent| matches!(self.changes.get(parent), Some(Node::Directory(None))))
        {
            return Ok(Node::Missing);
        }
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Node::Missing),
            Err(error) => return Err(error.into()),
        };
        Ok(if metadata.is_dir() {
            Node::Directory(Some((metadata.dev(), metadata.ino())))
        } else if metadata.file_type().is_symlink() {
            Node::Symlink(fs::read_link(path)?)
        } else {
            Node::File
        })
    }

    fn resolve_alias(&self, parent: &Path, target: &Path, links: &mut usize) -> Result<PathBuf> {
        *links += 1;
        ensure!(*links <= 40, "too many directory symlinks");
        let (mut current, path) = if target.is_absolute() {
            (
                self.root.to_path_buf(),
                target
                    .strip_prefix(self.root)
                    .context("update path traverses a directory symlink outside the target root")?,
            )
        } else {
            (parent.to_path_buf(), target)
        };
        for component in path.components() {
            match component {
                Component::Normal(part) => {
                    let candidate = current.join(part);
                    match self.node(&candidate)? {
                        Node::Directory(_) => current = candidate,
                        Node::Symlink(target) => {
                            current = self.resolve_alias(&current, &target, links)?
                        }
                        _ => bail!(
                            "directory symlink target is not a directory: {}",
                            candidate.display()
                        ),
                    }
                }
                Component::CurDir => {}
                Component::ParentDir if current != self.root => {
                    current.pop();
                }
                Component::ParentDir if self.root == Path::new("/") => {}
                _ => bail!("update path traverses a directory symlink outside the target root"),
            }
        }
        Ok(current)
    }
}
