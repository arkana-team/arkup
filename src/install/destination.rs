use anyhow::{Context, Result, ensure};
use rustix::fs::{self as at, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

// Keep the checked parent open for staging, installation, deletion and rollback.
// Reopening its pathname would allow a directory symlink swap to redirect them.
pub(super) struct Destination {
    pub parent: File,
    pub name: OsString,
    pub path: PathBuf,
}

impl Destination {
    pub fn metadata(&self) -> Result<Option<Stat>> {
        match at::statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn existing_metadata(&self) -> Result<Option<Stat>> {
        let metadata = self.metadata()?;
        if let Some(metadata) = &metadata {
            let kind = FileType::from_raw_mode(metadata.st_mode);
            ensure!(
                kind.is_file() || kind.is_symlink(),
                "refusing to replace unsupported destination {}",
                self.path.display()
            );
        }
        Ok(metadata)
    }

    pub fn open_file(&self) -> Result<File> {
        let file = File::from(at::openat(
            &self.parent,
            &self.name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        ensure!(
            file.metadata()?.is_file(),
            "destination must be a regular file"
        );
        Ok(file)
    }

    pub fn read_link(&self) -> Result<PathBuf> {
        let target = at::readlinkat(&self.parent, &self.name, Vec::new())?;
        Ok(OsString::from_vec(target.into_bytes()).into())
    }

    pub fn remove(&self, flags: AtFlags) -> io::Result<()> {
        at::unlinkat(&self.parent, &self.name, flags).map_err(Into::into)
    }

    pub fn stage_file(&self) -> Result<(Staged, File)> {
        loop {
            let mut staged = self.staged_name()?;
            match at::openat(
                &staged.parent,
                &staged.name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(file) => {
                    staged.armed = true;
                    return Ok((staged, file.into()));
                }
                Err(Errno::EXIST) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn stage_symlink(&self, target: &Path) -> Result<Staged> {
        loop {
            let mut staged = self.staged_name()?;
            match at::symlinkat(target, &staged.parent, &staged.name) {
                Ok(()) => {
                    staged.armed = true;
                    return Ok(staged);
                }
                Err(Errno::EXIST) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn staged_name(&self) -> Result<Staged> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let name = loop {
            let name = OsString::from(format!(
                ".arkup-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            if name != self.name {
                break name;
            }
        };
        Ok(Staged {
            parent: self.parent.try_clone()?,
            name,
            armed: false,
        })
    }
}

pub(super) struct Staged {
    parent: File,
    name: OsString,
    armed: bool,
}

impl Staged {
    pub fn persist(mut self, destination: &Destination) -> Result<()> {
        at::renameat(
            &self.parent,
            &self.name,
            &destination.parent,
            &destination.name,
        )
        .with_context(|| format!("cannot install {}", destination.path.display()))?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if self.armed {
            let _ = at::unlinkat(&self.parent, &self.name, AtFlags::empty());
        }
    }
}

pub(super) fn open_directory(parent: &File, name: &Path) -> Result<File> {
    Ok(at::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into())
}

pub(super) fn create_directory(parent: &File, name: &str) -> Result<File> {
    at::mkdirat(parent, name, Mode::from_raw_mode(0o755))?;
    let directory = open_directory(parent, Path::new(name))?;
    use std::os::unix::fs::PermissionsExt;
    directory.set_permissions(fs::Permissions::from_mode(0o755))?;
    Ok(directory)
}
