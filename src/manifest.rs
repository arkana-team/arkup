use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

pub const FORMAT_VERSION: u32 = 1;
pub const MAX_MANIFEST_ENTRIES: usize = 100_000;
pub const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_PACKAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifest {
    pub format_version: u32,
    pub name: String,
    pub version: String,
    pub sequence: u64,
    pub architecture: String,
    pub description: String,
    pub key_id: String,
    pub entries: Vec<UpdateEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateEntry {
    pub path: String,
    pub kind: EntryKind,
    pub mode: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub config: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Symlink,
    Delete,
}

impl UpdateManifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == FORMAT_VERSION,
            "unsupported arkup format version {}",
            self.format_version
        );
        ensure!(valid_name(&self.name), "invalid update pack name");
        ensure!(valid_version(&self.version), "invalid update pack version");
        ensure!(
            valid_atom(&self.architecture),
            "invalid update pack architecture"
        );
        ensure!(
            !self.description.trim().is_empty()
                && self.description.len() <= 512
                && !self.description.chars().any(char::is_control),
            "invalid update pack description"
        );
        ensure!(valid_key_id(&self.key_id), "invalid signing key id");
        ensure!(
            !self.entries.is_empty() && self.entries.len() <= MAX_MANIFEST_ENTRIES,
            "update pack must contain between 1 and {MAX_MANIFEST_ENTRIES} entries"
        );

        let mut previous_path: Option<&str> = None;
        let mut paths = BTreeMap::new();
        for entry in &self.entries {
            validate_path(&entry.path)?;
            ensure!(
                !is_protected_path(&entry.path),
                "update pack may not write protected path '{}'",
                entry.path
            );
            if let Some(previous) = previous_path {
                ensure!(
                    previous < entry.path.as_str(),
                    "update manifest paths must be unique and sorted"
                );
            }
            previous_path = Some(&entry.path);
            paths.insert(entry.path.as_str(), entry);
            ensure!(entry.mode <= 0o7777, "invalid mode for '{}'", entry.path);

            match entry.kind {
                EntryKind::File => {
                    ensure!(
                        entry.target.is_none(),
                        "regular file '{}' has a symlink target",
                        entry.path
                    );
                    ensure!(
                        entry.size.is_some_and(|size| size <= MAX_PACKAGE_BYTES),
                        "regular file '{}' has an invalid size",
                        entry.path
                    );
                    ensure!(
                        entry.sha256.as_deref().is_some_and(valid_sha256),
                        "regular file '{}' has an invalid SHA-256 checksum",
                        entry.path
                    );
                }
                EntryKind::Symlink => {
                    ensure!(
                        entry.size.is_none() && entry.sha256.is_none(),
                        "symlink '{}' must not have file size or checksum fields",
                        entry.path
                    );
                    let target = entry
                        .target
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("symlink '{}' has no target", entry.path))?;
                    ensure!(
                        safe_symlink_target(&entry.path, target),
                        "symlink '{}' points outside the system root",
                        entry.path
                    );
                    ensure!(
                        !entry.config,
                        "symlink '{}' cannot be marked as a configuration file",
                        entry.path
                    );
                }
                EntryKind::Delete => {
                    ensure!(
                        entry.mode == 0
                            && entry.size.is_none()
                            && entry.sha256.is_none()
                            && entry.target.is_none(),
                        "delete entry '{}' must not contain file metadata",
                        entry.path
                    );
                }
            }
        }

        for entry in &self.entries {
            if entry.config && entry.kind == EntryKind::File {
                let sidecar = format!("{}.arkup-new", entry.path);
                ensure!(
                    !paths.contains_key(sidecar.as_str()),
                    "configuration update '{}' conflicts with its .arkup-new sidecar",
                    entry.path
                );
                ensure!(
                    !is_protected_path(&sidecar),
                    "configuration update '{}' has a protected .arkup-new sidecar",
                    entry.path
                );
            }
        }

        let symlinks: BTreeSet<&str> = self
            .entries
            .iter()
            .filter(|entry| entry.kind == EntryKind::Symlink)
            .map(|entry| entry.path.as_str())
            .collect();
        for entry in &self.entries {
            let mut parent = Path::new(&entry.path).parent();
            while let Some(path) = parent {
                let parent_string = path.to_string_lossy();
                ensure!(
                    !symlinks.contains(parent_string.as_ref()),
                    "entry '{}' descends through a symlink",
                    entry.path
                );
                ensure!(
                    !paths.contains_key(parent_string.as_ref()),
                    "entry '{}' descends through another update entry",
                    entry.path
                );
                parent = path.parent();
            }
        }
        Ok(())
    }
}

pub fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._+-".contains(&byte)
        })
}

pub fn valid_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

pub fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+- ()".contains(&byte))
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
}

pub fn valid_key_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn validate_path(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 4096
            && !value.contains('\\')
            && !value.starts_with('/')
            && !value.chars().any(char::is_control),
        "invalid update path '{}'",
        value
    );
    let path = Path::new(value);
    ensure!(
        value.split('/').all(|component| {
            !component.is_empty()
                && component.len() <= 255
                && component != "."
                && component != ".."
                && Path::new(component)
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
        }),
        "unsafe update path '{}'",
        value
    );
    ensure!(
        path.components().count() <= 128,
        "update path is too deep: '{}'",
        value
    );
    Ok(())
}

pub fn safe_symlink_target(link_path: &str, target: &str) -> bool {
    if target.is_empty() || target.contains('\\') || target.chars().any(char::is_control) {
        return false;
    }
    let target_path = Path::new(target);
    if target_path.is_absolute() {
        return target_path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    }

    let mut depth = Path::new(link_path)
        .parent()
        .map_or(0, |parent| parent.components().count());
    for component in target_path.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
            Component::CurDir => {}
        }
    }
    true
}

pub fn is_protected_path(value: &str) -> bool {
    if value == "etc/ld.so.cache"
        || value.starts_with("etc/ld.so.cache/")
        || matches!(
            value,
            "etc/localtime" | "etc/resolv.conf" | "etc/machine-id"
        )
        || value == "etc/arkup"
        || value.starts_with("etc/arkup/")
        || value == "var/lib/arkup"
        || value.starts_with("var/lib/arkup/")
        || value == "var/lib/arkpkg"
        || value.starts_with("var/lib/arkpkg/")
        || value == "etc/arkpkg"
        || value.starts_with("etc/arkpkg/")
    {
        return true;
    }

    let mut components = value.split('/');
    let first = components.next().unwrap_or_default();
    if matches!(
        first,
        "dev" | "proc" | "sys" | "run" | "tmp" | "home" | "root" | "srv"
    ) {
        return true;
    }
    matches!(
        (first, components.next().unwrap_or_default()),
        ("var", "cache" | "lib" | "log" | "spool" | "tmp") | ("usr", "local")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_host_cache_and_runtime_paths() {
        assert!(validate_path("etc/ld.so.cache").is_ok());
        assert!(is_protected_path("etc/ld.so.cache"));
        assert!(is_protected_path("etc/localtime"));
        assert!(is_protected_path("etc/resolv.conf"));
        assert!(is_protected_path("etc/machine-id"));
        assert!(is_protected_path("root/.NsCDE/NsCDE.conf"));
        assert!(is_protected_path("srv/site/index.html"));
        assert!(is_protected_path("usr/local/bin/local-tool"));
        assert!(is_protected_path("var/lib/dbus/machine-id"));
        assert!(is_protected_path("var/spool/mail/user"));
        assert!(is_protected_path("var/lib/arkup/installed/system.json"));
        assert!(is_protected_path("dev/null"));
        assert!(!is_protected_path("usr/lib/libc.so.6"));
    }

    #[test]
    fn rejects_traversal_and_unsafe_symlinks() {
        assert!(validate_path("../etc/passwd").is_err());
        assert!(validate_path("usr//bin/tool").is_err());
        assert!(!safe_symlink_target("usr/bin/tool", "../../../etc/passwd"));
        assert!(safe_symlink_target("usr/bin/tool", "../lib/tool"));
        assert!(safe_symlink_target("usr/bin/tool", "/usr/lib/tool"));
        assert!(!safe_symlink_target("usr/bin/tool", "/usr/../etc/passwd"));
    }

    #[test]
    fn manifest_requires_sorted_unique_paths() {
        let mut manifest = UpdateManifest {
            format_version: FORMAT_VERSION,
            name: "system-update".into(),
            version: "1.0.1".into(),
            sequence: 1,
            architecture: "x86_64".into(),
            description: "system update".into(),
            key_id: "0011223344556677001122334455667700112233445566770011223344556677".into(),
            entries: vec![
                UpdateEntry {
                    path: "usr/bin/zeta".into(),
                    kind: EntryKind::File,
                    mode: 0o755,
                    size: Some(1),
                    sha256: Some("0".repeat(64)),
                    target: None,
                    config: false,
                },
                UpdateEntry {
                    path: "usr/bin/alpha".into(),
                    kind: EntryKind::File,
                    mode: 0o755,
                    size: Some(1),
                    sha256: Some("0".repeat(64)),
                    target: None,
                    config: false,
                },
            ],
        };
        assert!(manifest.validate().is_err());
        manifest.entries.reverse();
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn rejects_unknown_fields() {
        let invalid = r#"{"format_version":1,"name":"system","version":"1","sequence":1,"architecture":"x86_64","description":"test","key_id":"0011223344556677001122334455667700112233445566770011223344556677","entries":[],"script":"rm -rf /"}"#;
        assert!(serde_json::from_str::<UpdateManifest>(invalid).is_err());
    }

    #[test]
    fn accepts_display_versions_and_rejects_sidecar_collisions() {
        assert!(valid_version("arkanaOS 1.0 (alpha 1) build 891"));
        assert!(!valid_version("1.0\nunsafe"));

        let mut manifest = UpdateManifest {
            format_version: FORMAT_VERSION,
            name: "system-update".into(),
            version: "arkanaOS 1.0 (alpha 1) build 891".into(),
            sequence: 891,
            architecture: "x86_64".into(),
            description: "system update".into(),
            key_id: "0011223344556677001122334455667700112233445566770011223344556677".into(),
            entries: vec![
                UpdateEntry {
                    path: "etc/example.conf".into(),
                    kind: EntryKind::File,
                    mode: 0o644,
                    size: Some(1),
                    sha256: Some("0".repeat(64)),
                    target: None,
                    config: true,
                },
                UpdateEntry {
                    path: "etc/example.conf.arkup-new".into(),
                    kind: EntryKind::File,
                    mode: 0o644,
                    size: Some(1),
                    sha256: Some("0".repeat(64)),
                    target: None,
                    config: true,
                },
            ],
        };
        assert!(manifest.validate().is_err());
        manifest.entries.pop();
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn rejects_file_and_delete_entries_that_are_parent_paths() {
        let mut manifest = UpdateManifest {
            format_version: FORMAT_VERSION,
            name: "system-update".into(),
            version: "1.0.1".into(),
            sequence: 1,
            architecture: "x86_64".into(),
            description: "system update".into(),
            key_id: "0011223344556677001122334455667700112233445566770011223344556677".into(),
            entries: vec![
                UpdateEntry {
                    path: "usr/bin/tool".into(),
                    kind: EntryKind::Delete,
                    mode: 0,
                    size: None,
                    sha256: None,
                    target: None,
                    config: false,
                },
                UpdateEntry {
                    path: "usr/bin/tool/data".into(),
                    kind: EntryKind::File,
                    mode: 0o644,
                    size: Some(1),
                    sha256: Some("0".repeat(64)),
                    target: None,
                    config: false,
                },
            ],
        };
        assert!(manifest.validate().is_err());
        manifest.entries.remove(0);
        assert!(manifest.validate().is_ok());
    }
}
