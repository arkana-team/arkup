use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn arkup() -> Command {
    Command::new(env!("CARGO_BIN_EXE_arkup"))
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "arkup command failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn pack(source: &Path, key: &Path, output: &Path, sequence: u64, deletions: &[&str]) {
    let mut command = arkup();
    let version = format!("arkanaOS 1.0 (alpha 1) build {sequence}");
    let sequence = sequence.to_string();
    command.args([
        "pack",
        "--source",
        source.to_str().unwrap(),
        "--name",
        "arkanaos-system",
        "--version",
        &version,
        "--sequence",
        &sequence,
        "--arch",
        "any",
        "--description",
        "CLI integration update",
        "--signing-key",
        key.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    for path in deletions {
        command.args(["--delete", path]);
    }
    success(command.output().unwrap());
}

#[test]
fn rejects_unsigned_manifest_path_control_characters_in_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("unsigned.aup");
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    let path = "usr/bin/tool\narkup: forged success\r\t\0\x1b[2J\u{7f}\u{85}";
    let manifest = serde_json::to_vec(&serde_json::json!({
        "format_version": 1,
        "name": "system-update",
        "version": "1.0.1",
        "sequence": 1,
        "architecture": "any",
        "description": "diagnostic test",
        "key_id": "0".repeat(64),
        "entries": [{ "path": path, "kind": "delete", "mode": 0 }]
    }))
    .unwrap();
    let encoder = flate2::write::GzEncoder::new(
        fs::File::create(&package).unwrap(),
        flate2::Compression::default(),
    );
    let mut archive = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(manifest.len() as u64);
    header.set_cksum();
    archive
        .append_data(&mut header, "arkup.json", manifest.as_slice())
        .unwrap();
    archive.into_inner().unwrap().finish().unwrap();

    for command in ["verify", "list", "apply"] {
        let output = arkup()
            .arg(command)
            .arg(&package)
            .arg("--root")
            .arg(&root)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        let diagnostic = stderr.strip_suffix('\n').unwrap();
        assert!(diagnostic.contains("invalid update path"));
        assert!(!diagnostic.chars().any(char::is_control));
        assert!(diagnostic.contains(r"\narkup: forged success"));
        assert!(diagnostic.contains(r"\u{1b}[2J"));
        assert!(fs::read_dir(&root).unwrap().next().is_none());
    }
}

#[test]
fn cli_builds_verifies_trusts_and_applies_successive_aup_updates() {
    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("release-keys");
    let root = temp.path().join("system-root");
    let first_source = temp.path().join("first-source");
    let second_source = temp.path().join("second-source");
    let first_pack = temp.path().join("arkanaOS-1.aup");
    let second_pack = temp.path().join("arkanaOS-2.aup");
    fs::create_dir_all(first_source.join("etc")).unwrap();
    fs::create_dir_all(first_source.join("usr/bin")).unwrap();
    fs::create_dir_all(second_source.join("usr/bin")).unwrap();
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::write(first_source.join("etc/desktop.conf"), b"theme=solaris\n").unwrap();
    fs::write(first_source.join("usr/bin/old-tool"), b"old version").unwrap();
    fs::set_permissions(
        first_source.join("usr/bin/old-tool"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(root.join("etc/desktop.conf"), b"theme=custom\n").unwrap();
    fs::write(second_source.join("usr/bin/new-tool"), b"new version").unwrap();

    let output = arkup()
        .args(["keygen", "--output-dir", keys.to_str().unwrap()])
        .output()
        .unwrap();
    let keygen_output = success(output);
    let key_id = keygen_output
        .lines()
        .find_map(|line| line.strip_prefix("key id: "))
        .expect("keygen should print its public key id");
    let signing_key = keys.join(format!("{key_id}.key"));
    let public_key = keys.join(format!("{key_id}.pub"));

    success(
        arkup()
            .args([
                "trust",
                public_key.to_str().unwrap(),
                "--root",
                root.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    pack(&first_source, &signing_key, &first_pack, 233, &[]);
    assert!(
        success(
            arkup()
                .args([
                    "verify",
                    first_pack.to_str().unwrap(),
                    "--root",
                    root.to_str().unwrap(),
                ])
                .output()
                .unwrap(),
        )
        .contains("sequence 233")
    );
    assert!(
        success(
            arkup()
                .args([
                    "list",
                    first_pack.to_str().unwrap(),
                    "--root",
                    root.to_str().unwrap(),
                ])
                .output()
                .unwrap(),
        )
        .contains("etc/desktop.conf")
    );
    success(
        arkup()
            .args([
                "apply",
                first_pack.to_str().unwrap(),
                "--root",
                root.to_str().unwrap(),
                "--arch",
                "x86_64",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(
        fs::read(root.join("etc/desktop.conf")).unwrap(),
        b"theme=custom\n"
    );
    assert_eq!(
        fs::read(root.join("etc/desktop.conf.arkup-new")).unwrap(),
        b"theme=solaris\n"
    );
    assert_eq!(
        fs::metadata(root.join("usr/bin/old-tool"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );

    pack(
        &second_source,
        &signing_key,
        &second_pack,
        234,
        &["usr/bin/old-tool"],
    );
    success(
        arkup()
            .args([
                "apply",
                second_pack.to_str().unwrap(),
                "--root",
                root.to_str().unwrap(),
                "--arch",
                "x86_64",
            ])
            .output()
            .unwrap(),
    );
    assert!(!root.join("usr/bin/old-tool").exists());
    assert_eq!(
        fs::read(root.join("usr/bin/new-tool")).unwrap(),
        b"new version"
    );
    assert!(
        !arkup()
            .args([
                "apply",
                first_pack.to_str().unwrap(),
                "--root",
                root.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
}
