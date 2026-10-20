use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

pub fn key_id(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(digest)
}

pub fn generate_keypair(
    output_dir: &Path,
) -> Result<(String, std::path::PathBuf, std::path::PathBuf)> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("cannot create key directory {}", output_dir.display()))?;

    let mut secret = Zeroizing::new([0_u8; 32]);
    File::open("/dev/urandom")?.read_exact(secret.as_mut())?;
    let signing_key = SigningKey::from_bytes(&secret);
    let public_bytes = signing_key.verifying_key().to_bytes();
    let id = key_id(&public_bytes);
    let private_path = output_dir.join(format!("{id}.key"));
    let public_path = output_dir.join(format!("{id}.pub"));

    let encoded_secret = Zeroizing::new(STANDARD.encode(*secret));
    write_new_secret(&private_path, encoded_secret.as_bytes())?;
    if let Err(error) = write_new_public(&public_path, STANDARD.encode(public_bytes).as_bytes()) {
        let _ = fs::remove_file(&private_path);
        return Err(error);
    }
    Ok((id, private_path, public_path))
}

pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let encoded = Zeroizing::new(read_key_text(path, true)?);
    let bytes = Zeroizing::new(
        STANDARD
            .decode(encoded.trim())
            .context("signing key is not valid base64")?,
    );
    ensure!(
        bytes.len() == 32,
        "signing key must contain exactly 32 bytes"
    );
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&bytes);
    let secret = Zeroizing::new(secret);
    Ok(SigningKey::from_bytes(&secret))
}

pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let encoded = read_key_text(path, false)?;
    let bytes = STANDARD
        .decode(encoded.trim())
        .context("trusted key is not valid base64")?;
    let public_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("trusted key must contain exactly 32 bytes"))?;
    VerifyingKey::from_bytes(&public_bytes).context("trusted key is invalid")
}

fn read_key_text(path: &Path, private: bool) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("cannot open key {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(metadata.file_type().is_file(), "key must be a regular file");
    if private {
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "signing key must have permissions no broader than 0600"
        );
    }
    let mut encoded = String::new();
    file.read_to_string(&mut encoded)?;
    Ok(encoded)
}

pub fn sign(signing_key: &SigningKey, message: &[u8]) -> [u8; 64] {
    signing_key.sign(message).to_bytes()
}

pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature_bytes: &[u8]) -> Result<()> {
    let signature = Signature::from_slice(signature_bytes)
        .context("update signature must contain exactly 64 bytes")?;
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| anyhow::anyhow!("update signature is invalid"))
}

fn write_new_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("refusing to overwrite existing key {}", path.display()))?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn write_new_public(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("refusing to overwrite existing key {}", path.display()))?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_private_and_verifiable() {
        let directory = tempfile::tempdir().unwrap();
        let (id, private_path, public_path) = generate_keypair(directory.path()).unwrap();
        let signing = load_signing_key(&private_path).unwrap();
        let verifying = load_verifying_key(&public_path).unwrap();
        assert_eq!(id, key_id(&verifying.to_bytes()));

        let message = b"arkup test manifest";
        let signature = sign(&signing, message);
        verify(&verifying, message, &signature).unwrap();
        assert!(verify(&verifying, b"tampered manifest", &signature).is_err());

        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(private_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn key_generation_never_overwrites_existing_keys() {
        let directory = tempfile::tempdir().unwrap();
        let (_, private_path, _) = generate_keypair(directory.path()).unwrap();
        assert!(generate_keypair(directory.path()).is_ok());
        assert!(private_path.exists());
    }

    #[test]
    fn signing_key_loader_rejects_broad_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let private_key = directory.path().join("weak.key");
        fs::write(&private_key, STANDARD.encode([9_u8; 32])).unwrap();
        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_signing_key(&private_key).is_err());
    }
}
