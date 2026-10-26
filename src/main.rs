use anyhow::Result;
use arkup::archive::{PackOptions, create_pack, verify_archive};
use arkup::install::{ApplyOptions, apply, trust_key};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "arkup",
    version,
    about = "Signed system update packs for arkanaOS"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a private signing key and its public trust key.
    Keygen {
        #[arg(long, default_value = "release-keys")]
        output_dir: PathBuf,
    },
    /// Add a public signing key to the target system's trust store.
    Trust {
        public_key: PathBuf,
        #[arg(long, default_value = "/")]
        root: PathBuf,
    },
    /// Build a signed .aup update pack from a staged root tree.
    Pack {
        #[arg(long)]
        source: PathBuf,
        /// Remove an existing path as part of the update; may be repeated.
        #[arg(long = "delete")]
        deletions: Vec<String>,
        /// Treat this exact path as system-managed rather than local config; may be repeated.
        #[arg(long = "system-file")]
        system_files: Vec<String>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long, default_value = "any")]
        arch: String,
        #[arg(long)]
        description: String,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify the signature, manifest, paths, and every payload checksum.
    Verify {
        package: PathBuf,
        #[arg(long, default_value = "/")]
        root: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// List the contents of a trusted, verified update pack.
    List {
        package: PathBuf,
        #[arg(long, default_value = "/")]
        root: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Apply a verified update pack and retain backups of replaced files.
    Apply {
        package: PathBuf,
        #[arg(long, default_value = "/")]
        root: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        arch: Option<String>,
        #[arg(long)]
        allow_downgrade: bool,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("arkup: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { output_dir } => {
            let (id, private_key, public_key) = arkup::key::generate_keypair(&output_dir)?;
            println!("key id: {id}");
            println!("private key: {}", private_key.display());
            println!("public key: {}", public_key.display());
            println!("keep the private key offline and out of Git");
        }
        Command::Trust { public_key, root } => {
            let path = trust_key(&public_key, &root)?;
            println!("trusted key installed at {}", path.display());
        }
        Command::Pack {
            source,
            deletions,
            system_files,
            name,
            version,
            sequence,
            arch,
            description,
            signing_key,
            output,
        } => {
            let manifest = create_pack(&PackOptions {
                source,
                deletions,
                system_files,
                name,
                version,
                sequence,
                architecture: arch,
                description,
                signing_key,
                output: output.clone(),
            })?;
            println!(
                "created {}: {} {} (sequence {}, {} files)",
                output.display(),
                manifest.name,
                manifest.version,
                manifest.sequence,
                manifest.entries.len()
            );
        }
        Command::Verify { package, root, key } => {
            let verified = verify_archive(&package, &root, key.as_deref())?;
            let manifest = verified.manifest;
            println!(
                "verified {} {} (sequence {}, {}, {} entries, key {})",
                manifest.name,
                manifest.version,
                manifest.sequence,
                manifest.architecture,
                manifest.entries.len(),
                manifest.key_id
            );
        }
        Command::List { package, root, key } => {
            let verified = verify_archive(&package, &root, key.as_deref())?;
            let manifest = verified.manifest;
            println!(
                "{} {} — {} (sequence {}, arch {})",
                manifest.name,
                manifest.version,
                manifest.description,
                manifest.sequence,
                manifest.architecture
            );
            for entry in manifest.entries {
                let kind = match entry.kind {
                    arkup::manifest::EntryKind::File => "file",
                    arkup::manifest::EntryKind::Symlink => "symlink",
                    arkup::manifest::EntryKind::Delete => "delete",
                };
                println!("{kind:7} {:04o} {}", entry.mode, entry.path);
            }
        }
        Command::Apply {
            package,
            root,
            key,
            arch,
            allow_downgrade,
        } => {
            let manifest = apply(&ApplyOptions {
                archive: package,
                root,
                supplied_key: key,
                architecture: arch,
                allow_downgrade,
            })?;
            println!(
                "applied {} {} (sequence {}, {} entries)",
                manifest.name,
                manifest.version,
                manifest.sequence,
                manifest.entries.len()
            );
        }
    }
    Ok(())
}
