//! Server secrets: from the environment, or generated once and kept in the
//! data directory.
//!
//! A local install (SQLite, no `.env`) used to get a fresh random JWT secret on
//! every start, and the vault reused it. Each restart therefore logged every
//! user out and left the stored credentials undecryptable. Now the first start
//! writes random secrets to `<data_dir>/secrets/` and later starts reuse them.
//!
//! Resolution order:
//! - JWT: `Z8_JWT_SECRET`, else `secrets/jwt.key`.
//! - Vault: `Z8_VAULT_SECRET`; else `Z8_JWT_SECRET` when that is set (the
//!   behavior existing deployments encrypted their vault with); else
//!   `secrets/vault.key`, which is independent of the JWT key.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

/// Minimum length accepted for a secret read from disk.
const MIN_FILE_SECRET_LEN: usize = 16;

/// Where a secret came from, for startup logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Env(&'static str),
    File,
    Generated,
}

/// The secrets the server signs sessions and encrypts the vault with.
pub struct Secrets {
    pub jwt: String,
    pub jwt_source: Source,
    pub vault: String,
    pub vault_source: Source,
}

/// Resolves the secrets from the process environment and `data_dir`.
pub fn resolve(data_dir: &Path) -> anyhow::Result<Secrets> {
    resolve_with(data_dir, |name| std::env::var(name).ok())
}

/// [`resolve`] with an injectable environment, for tests.
fn resolve_with(data_dir: &Path, env: impl Fn(&str) -> Option<String>) -> anyhow::Result<Secrets> {
    let env = |name: &'static str| env(name).filter(|v| !v.is_empty());
    let dir = data_dir.join("secrets");

    let (jwt, jwt_source) = match env("Z8_JWT_SECRET") {
        Some(secret) => (secret, Source::Env("Z8_JWT_SECRET")),
        None => load_or_create(&dir.join("jwt.key"))?,
    };
    let (vault, vault_source) = match env("Z8_VAULT_SECRET") {
        Some(secret) => (secret, Source::Env("Z8_VAULT_SECRET")),
        None if jwt_source == Source::Env("Z8_JWT_SECRET") => {
            (jwt.clone(), Source::Env("Z8_JWT_SECRET"))
        }
        None => load_or_create(&dir.join("vault.key"))?,
    };

    Ok(Secrets {
        jwt,
        jwt_source,
        vault,
        vault_source,
    })
}

/// Reads the secret at `path`, creating it with a random value if missing.
fn load_or_create(path: &Path) -> anyhow::Result<(String, Source)> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let secret = contents.trim().to_string();
            // Never replace a bad file: a new vault key would make every
            // stored credential unreadable. Let the operator decide.
            if secret.len() < MIN_FILE_SECRET_LEN {
                bail!(
                    "{} is empty or too short (< {MIN_FILE_SECRET_LEN} chars). Restore it from a \
                     backup, or delete it to generate a new one (credentials stored in the vault \
                     will then be unreadable).",
                    path.display()
                );
            }
            Ok((secret, Source::File))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let secret = generate();
            match write_new(path, &secret) {
                Ok(()) => Ok((secret, Source::Generated)),
                // Another process created it first: use theirs.
                Err(e) if e.kind() == ErrorKind::AlreadyExists => load_or_create(path),
                Err(e) => Err(e).with_context(|| format!("could not write {}", path.display())),
            }
        }
        Err(e) => Err(e).with_context(|| format!("could not read {}", path.display())),
    }
}

/// 32 random bytes, hex encoded.
fn generate() -> String {
    (0..32)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

/// Creates `path` (failing if it exists), readable only by the current user.
fn write_new(path: &Path, secret: &str) -> std::io::Result<()> {
    let dir: PathBuf = path.parent().map(Path::to_path_buf).unwrap_or_default();
    fs::create_dir_all(&dir)?;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        options.mode(0o600);
    }
    // On Windows the file inherits the ACL of the per-user data directory.
    let mut file = options.open(path)?;
    file.write_all(secret.as_bytes())?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("z8-secrets-{}", rand::random::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn first_start_generates_and_later_starts_reuse() {
        let dir = scratch_dir();

        let first = resolve_with(&dir, env(&[])).unwrap();
        assert_eq!(first.jwt_source, Source::Generated);
        assert_eq!(first.vault_source, Source::Generated);
        assert_eq!(first.jwt.len(), 64);
        assert_ne!(
            first.jwt, first.vault,
            "vault key is independent of the JWT key"
        );

        let second = resolve_with(&dir, env(&[])).unwrap();
        assert_eq!(second.jwt_source, Source::File);
        assert_eq!(second.vault_source, Source::File);
        assert_eq!((second.jwt, second.vault), (first.jwt, first.vault));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn environment_wins_and_legacy_vault_fallback_is_kept() {
        let dir = scratch_dir();
        let jwt = "j".repeat(32);
        let vault = "v".repeat(32);

        let both = resolve_with(
            &dir,
            env(&[("Z8_JWT_SECRET", &jwt), ("Z8_VAULT_SECRET", &vault)]),
        )
        .unwrap();
        assert_eq!(
            (both.jwt.as_str(), both.vault.as_str()),
            (jwt.as_str(), vault.as_str())
        );

        // Existing deployments with only Z8_JWT_SECRET encrypted their vault
        // with it; that must not change under them.
        let jwt_only = resolve_with(&dir, env(&[("Z8_JWT_SECRET", &jwt)])).unwrap();
        assert_eq!(jwt_only.vault, jwt);
        assert_eq!(jwt_only.vault_source, Source::Env("Z8_JWT_SECRET"));
        assert!(
            !dir.join("secrets").exists(),
            "nothing written when env provides both"
        );

        // Empty values count as unset.
        let empty = resolve_with(&dir, env(&[("Z8_JWT_SECRET", "")])).unwrap();
        assert_eq!(empty.jwt_source, Source::Generated);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_key_file_is_reported_not_replaced() {
        let dir = scratch_dir();
        fs::create_dir_all(dir.join("secrets")).unwrap();
        fs::write(dir.join("secrets/vault.key"), "  \n").unwrap();

        let err = resolve_with(&dir, env(&[])).err().unwrap().to_string();
        assert!(err.contains("vault.key"), "{err}");
        assert_eq!(
            fs::read_to_string(dir.join("secrets/vault.key")).unwrap(),
            "  \n"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir();
        resolve_with(&dir, env(&[])).unwrap();

        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.join("secrets")), 0o700);
        assert_eq!(mode(dir.join("secrets/jwt.key")), 0o600);
        assert_eq!(mode(dir.join("secrets/vault.key")), 0o600);

        let _ = fs::remove_dir_all(&dir);
    }
}
