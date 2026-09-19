//! `z8run init`: choose the database and port once and save them (#78).
//!
//! The answers go to `<data_dir>/z8run.env`, which every command loads at
//! startup. Real environment variables and a `.env` in the working directory
//! still take precedence, so Docker and scripted setups are unaffected.

use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};

/// Config file name inside the data directory.
pub const CONFIG_FILE: &str = "z8run.env";

/// Secrets carried over when the file is rewritten: a new vault key would
/// make every stored credential unreadable.
const KEPT_KEYS: &[&str] = &["Z8_JWT_SECRET", "Z8_VAULT_SECRET"];

pub fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CONFIG_FILE)
}

/// Loads `<data_dir>/z8run.env` without overriding variables already set.
/// Returns whether a file was loaded.
pub fn load(data_dir: &Path) -> anyhow::Result<bool> {
    let path = config_path(data_dir);
    match dotenvy::from_path(&path) {
        Ok(()) => Ok(true),
        Err(dotenvy::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("could not read {}", path.display())),
    }
}

/// What the user chose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answers {
    pub db_url: String,
    pub port: u16,
}

/// SQLite URL for a database file. sqlx percent-decodes the path, so the
/// characters that would change its meaning (`%`, `?`, `#`) are encoded.
pub fn sqlite_file_url(file: &str) -> String {
    let path = file
        .replace('%', "%25")
        .replace('?', "%3F")
        .replace('#', "%23");
    format!("sqlite://{path}?mode=rwc")
}

fn ask<R: BufRead, W: Write>(input: &mut R, out: &mut W, question: &str) -> anyhow::Result<String> {
    write!(out, "{question}")?;
    out.flush()?;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        bail!("no answer (input closed); pass --db-url and --port to run without prompts");
    }
    Ok(line.trim().to_string())
}

/// Asks for the database and port, re-asking on invalid answers.
pub fn prompt<R: BufRead, W: Write>(
    input: &mut R,
    out: &mut W,
    default_sqlite_file: &Path,
) -> anyhow::Result<Answers> {
    writeln!(out, "Database:")?;
    writeln!(
        out,
        "  1) SQLite      a single file, nothing to install (recommended)"
    )?;
    writeln!(out, "  2) PostgreSQL  an existing server")?;
    let postgres = loop {
        match ask(input, out, "Choose [1]: ")?.as_str() {
            "" | "1" => break false,
            "2" => break true,
            other => writeln!(out, "  '{other}' is not an option; type 1 or 2.")?,
        }
    };

    let db_url = if postgres {
        loop {
            let url = ask(
                input,
                out,
                "PostgreSQL URL (postgres://user:password@host:5432/database): ",
            )?;
            if url.starts_with("postgres://") || url.starts_with("postgresql://") {
                break url;
            }
            writeln!(
                out,
                "  The URL must start with postgres:// or postgresql://"
            )?;
        }
    } else {
        let default = default_sqlite_file.display().to_string();
        let file = ask(input, out, &format!("SQLite file [{default}]: "))?;
        let file = if file.is_empty() { default } else { file };
        // The server may start from another directory: store it absolute.
        let file = std::path::absolute(&file).unwrap_or_else(|_| PathBuf::from(&file));
        sqlite_file_url(&file.display().to_string())
    };

    let port = loop {
        let answer = ask(input, out, "Port [7700]: ")?;
        if answer.is_empty() {
            break 7700;
        }
        match answer.parse::<u16>() {
            Ok(p) if p > 0 => break p,
            _ => writeln!(out, "  '{answer}' is not a port number (1-65535).")?,
        }
    };

    Ok(Answers { db_url, port })
}

/// Opens the database and applies migrations, so problems show up now
/// rather than on the next start.
pub async fn verify(db_url: &str) -> anyhow::Result<()> {
    let check = async {
        if db_url.starts_with("postgres") {
            // One direct connection first: the pool retries until its own
            // timeout and would hide "connection refused" or a bad password.
            use sqlx::Connection;
            sqlx::PgConnection::connect(db_url).await?.close().await?;
            let pg = z8run_storage::postgres::PgStorage::new(db_url).await?;
            pg.migrate().await?;
        } else {
            use std::str::FromStr;
            let opts = sqlx::sqlite::SqliteConnectOptions::from_str(db_url)?;
            if let Some(dir) = opts
                .get_filename()
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
            {
                fs::create_dir_all(dir)
                    .with_context(|| format!("could not create {}", dir.display()))?;
            }
            let sqlite = z8run_storage::sqlite::SqliteStorage::new(db_url).await?;
            sqlite.migrate().await?;
        }
        anyhow::Ok(())
    };
    tokio::time::timeout(Duration::from_secs(15), check)
        .await
        .context("timed out connecting to the database")?
}

/// Renders the config file. Values are single-quoted so `#`, `$` and spaces
/// are taken literally.
fn render(entries: &[(&str, String)]) -> anyhow::Result<String> {
    let mut out = String::from(
        "# Written by `z8run init`. Environment variables and a .env file in the\n\
         # working directory take precedence over these values.\n",
    );
    for (key, value) in entries {
        if value.contains('\'') || value.contains('\n') {
            bail!(
                "{key} contains a quote or line break; percent-encode it in the URL \
                 (' is %27)"
            );
        }
        out.push_str(&format!("{key}='{value}'\n"));
    }
    Ok(out)
}

/// Existing values of [`KEPT_KEYS`] in the config file.
fn kept_secrets(path: &Path) -> Vec<(&'static str, String)> {
    let Ok(iter) = dotenvy::from_path_iter(path) else {
        return Vec::new();
    };
    let found: Vec<(String, String)> = iter.filter_map(Result::ok).collect();
    KEPT_KEYS
        .iter()
        .filter_map(|key| {
            found
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| (*key, v.clone()))
        })
        .collect()
}

/// 32 random bytes, hex encoded.
fn random_secret() -> String {
    (0..32)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

/// Writes the config for `answers`. PostgreSQL needs its secrets from the
/// environment, so they are generated here unless the file already has them.
pub fn write(data_dir: &Path, answers: &Answers) -> anyhow::Result<PathBuf> {
    let path = config_path(data_dir);
    let mut entries: Vec<(&str, String)> = vec![
        ("Z8_DB_URL", answers.db_url.clone()),
        ("Z8_PORT", answers.port.to_string()),
    ];
    let kept = kept_secrets(&path);
    entries.extend(kept.iter().cloned());
    if answers.db_url.starts_with("postgres") {
        for key in KEPT_KEYS {
            if !kept.iter().any(|(k, _)| k == key) {
                entries.push((key, random_secret()));
            }
        }
    }
    let contents = render(&entries)?;

    fs::create_dir_all(data_dir)?;
    let tmp = path.with_extension("env.tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .with_context(|| format!("could not write {}", tmp.display()))?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, &path)?;
    Ok(path)
}

/// `z8run init`.
pub async fn run(
    data_dir: &Path,
    db_url: Option<String>,
    port: Option<u16>,
    force: bool,
) -> anyhow::Result<()> {
    let path = config_path(data_dir);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut out = std::io::stdout();

    if path.exists() && !force {
        let answer = ask(
            &mut input,
            &mut out,
            &format!("{} already exists. Replace it? [y/N]: ", path.display()),
        )?;
        if !matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Nothing changed.");
            return Ok(());
        }
    }

    let default_sqlite = data_dir.join("z8run.db");
    let answers = loop {
        let answers = match (&db_url, port) {
            (Some(url), port) => Answers {
                db_url: url.clone(),
                port: port.unwrap_or(7700),
            },
            (None, _) => prompt(&mut input, &mut out, &default_sqlite)?,
        };
        println!("Checking the database...");
        match verify(&answers.db_url).await {
            Ok(()) => break answers,
            // With flags there is nobody to re-ask.
            Err(e) if db_url.is_some() => return Err(e.context("database check failed")),
            Err(e) => println!("  Could not use that database: {e:#}\n  Let's try again.\n"),
        }
    };

    let written = write(data_dir, &answers)?;
    println!("Saved {}", written.display());
    println!(
        "Start z8run with `z8run` (or double-click it); the editor opens on port {}.",
        answers.port
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("z8-init-{}", rand::random::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Absolute on every platform ("/data/..." has no drive on Windows).
    fn default_file() -> PathBuf {
        std::env::temp_dir().join("z8run.db")
    }

    fn run_prompt(script: &str) -> (anyhow::Result<Answers>, String) {
        let mut input = std::io::Cursor::new(script.as_bytes().to_vec());
        let mut out = Vec::new();
        let result = prompt(&mut input, &mut out, &default_file());
        (result, String::from_utf8(out).unwrap())
    }

    #[test]
    fn enter_everywhere_picks_sqlite_defaults() {
        let (answers, _) = run_prompt("\n\n\n");
        assert_eq!(
            answers.unwrap(),
            Answers {
                db_url: sqlite_file_url(&default_file().display().to_string()),
                port: 7700
            }
        );
    }

    #[test]
    fn relative_sqlite_paths_are_made_absolute() {
        let (answers, _) = run_prompt("1\nmy.db\n\n");
        let expected = std::env::current_dir().unwrap().join("my.db");
        assert_eq!(
            answers.unwrap().db_url,
            sqlite_file_url(&expected.display().to_string())
        );
    }

    #[test]
    fn invalid_answers_are_asked_again() {
        let (answers, out) =
            run_prompt("x\n2\nmysql://nope\npostgres://u:p@db:5432/z8\n99999\n8080\n");
        assert_eq!(
            answers.unwrap(),
            Answers {
                db_url: "postgres://u:p@db:5432/z8".into(),
                port: 8080
            }
        );
        assert!(out.contains("'x' is not an option"));
        assert!(out.contains("must start with postgres://"));
        assert!(out.contains("'99999' is not a port number"));
    }

    #[test]
    fn closed_input_is_an_error_not_a_loop() {
        let (answers, _) = run_prompt("x\n");
        assert!(answers.unwrap_err().to_string().contains("--db-url"));
    }

    #[test]
    fn sqlite_paths_with_special_characters_round_trip() {
        use std::str::FromStr;
        let file = "C:\\Users\\ana#1\\z8 run\\100%?.db";
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str(&sqlite_file_url(file)).unwrap();
        assert_eq!(opts.get_filename(), Path::new(file));
    }

    #[test]
    fn written_file_reads_back_literally_and_privately() {
        let dir = scratch_dir();
        let answers = Answers {
            db_url: "postgres://u:p#w$HOME@db/z8".into(),
            port: 8080,
        };
        let path = write(&dir, &answers).unwrap();

        let values: Vec<(String, String)> = dotenvy::from_path_iter(&path)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let get = |k: &str| {
            values
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("Z8_DB_URL").unwrap(), "postgres://u:p#w$HOME@db/z8");
        assert_eq!(get("Z8_PORT").unwrap(), "8080");
        // PostgreSQL gets generated secrets.
        assert_eq!(get("Z8_JWT_SECRET").unwrap().len(), 64);
        assert_eq!(get("Z8_VAULT_SECRET").unwrap().len(), 64);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewriting_keeps_existing_secrets() {
        let dir = scratch_dir();
        let pg = Answers {
            db_url: "postgres://u:p@db/z8".into(),
            port: 7700,
        };
        write(&dir, &pg).unwrap();
        let before = kept_secrets(&config_path(&dir));
        assert_eq!(before.len(), 2);

        write(&dir, &pg).unwrap();
        assert_eq!(kept_secrets(&config_path(&dir)), before);

        // Switching to SQLite keeps them too: the vault stays readable.
        let sqlite = Answers {
            db_url: sqlite_file_url("/data/z8run.db"),
            port: 7700,
        };
        write(&dir, &sqlite).unwrap();
        assert_eq!(kept_secrets(&config_path(&dir)), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn quotes_are_refused_with_a_hint() {
        let err = render(&[("Z8_DB_URL", "postgres://u:it's@db/z8".into())]).unwrap_err();
        assert!(err.to_string().contains("%27"));
    }

    #[test]
    fn load_does_not_override_the_environment() {
        let dir = scratch_dir();
        // Names unique to this test: the process environment is shared.
        fs::write(
            config_path(&dir),
            "Z8_INIT_TEST_A='from-file'\nZ8_INIT_TEST_B='from-file'\n",
        )
        .unwrap();
        std::env::set_var("Z8_INIT_TEST_A", "from-env");

        assert!(load(&dir).unwrap());
        assert_eq!(std::env::var("Z8_INIT_TEST_A").unwrap(), "from-env");
        assert_eq!(std::env::var("Z8_INIT_TEST_B").unwrap(), "from-file");
        assert!(!load(&dir.join("missing")).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verify_creates_and_migrates_a_sqlite_file() {
        let dir = scratch_dir();
        // The parent folder does not exist yet.
        let file = dir.join("sub dir").join("z8run.db");
        verify(&sqlite_file_url(&file.display().to_string()))
            .await
            .unwrap();
        assert!(file.exists());

        // Fails fast with the real cause, not a pool timeout.
        let started = std::time::Instant::now();
        let bad = verify("postgres://u:p@127.0.0.1:1/z8").await.unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(!format!("{bad:#}").contains("timed out"), "{bad:#}");
        let _ = fs::remove_dir_all(&dir);
    }
}
