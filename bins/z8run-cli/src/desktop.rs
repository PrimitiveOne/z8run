//! Desktop mode: what `z8run` does when started without a subcommand, e.g.
//! by double-clicking the binary (#78).
//!
//! Unlike `z8run serve`, it keeps data in the per-user data directory rather
//! than `./data` (the working directory of a double-clicked program is not a
//! meaningful place), listens on loopback only, and opens the editor in the
//! browser. A second launch while one is running just opens the browser.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Per-user data directory:
/// - Windows: `%APPDATA%\z8run`
/// - macOS: `~/Library/Application Support/z8run`
/// - Linux and others: `$XDG_DATA_HOME/z8run`, else `~/.local/share/z8run`
///
/// Falls back to `./data` when none of those variables are set.
pub fn default_data_dir() -> PathBuf {
    data_dir_from(|name| std::env::var_os(name).filter(|v| !v.is_empty()))
}

fn data_dir_from(env: impl Fn(&str) -> Option<std::ffi::OsString>) -> PathBuf {
    let base = if cfg!(windows) {
        env("APPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"))
    } else {
        env("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| env("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    };
    base.map(|b| b.join("z8run"))
        .unwrap_or_else(|| PathBuf::from("./data"))
}

/// Whether a z8run server already answers on `127.0.0.1:port`.
pub async fn is_running(port: u16) -> bool {
    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .ok()?;
        stream
            .write_all(b"GET /api/v1/health HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await
            .ok()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.ok()?;
        let text = String::from_utf8_lossy(&response);
        Some(text.starts_with("HTTP/1.") && text.contains("\"service\":\"z8run\""))
    };
    tokio::time::timeout(Duration::from_secs(2), probe)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

/// Opens `url` in the default browser. Failures are logged, not fatal: the
/// URL is also printed.
pub fn open_browser(url: &str) {
    let result = if cfg!(windows) {
        // `start` would treat a quoted first argument as a window title.
        std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .spawn()
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).spawn()
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, url, "Could not open the browser; open the URL manually");
    }
}

/// Whether the browser should be opened (`Z8_NO_BROWSER` unset or falsy).
pub fn browser_enabled() -> bool {
    !std::env::var("Z8_NO_BROWSER")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// A double-clicked console window closes as soon as the process exits,
/// taking the error message with it. Keep it open until the user reads it.
pub fn wait_before_exit() {
    if cfg!(windows) {
        eprintln!("\nPress Enter to close this window.");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn data_dir_is_per_user() {
        let dir = data_dir_from(env(&[
            ("APPDATA", "C:\\Users\\ana\\AppData\\Roaming"),
            ("HOME", "/home/ana"),
            ("XDG_DATA_HOME", "/data/xdg"),
        ]));
        let expected = if cfg!(windows) {
            PathBuf::from("C:\\Users\\ana\\AppData\\Roaming").join("z8run")
        } else if cfg!(target_os = "macos") {
            PathBuf::from("/home/ana/Library/Application Support/z8run")
        } else {
            PathBuf::from("/data/xdg/z8run")
        };
        assert_eq!(dir, expected);
        assert_eq!(data_dir_from(env(&[])), PathBuf::from("./data"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn linux_falls_back_to_local_share() {
        assert_eq!(
            data_dir_from(env(&[("HOME", "/home/ana")])),
            PathBuf::from("/home/ana/.local/share/z8run")
        );
    }

    /// Answers every connection on a random port with `response`.
    async fn serve(response: &'static str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(response.as_bytes()).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn detects_a_running_z8run_but_not_other_servers() {
        let z8 = serve(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n\
             {\"status\":\"ok\",\"service\":\"z8run\",\"version\":\"0.2.0\"}",
        )
        .await;
        assert!(is_running(z8).await);

        let other = serve("HTTP/1.1 200 OK\r\n\r\nhello").await;
        assert!(!is_running(other).await);

        // Nothing listening.
        let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        assert!(!is_running(port).await);
    }
}
