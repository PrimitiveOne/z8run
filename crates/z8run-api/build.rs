//! With the `embed-ui` feature, generates `$OUT_DIR/ui_assets.rs`: every file
//! of the built web UI (`frontend/dist`, or `Z8_UI_DIST`) as
//! `(path, include_bytes!(..))`, so the binary serves the editor on its own.

use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-env-changed=Z8_UI_DIST");
    if env::var_os("CARGO_FEATURE_EMBED_UI").is_none() {
        return;
    }

    let dist = env::var_os("Z8_UI_DIST")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../frontend/dist")
        });
    let dist = dist.canonicalize().unwrap_or_else(|_| {
        panic!(
            "embed-ui: web UI not found at {}. Build it first with \
             `npm --prefix frontend ci && npm --prefix frontend run build`, \
             or point Z8_UI_DIST at a built copy.",
            dist.display()
        )
    });
    if !dist.join("index.html").is_file() {
        panic!("embed-ui: {} has no index.html", dist.display());
    }

    let mut files = Vec::new();
    collect(&dist, &dist, &mut files);
    files.sort();

    let mut out = String::from("pub static ASSETS: &[(&str, &[u8])] = &[\n");
    for (rel, abs) in &files {
        println!("cargo:rerun-if-changed={}", abs.display());
        // `{:?}` yields valid Rust string literals, escapes included.
        out.push_str(&format!(
            "    ({rel:?}, include_bytes!({:?})),\n",
            abs.display().to_string()
        ));
    }
    out.push_str("];\n");
    println!("cargo:rerun-if-changed={}", dist.display());

    let dest = Path::new(&env::var("OUT_DIR").unwrap()).join("ui_assets.rs");
    fs::write(dest, out).unwrap();
}

/// Files under `dir`, as (path relative to `root` with `/` separators, absolute path).
fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            println!("cargo:rerun-if-changed={}", path.display());
            collect(root, &path, files);
        } else {
            let rel = path.strip_prefix(root).unwrap();
            let rel = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            files.push((rel, path));
        }
    }
}
