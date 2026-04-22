//! Build script — triggers frontend build before cargo compile.
//!
//! Ensures static/assets/app.js and app.css are up-to-date when
//! any frontend source file changes. Skips if npm is not available
//! (CI without Node.js, or users who don't modify the frontend).

use std::path::Path;
use std::process::Command;

fn main() {
    let frontend_dir = Path::new("frontend");

    // Only rebuild if frontend directory exists and has source files
    if !frontend_dir.join("src").exists() {
        return;
    }

    // Rerun if any frontend source changes
    println!("cargo:rerun-if-changed=frontend/src");
    println!("cargo:rerun-if-changed=frontend/package.json");
    println!("cargo:rerun-if-changed=frontend/esbuild.config.mjs");

    // Check if node_modules exists (npm install was run)
    if !frontend_dir.join("node_modules").exists() {
        println!("cargo:warning=Frontend node_modules missing. Run: cd crates/sigint-web/frontend && npm install");
        return;
    }

    // Run npm build
    let status = Command::new("npm")
        .args(["run", "build"])
        .current_dir(frontend_dir)
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            println!("cargo:warning=Frontend build failed with exit code: {}", s);
        }
        Err(e) => {
            println!(
                "cargo:warning=npm not found or frontend build failed: {}. Web UI may be stale.",
                e
            );
        }
    }
}
