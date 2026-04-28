// build.rs — expose the compilation target triple to the crate via env!("TARGET").
//
// Cargo sets the TARGET environment variable during build scripts.
// Re-emitting it as a cargo:rustc-env value makes it available to
// source code via env!("TARGET") — used by the runtime loader to
// validate plugin target triples against the host.
fn main() {
    let target = std::env::var("TARGET").expect("Cargo always sets TARGET in build scripts");
    println!("cargo:rustc-env=TARGET={}", target);
    // Re-run only if nothing changes (TARGET is stable per build).
    println!("cargo:rerun-if-changed=build.rs");
}
