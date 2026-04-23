use std::path::PathBuf;
use std::process::Command;

fn build_default_init() -> PathBuf {
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is always set by cargo"),
    );
    let libkrun_root = manifest_dir.join("../..");
    let init_manifest = libkrun_root.join("init/Cargo.toml");

    println!("cargo:rerun-if-env-changed=KRUN_INIT_TARGET");
    println!(
        "cargo:rerun-if-changed={}",
        libkrun_root.join("init/src").display()
    );
    println!("cargo:rerun-if-changed={}", init_manifest.display());

    // Use the same `cargo` binary that is building libkrun so we stay on the
    // same toolchain and pick up any rustup overrides.
    let cargo = std::env::var_os("CARGO").expect("CARGO is always set by cargo");

    // The target for the init binary.  Defaults to the host target so we
    // always use a toolchain that is available.  Override with
    // KRUN_INIT_TARGET=x86_64-unknown-linux-musl (or similar) when the musl
    // std is installed in the active toolchain.
    let target = std::env::var("KRUN_INIT_TARGET").unwrap_or_else(|_| {
        std::env::var("HOST").unwrap_or_else(|_| "x86_64-unknown-linux-gnu".to_string())
    });

    // The outer `cargo build` holds a lock on the workspace target directory.
    // Give the inner build its own target dir to avoid a deadlock.
    let init_target_dir = libkrun_root.join("init/target");

    // Append our flag to any caller-supplied RUSTFLAGS rather than replacing
    // them, so that things like custom linkers or sanitizer flags are preserved.
    let rustflags = {
        let existing = std::env::var("RUSTFLAGS").unwrap_or_default();
        if existing.is_empty() {
            "-C target-feature=+crt-static".to_string()
        } else {
            format!("{existing} -C target-feature=+crt-static")
        }
    };

    // Mirror any features that must be forwarded to the init crate.
    // CARGO_FEATURE_<NAME> is set by Cargo when a feature is active on this crate.
    let mut init_features: Vec<&str> = Vec::new();
    if std::env::var_os("CARGO_FEATURE_TIMESYNC").is_some() {
        init_features.push("timesync");
    }

    let mut cmd = Command::new(&cargo);
    cmd.args(["build", "--release", "--manifest-path"])
        .arg(&init_manifest)
        .args(["--target", &target])
        .arg("--target-dir")
        .arg(&init_target_dir)
        .env("RUSTFLAGS", rustflags);

    if !init_features.is_empty() {
        cmd.args(["--features", &init_features.join(",")]);
    }

    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke cargo for init crate: {e}"));

    if !status.success() {
        panic!("failed to build init crate (target={target})");
    }

    init_target_dir.join(&target).join("release/init")
}

fn main() {
    println!("cargo:rerun-if-env-changed=KRUN_INIT_BINARY_PATH");
    println!("cargo:rerun-if-env-changed=KRUN_INIT_TARGET");

    let init_binary_path = std::env::var_os("KRUN_INIT_BINARY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(build_default_init);

    println!(
        "cargo:rustc-env=KRUN_INIT_BINARY_PATH={}",
        init_binary_path.display()
    );
}
