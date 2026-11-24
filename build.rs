#[path = "build/engines.rs"]
#[cfg(unix)]
mod engines;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=AIDBG_BUILD_REVISION");
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--git-path", "HEAD"])
        .output()
        && output.status.success()
    {
        println!(
            "cargo:rerun-if-changed={}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    if let Ok(output) = std::process::Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .output()
        && output.status.success()
    {
        let reference = String::from_utf8_lossy(&output.stdout);
        if let Ok(path) = std::process::Command::new("git")
            .args(["rev-parse", "--git-path", reference.trim()])
            .output()
            && path.status.success()
        {
            println!(
                "cargo:rerun-if-changed={}",
                String::from_utf8_lossy(&path.stdout).trim()
            );
        }
    }
    let revision = std::env::var("AIDBG_BUILD_REVISION").ok().or_else(|| {
        let output = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    });
    let version = std::env::var("CARGO_PKG_VERSION")?;
    if let Some(revision) =
        revision.filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        println!("cargo:rustc-env=AIDBG_BUILD_REVISION={revision}");
        println!("cargo:rustc-env=AIDBG_BUILD_VERSION={version}+{revision}");
    } else {
        println!("cargo:rustc-env=AIDBG_BUILD_VERSION={version}");
    }
    println!("cargo:rerun-if-changed=proto/aidbg.proto");
    println!("cargo:rerun-if-changed=proto/backend.proto");
    let mut cfg = prost_build::Config::new();
    cfg.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure().compile_with_config(
        cfg,
        &["proto/aidbg.proto", "proto/backend.proto"],
        &["proto"],
    )?;
    #[cfg(unix)]
    if std::env::var("CARGO_CFG_TARGET_OS")?.as_str() == "linux" {
        engines::build()?;
    }
    Ok(())
}
