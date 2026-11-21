#[path = "build/engines.rs"]
mod engines;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/aidbg.proto");
    let mut cfg = prost_build::Config::new();
    cfg.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure().compile_with_config(cfg, &["proto/aidbg.proto"], &["proto"])?;
    engines::build()?;
    Ok(())
}
