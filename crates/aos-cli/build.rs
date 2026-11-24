//! Compile `proto/forkloom/v1/runtime.proto` client stubs for `aos-cli`.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join("../../proto");
    let proto_file = proto_root.join("forkloom/v1/runtime.proto");

    println!("cargo:rerun-if-changed={}", proto_file.display());
    println!("cargo:rerun-if-env-changed=PROTOC");

    if std::env::var_os("PROTOC").is_none() {
        let vendored = protoc_bin_vendored::protoc_bin_path()?;
        // SAFETY: build script runs single-threaded before spawning tonic_build.
        unsafe {
            std::env::set_var("PROTOC", vendored);
        }
    }

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&[proto_file], &[proto_root])?;
    Ok(())
}
