use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: Cargo executes this build script in its own process and this is
    // the first operation in `main`, before tonic/prost can create workers or
    // read the environment. The value is scoped to this build-script process.
    unsafe { std::env::set_var("PROTOC", protoc) };
    println!("cargo:rerun-if-changed=../proto/chirondb/v1/compat.proto");
    println!("cargo:rerun-if-changed=../proto/chirondb/v1/chirondb.proto");
    println!("cargo:rerun-if-changed=../proto/chirondb/v1/raft.proto");
    let descriptor_path = PathBuf::from(std::env::var("OUT_DIR")?).join("gaussdb_descriptor.bin");
    tonic_prost_build::configure()
        .file_descriptor_set_path(descriptor_path)
        .compile_protos(
            &[
                "../proto/chirondb/v1/compat.proto",
                "../proto/chirondb/v1/chirondb.proto",
            ],
            &["../proto"],
        )?;
    tonic_prost_build::configure()
        .compile_protos(&["../proto/chirondb/v1/raft.proto"], &["../proto"])?;
    Ok(())
}
