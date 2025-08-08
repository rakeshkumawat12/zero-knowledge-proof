fn main() {
    tonic_build::configure()
        .build_server(true)
        .out_dir("src/") 
        .compile_protos(
            &["proto/zkp_auth.proto"],
            &["proto/"], // root for imports
        )
        .unwrap();
}