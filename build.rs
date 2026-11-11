fn main() {
    // No system protoc needed; a packaged build (Nix) provides its own via PROTOC.
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path().expect("no vendored protoc");

        // SAFETY: build scripts are single-threaded at this point.
        unsafe { std::env::set_var("PROTOC", protoc) };
    }

    connectrpc_build::Config::new()
        .files(&["proto/agentbox/v1/daemon.proto"])
        .includes(&["proto"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("generating code from proto");
}
