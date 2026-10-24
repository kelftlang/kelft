fn main() {
    println!("cargo:rustc-check-cfg=cfg(kelft_rebuild)");
    println!("cargo:rerun-if-env-changed=KELFT_REBUILD_POLICY");
    if let Some(path)=std::env::var_os("KELFT_REBUILD_POLICY") {
        println!("cargo:rerun-if-changed={}",std::path::Path::new(&path).display());
        println!("cargo:rustc-cfg=kelft_rebuild");
    }
    println!("cargo:rustc-check-cfg=cfg(kelft_development_windows_system_inputs)");
    println!("cargo:rerun-if-env-changed=KELFT_DEVELOPMENT_WINDOWS_SYSTEM_INPUTS");
    if let Ok(value)=std::env::var("KELFT_DEVELOPMENT_WINDOWS_SYSTEM_INPUTS") {
        assert!(value=="1" && std::env::var("CARGO_CFG_TARGET_OS").as_deref()==Ok("windows") && std::env::var_os("KELFT_TESTING_POLICY").is_some(),"host System32 binding is restricted to explicit Windows development testing builds");
        println!("cargo:rustc-cfg=kelft_development_windows_system_inputs");
    }
    println!("cargo:rustc-check-cfg=cfg(kelft_testing)");
    println!("cargo:rerun-if-env-changed=KELFT_TESTING_POLICY");
    if let Some(path)=std::env::var_os("KELFT_TESTING_POLICY") {
        println!("cargo:rerun-if-changed={}",std::path::Path::new(&path).display());
        println!("cargo:rustc-cfg=kelft_testing");
    }
    println!("cargo:rustc-check-cfg=cfg(kelft_target_components)");
    println!("cargo:rustc-check-cfg=cfg(kelft_workspace)");
    println!("cargo:rerun-if-env-changed=KELFT_WORKSPACE_POLICY");
    if let Some(path) = std::env::var_os("KELFT_WORKSPACE_POLICY") {
        assert!(matches!(std::env::var("CARGO_CFG_TARGET_OS").as_deref(),Ok("linux"|"windows")) && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref()==Ok("x86_64"),"workspace policy is currently supported only on Linux/Windows x64");
        println!("cargo:rerun-if-changed={}", std::path::Path::new(&path).display());
        println!("cargo:rustc-cfg=kelft_workspace");
    }
    for name in ["KELFT_TARGET_CATALOG", "KELFT_COMPONENT_POLICY"] {
        println!("cargo:rerun-if-env-changed={name}");
        if let Some(path) = std::env::var_os(name) {println!("cargo:rerun-if-changed={}",std::path::Path::new(&path).display());}
    }
    if std::env::var_os("KELFT_TARGET_CATALOG").is_some() {
        assert!(std::env::var_os("KELFT_COMPONENT_POLICY").is_some(),"component policy image required");
        println!("cargo:rustc-cfg=kelft_target_components");
    }
    let compiler = std::env::var_os("RUSTC").expect("RUSTC is required");
    let result = std::process::Command::new(compiler)
        .arg("--version")
        .output()
        .expect("rustc version unavailable");
    let version = String::from_utf8(result.stdout).expect("rustc identity must be UTF-8");
    assert!(
        result.status.success() && version.starts_with("rustc 1.99.0 "),
        "Kelft's driver requires pinned Rust 1.99.0"
    );
    println!("cargo:rustc-env=KELFT_RUSTC_VERSION={}", version.trim());
    println!("cargo:rerun-if-changed=build.rs");
}
