//! Private native host components. These modules confer no public source FFI
//! and do not register or certify a compiler target.
#[cfg(feature = "native-host")]
pub mod native_artifact_channel;
#[cfg(feature = "native-host")]
pub mod native_target;
#[cfg(feature = "native-host")]
pub mod cross_elf;
#[cfg(feature = "native-host")]
pub mod native_resources;
#[cfg(feature = "installed-native")]
#[path = "installed_cli.rs"]
pub mod installed_cli;
#[cfg(feature = "installed-native")]
pub mod installed_request;
#[cfg(feature = "installed-native")]
pub mod distribution_archive;
#[cfg(feature = "installed-native")]
pub mod component_store;
#[cfg(feature = "installed-native")]
pub mod workspace_store;
#[cfg(feature = "native-host")]
pub mod filesystem_channel;
#[cfg(feature = "native-host")]
pub mod host_channel;
#[cfg(feature = "native-host")]
pub mod engine_channel;
#[cfg(feature = "native-host")]
pub mod engine_profiles;
#[cfg(all(feature = "wasi", feature = "native-host"))]
pub mod broker_wasi;
#[cfg(feature = "macos-host")]
pub mod macos_seatbelt;
#[cfg(feature = "macos-host")]
pub mod macos_format;
#[cfg(feature = "macos-host")]
pub mod macos_linked_image;
#[cfg(all(feature = "macos-host", target_os = "macos"))]
pub mod macos_task;
#[cfg(all(feature = "macos-host", target_os = "macos"))]
pub mod macos_process;
#[cfg(all(feature = "macos-host", target_os = "macos"))]
pub mod macos_snapshot;
#[cfg(all(feature = "macos-host", target_os = "macos"))]
pub mod macos_supervisor;
#[cfg(all(feature = "macos-host", target_os = "macos"))]
pub mod macos_filesystem_session;
#[cfg(all(feature = "macos-host", target_os = "macos"))]
pub mod macos_host;
#[cfg(all(feature = "macos-host", target_os = "macos"))]
pub mod macos_artifact;
#[cfg(all(feature = "macos-host", target_os = "macos"))]
pub mod macos_linker;
#[cfg(all(feature = "macos-host", target_os = "macos"))]
pub mod macos_engine;
#[cfg(all(feature = "native-host", unix))]
pub mod unix_filesystem;
#[cfg(all(feature = "native-host", unix))]
pub mod unix_host;
#[cfg(all(feature = "installed-native", unix))]
pub mod unix_installed_host;
#[cfg(feature = "windows-host")]
pub mod windows_process;
#[cfg(all(feature = "windows-host", target_os = "windows"))]
pub mod windows_filesystem;
#[cfg(all(feature = "windows-host", target_os = "windows"))]
pub mod windows_filesystem_session;
#[cfg(all(feature = "windows-host", target_os = "windows"))]
pub mod windows_host;
#[cfg(all(feature = "windows-host", target_os = "windows"))]
pub mod windows_snapshot;
#[cfg(all(feature = "windows-host", target_os = "windows"))]
pub mod windows_supervisor;
#[cfg(all(feature = "windows-host", target_os = "windows"))]
pub mod windows_lifeline;
#[cfg(all(feature = "windows-host", target_os = "windows"))]
pub mod windows_engine;
#[cfg(all(feature = "windows-host", target_os = "windows"))]
pub mod windows_artifact;
#[cfg(all(feature = "windows-host", target_os = "windows"))]
pub mod windows_linker;
#[cfg(all(feature = "windows-host", target_os = "windows"))]
pub mod windows_cross_linker;
#[cfg(all(feature = "windows-host", target_os = "windows"))]
pub mod windows_network_probe;
