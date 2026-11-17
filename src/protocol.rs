//! What the host tells a guest: written into each boot's initramfs by the
//! host, read by the same binary running as the guest's init. Both ends are
//! always one build, so this needs no versioning.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Where the initramfs holds the config and the shared files.
pub const INITRAMFS_DIR: &str = "arsonist";
pub const INITRAMFS_CONFIG: &str = "arsonist/config.json";

/// The ext4 labels the guest finds its writable drives by. The image is the
/// one erofs drive. Labels rather than /dev/vdX, so nothing depends on the
/// order Firecracker attaches drives in.
pub const SCRATCH_LABEL: &str = "arsonist-scratch";
pub const CACHE_LABEL: &str = "arsonist-cache";

/// Where the guest leaves [`VmInfo`] for jobs to read.
pub const VM_INFO_PATH: &str = "/run/arsonist/vm.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuestConfig {
    pub hostname: String,
    pub dns: Vec<Ipv4Addr>,
    /// In order; a later entry overrides an earlier one with the same name.
    pub env: Vec<(String, String)>,
    /// The agent's whole argv.
    pub agent: Vec<String>,
    /// Guest paths bound from the cache disk.
    pub cache_paths: Vec<String>,
    /// File `i` is at `arsonist/files/<i>` in the initramfs.
    pub files: Vec<String>,
    /// Mount the scratch and cache disks with `discard`.
    pub discard: bool,
    pub info: VmInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmInfo {
    pub slot: String,
    pub host: String,
    /// The pinned image ref the root filesystem is.
    pub image: String,
    pub kernel: String,
    pub arsonist: String,
}

/// `/a/b` → `a/b`, the place a guest path's data lives on the cache disk.
pub fn cache_subdir(guest_path: &str) -> &str {
    guest_path.trim_start_matches('/')
}
