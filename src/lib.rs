//! Buildkite agents in single-use Firecracker microVMs, booted from OCI
//! images. The binary is both the host's tool and every guest's init.

pub mod cmd;
pub mod config;
pub mod elf;
pub mod firecracker;
pub mod guest;
pub mod host;
pub mod images;
pub mod initramfs;
pub mod layers;
pub mod log;
pub mod net;
pub mod protocol;
pub mod registry;
pub mod signals;
pub mod slot;
pub mod systemd;
pub mod tarball;
pub mod vm;
