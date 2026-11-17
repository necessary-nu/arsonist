//! A boot's Firecracker config and kernel command line.

use std::net::Ipv4Addr;

use serde_json::{Value, json};

use crate::config::{IoEngine, Pool};
use crate::net::SlotAddress;

/// Paths as the jailed Firecracker sees them, inside its chroot.
pub mod jail {
    pub const KERNEL: &str = "vmlinux";
    pub const INITRD: &str = "initrd.cpio";
    pub const ROOTFS: &str = "rootfs.erofs";
    pub const SCRATCH: &str = "scratch.ext4";
    pub const CACHE: &str = "cache.ext4";
    pub const VM_CONFIG: &str = "vm.json";
    pub const API_SOCKET: &str = "firecracker.socket";
}

const HOSTNAME_MAX: usize = 63;

/// `<host>-<slot>`, which is also the agent's name in Buildkite.
pub fn guest_hostname(host: &str, slot: &str) -> String {
    let host: String = host
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let room = HOSTNAME_MAX.saturating_sub(slot.len() + 1);
    let host = host[..host.len().min(room)].trim_end_matches('-');
    format!("{host}-{slot}")
}

pub fn boot_args(addr: &SlotAddress, hostname: &str, dns: &[Ipv4Addr], extra: &str) -> String {
    let dns0 = dns.first().map(|d| d.to_string()).unwrap_or_default();
    let dns1 = dns.get(1).map(|d| d.to_string()).unwrap_or_default();
    let ip = format!(
        "ip={}::{}:{}:{hostname}:eth0:off:{dns0}:{dns1}",
        addr.guest_ip, addr.host_ip, addr.netmask
    );
    [
        "console=ttyS0",
        "reboot=k",
        "panic=1",
        "pci=off",
        // SendCtrlAltDel arrives through the i8042, which the guest must find
        // from its ACPI description: probed for by hand (i8042.nopnp), its
        // interrupt is never mapped. These skip what Firecracker's minimal
        // controller cannot answer.
        "i8042.noaux",
        "i8042.nomux",
        "i8042.dumbkbd",
        &ip,
        extra,
    ]
    .into_iter()
    .filter(|a| !a.is_empty())
    .collect::<Vec<_>>()
    .join(" ")
}

pub fn firecracker_config(pool: &Pool, addr: &SlotAddress, boot_args: &str) -> Value {
    let writable = |id: &str, path: &str, cache_type: &str| {
        let mut drive = json!({
            "drive_id": id,
            "path_on_host": format!("/{path}"),
            "is_root_device": false,
            "is_read_only": false,
            "cache_type": cache_type,
            "io_engine": match pool.io_engine { IoEngine::Sync => "Sync", IoEngine::Async => "Async" },
        });
        // Firecracker passes discards through on the Sync engine only.
        if pool.io_engine == IoEngine::Sync {
            drive["discard"] = json!(true);
        }
        drive
    };
    json!({
        "boot-source": {
            "kernel_image_path": format!("/{}", jail::KERNEL),
            "initrd_path": format!("/{}", jail::INITRD),
            "boot_args": boot_args,
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": format!("/{}", jail::ROOTFS),
                "is_root_device": false,
                "is_read_only": true,
            },
            // Thrown away after the boot, so flushes can be skipped.
            writable("scratch", jail::SCRATCH, "Unsafe"),
            writable("cache", jail::CACHE, "Writeback"),
        ],
        "machine-config": {
            "vcpu_count": pool.vcpus(),
            "mem_size_mib": pool.memory_mib(),
            "smt": false,
        },
        "network-interfaces": [{
            "iface_id": "eth0",
            "host_dev_name": addr.tap,
            "guest_mac": addr.guest_mac,
        }],
        "entropy": {},
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::config::Config;

    fn config() -> Config {
        Config::parse(
            r#"
[pools.linux]
image = "ghcr.io/divvun/divvun-actions:ubuntu-latest"
count = 4
memory = "24G"
tags = ["queue=linux"]
"#,
            Path::new("c.toml"),
            16,
        )
        .unwrap()
    }

    #[test]
    fn guest_hostnames_are_one_valid_label() {
        assert_eq!(
            guest_hostname("Build01.uit.no", "linux-2"),
            "build01-linux-2"
        );
        assert_eq!(guest_hostname("my_host", "linux-2"), "my-host-linux-2");
        let long = guest_hostname(&"x".repeat(80), "linux-large-12");
        assert_eq!(long.len(), 63);
        assert!(long.ends_with("-linux-large-12"));
    }

    #[test]
    fn the_kernel_configures_the_network_itself() {
        let addr = config().network.subnet.slot(1).unwrap();
        let args = boot_args(
            &addr,
            "build01-linux-2",
            &["192.168.1.1".parse().unwrap(), "1.1.1.1".parse().unwrap()],
            "quiet",
        );
        assert!(args.contains(
            "ip=172.30.0.6::172.30.0.5:255.255.255.252:build01-linux-2:eth0:off:192.168.1.1:1.1.1.1"
        ));
        assert!(args.starts_with("console=ttyS0 reboot=k panic=1 "));
        assert!(
            !args.contains("i8042.nopnp"),
            "the i8042 is found through ACPI"
        );
        assert!(args.ends_with(" quiet"));
        assert!(!args.contains("init="), "the initramfs's /init is the init");
    }

    #[test]
    fn the_vm_boots_the_initramfs_with_the_image_read_only() {
        let c = config();
        let addr = c.network.subnet.slot(1).unwrap();
        let vm = firecracker_config(&c.pools["linux"], &addr, "console=ttyS0");
        assert_eq!(vm["boot-source"]["initrd_path"], "/initrd.cpio");
        let drives: Vec<_> = vm["drives"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d["drive_id"].as_str().unwrap(),
                    d["is_read_only"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            drives,
            [("rootfs", true), ("scratch", false), ("cache", false)]
        );
        assert!(
            vm["drives"]
                .as_array()
                .unwrap()
                .iter()
                .all(|d| d["is_root_device"] == false)
        );
        assert_eq!(vm["drives"][1]["discard"], true);
        assert_eq!(vm["drives"][2]["cache_type"], "Writeback");
        assert_eq!(
            vm["machine-config"],
            json!({ "vcpu_count": 16, "mem_size_mib": 24 * 1024, "smt": false })
        );
        assert_eq!(vm["network-interfaces"][0]["host_dev_name"], "arsonist1");
    }

    #[test]
    fn discard_is_only_asked_of_the_sync_engine() {
        let mut c = config();
        c.pools["linux"].io_engine = IoEngine::Async;
        let addr = c.network.subnet.slot(0).unwrap();
        let vm = firecracker_config(&c.pools["linux"], &addr, "");
        assert!(vm["drives"][1].get("discard").is_none());
        assert_eq!(vm["drives"][1]["io_engine"], "Async");
    }
}
