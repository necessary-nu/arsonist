//! Host commands that are not the slot loop: setup, status, registry login.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::cmd::Cmd;
use crate::config::{Config, DEFAULT_CONFIG_PATH};
use crate::registry::{Credential, Credentials};
use crate::slot::{cache_paths, ext4_usage};
use crate::{firecracker, images, info, systemd, warn};

const BIN_DIR: &str = "/usr/local/bin";
const APT_PACKAGES: &[&str] = &["e2fsprogs", "erofs-utils", "iproute2", "nftables"];
const EXAMPLE_CONFIG: &str = include_str!("../config.example.toml");

/// Install what a host needs, and an example config if there is none.
pub fn setup(config_path: &Path) -> Result<()> {
    if std::env::consts::OS != "linux" || std::env::consts::ARCH != "x86_64" {
        bail!("arsonist hosts are x86_64 Linux");
    }
    if !Path::new("/dev/kvm").exists() {
        bail!(
            "/dev/kvm is missing: enable virtualisation in the firmware, or nested virtualisation on the hypervisor"
        );
    }
    if Cmd::new("apt-get").arg("--version").succeeds() {
        Cmd::new("apt-get").arg("update").run()?;
        Cmd::new("apt-get")
            .args(["install", "-y"])
            .args(APT_PACKAGES)
            .run()?;
        info!("installed {}", APT_PACKAGES.join(", "));
    } else {
        warn!(
            "no apt-get; install these yourself: {}",
            APT_PACKAGES.join(", ")
        );
    }
    firecracker::install(Path::new(BIN_DIR))?;

    let dir = config_path.parent().unwrap_or(Path::new("/"));
    fs::create_dir_all(dir)?;
    if config_path == Path::new(DEFAULT_CONFIG_PATH) {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    if !config_path.exists() {
        fs::write(config_path, EXAMPLE_CONFIG)?;
        info!(
            "wrote {} from the example. Edit it, put the agent token in the token_file, log in to the registries with `arsonist auth login`, then run `arsonist install`.",
            config_path.display()
        );
    }
    Ok(())
}

fn unit_state(slot: &str) -> String {
    Cmd::new("systemctl")
        .args(["is-active", &systemd::slot_unit(slot)])
        .ok_codes(&[1, 3, 4])
        .run()
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

pub fn status(config: &Config) -> Result<()> {
    let kernel = images::current_version(&images::kernel_dir(config))?;
    println!(
        "kernel  {}",
        kernel.map_or_else(
            || format!("{}, not converted yet", config.kernel.image),
            |k| k.meta.image
        )
    );
    for pool in config.pools.values() {
        let image = images::current_version(&images::image_dir(config, &pool.image))?;
        println!(
            "pool    {}: {} x {} vCPU, {} GiB, tags {}",
            pool.name,
            pool.count,
            pool.vcpus(),
            pool.memory_mib() / 1024,
            pool.tags.join(",")
        );
        println!(
            "        image {}",
            image.map_or_else(
                || format!("{}, not converted yet", pool.image),
                |i| i.meta.image
            )
        );
    }
    println!();
    for slot in &config.slots {
        let disk = cache_paths(config, slot).disk;
        let cache = if disk.exists() {
            match ext4_usage(&disk) {
                Ok((used, total)) => format!("{}/{} GiB used", used >> 30, total >> 30),
                Err(_) => "unreadable".into(),
            }
        } else {
            "none yet".into()
        };
        println!(
            "{:<24} {:<12} cache {cache}",
            slot.name,
            unit_state(&slot.name)
        );
    }
    Ok(())
}

/// Store a registry password, read from stdin, in the auth file.
pub fn login(auth_file: &Path, registry: &str, username: &str) -> Result<()> {
    let mut password = String::new();
    std::io::stdin().read_to_string(&mut password)?;
    let password = password.trim_end_matches(['\n', '\r']);
    if password.is_empty() {
        bail!("give the password or token on stdin");
    }
    let mut creds = Credentials::load(auth_file)?;
    creds.set(
        registry,
        Credential {
            username: username.into(),
            password: password.into(),
        },
    );
    if let Some(dir) = auth_file.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = auth_file.with_extension("json.new");
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("{}", tmp.display()))?;
    std::io::Write::write_all(&mut out, creds.to_docker_config().as_bytes())?;
    drop(out);
    fs::rename(&tmp, auth_file)?;
    info!(
        "saved credentials for {registry} in {}",
        auth_file.display()
    );
    Ok(())
}
