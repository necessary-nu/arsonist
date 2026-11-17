//! Turning the kernel image and the pools' images into what Firecracker
//! boots, once per digest. Each lives in a directory named by its digest,
//! and an atomically replaced `current` symlink says which one slots boot.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::cmd::Cmd;
use crate::config::Config;
use crate::layers;
use crate::registry::{self, Client, Credentials, Reference, Resolved};
use crate::{error, info};

/// The current version and the one before it.
const VERSIONS_KEPT: usize = 2;
const META: &str = "image.json";
pub const KERNEL_FILE: &str = "vmlinux";
pub const ROOTFS_FILE: &str = "rootfs.erofs";
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    /// `registry/repository@sha256:…`
    pub image: String,
    /// The image config's `Env`, which Docker would have set.
    #[serde(default)]
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct Version {
    pub dir: PathBuf,
    pub meta: Meta,
}

pub fn kernel_dir(config: &Config) -> PathBuf {
    config.state_dir.join("kernel")
}

/// One directory per configured ref, tag included, digest left out.
pub fn image_dir(config: &Config, image: &str) -> PathBuf {
    let without_digest = image.split('@').next().unwrap_or(image);
    let name: String = without_digest
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    config.state_dir.join("images").join(name)
}

pub fn current_version(dir: &Path) -> Result<Option<Version>> {
    let target = match fs::read_link(dir.join("current")) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("{}/current", dir.display())),
    };
    let version_dir = dir.join(target);
    let meta_path = version_dir.join(META);
    let meta = serde_json::from_slice(
        &fs::read(&meta_path).with_context(|| format!("{}", meta_path.display()))?,
    )
    .with_context(|| format!("{}", meta_path.display()))?;
    Ok(Some(Version {
        dir: version_dir,
        meta,
    }))
}

fn set_current(dir: &Path, name: &str) -> Result<()> {
    let next = dir.join("current.next");
    let _ = fs::remove_file(&next);
    std::os::unix::fs::symlink(name, &next)?;
    fs::rename(&next, dir.join("current"))?;
    Ok(())
}

/// A running VM holds hard links to its files in its jail, so removing the
/// version it booted from does not pull the disk out from under it.
fn prune(dir: &Path) -> Result<()> {
    let current = fs::read_link(dir.join("current"))?;
    let mut versions: Vec<(SystemTime, String)> = vec![];
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".partial") {
            fs::remove_dir_all(entry.path())?;
            continue;
        }
        versions.push((entry.metadata()?.modified()?, name));
    }
    versions.sort_by_key(|v| std::cmp::Reverse(v.0));
    let mut keep = vec![current.to_string_lossy().into_owned()];
    for (_, name) in &versions {
        if keep.len() >= VERSIONS_KEPT {
            break;
        }
        if !keep.contains(name) {
            keep.push(name.clone());
        }
    }
    for (_, name) in versions {
        if !keep.contains(&name) {
            info!("removing {}", dir.join(&name).display());
            fs::remove_dir_all(dir.join(&name))?;
        }
    }
    Ok(())
}

type Build<'a> = &'a mut dyn FnMut(&mut Client, &Reference, &Resolved, &Path) -> Result<Meta>;

/// Point `dir/current` at the conversion of the digest `image` resolves to,
/// converting it first if it is new. Returns whether `current` moved.
fn update(client: &mut Client, dir: &Path, image: &str, build: Build) -> Result<bool> {
    let reference = Reference::parse(image)?;
    let resolved = client.resolve(&reference)?;
    let hex = &resolved.digest["sha256:".len()..];
    let version_dir = dir.join(hex);
    if let Some(current) = current_version(dir)?
        && current.dir == version_dir
    {
        return Ok(false);
    }

    fs::create_dir_all(dir)?;
    if !version_dir.join(META).exists() {
        let partial = dir.join(format!("{hex}.partial"));
        let _ = fs::remove_dir_all(&partial);
        fs::create_dir_all(&partial)?;
        let pinned = reference.pinned(&resolved.digest);
        info!("converting {pinned}");
        let started = Instant::now();
        let meta = build(client, &reference, &resolved, &partial)?;
        fs::write(partial.join(META), serde_json::to_vec_pretty(&meta)?)?;
        fs::rename(&partial, &version_dir)?;
        info!("converted {pinned} in {}s", started.elapsed().as_secs());
    }
    set_current(dir, hex)?;
    info!("{}: current is now {}", dir.display(), resolved.digest);
    prune(dir)?;
    Ok(true)
}

/// Download every layer into `dir/blobs`, base layer first.
fn download_layers(
    client: &mut Client,
    r: &Reference,
    resolved: &Resolved,
    dir: &Path,
) -> Result<Vec<PathBuf>> {
    let blobs = dir.join("blobs");
    fs::create_dir_all(&blobs)?;
    let total: u64 = resolved.manifest.layers.iter().map(|l| l.size).sum();
    info!(
        "downloading {} layers, {} MiB",
        resolved.manifest.layers.len(),
        total >> 20
    );
    let mut paths = vec![];
    for (i, layer) in resolved.manifest.layers.iter().enumerate() {
        let path = blobs.join(i.to_string());
        client.blob_to_file(r, layer, &path)?;
        paths.push(path);
    }
    Ok(paths)
}

fn check_platform(r: &Reference, config: &registry::ImageConfig) -> Result<()> {
    let ok = |field: &str, want: &str| field.is_empty() || field == want;
    if !ok(&config.os, registry::OS) || !ok(&config.architecture, registry::ARCHITECTURE) {
        bail!(
            "{r} is {}/{}, not {}/{}",
            config.os,
            config.architecture,
            registry::OS,
            registry::ARCHITECTURE
        );
    }
    Ok(())
}

pub fn parse_env(entries: &[String]) -> Vec<(String, String)> {
    entries
        .iter()
        .filter_map(|e| e.split_once('='))
        .filter(|(k, _)| !k.is_empty())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn build_kernel(
    client: &mut Client,
    r: &Reference,
    resolved: &Resolved,
    dir: &Path,
) -> Result<Meta> {
    let blobs = download_layers(client, r, resolved, dir)?;
    let plan = layers::plan(&blobs)?;
    let dest = dir.join(KERNEL_FILE);
    let mut out = BufWriter::new(File::create(&dest)?);
    if !layers::extract(&blobs, &plan, KERNEL_FILE, &mut out)? {
        bail!("{r} has no /{KERNEL_FILE}");
    }
    out.flush()?;
    drop(out);
    fs::remove_dir_all(dir.join("blobs"))?;
    let mut magic = [0u8; 4];
    std::io::Read::read_exact(&mut File::open(&dest)?, &mut magic)?;
    if magic != *b"\x7fELF" {
        bail!("{r}: /{KERNEL_FILE} is not an uncompressed ELF kernel");
    }
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o644))?;
    Ok(Meta {
        image: r.pinned(&resolved.digest),
        env: vec![],
    })
}

/// Stream the flattened layers through `mkfs.erofs --tar`.
pub fn make_erofs(
    blobs: &[PathBuf],
    plan: &layers::Plan,
    dest: &Path,
    compression: &str,
) -> Result<()> {
    let mut cmd = Command::new("mkfs.erofs");
    cmd.arg("--tar=f").arg("--quiet");
    if compression != "none" {
        cmd.arg(format!("-z{compression}"));
    }
    cmd.arg(dest)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = cmd
        .spawn()
        .context("could not run mkfs.erofs (erofs-utils)")?;
    let stdin = child.stdin.take().expect("stdin is piped");
    let written = layers::write_tar(blobs, plan, BufWriter::with_capacity(1 << 20, stdin));
    let status = child.wait()?;
    if !status.success() {
        bail!("mkfs.erofs exited with {status}");
    }
    written?;
    Ok(())
}

fn build_image(
    client: &mut Client,
    r: &Reference,
    resolved: &Resolved,
    dir: &Path,
    compression: &str,
) -> Result<Meta> {
    let image_config = client.image_config(r, &resolved.manifest)?;
    check_platform(r, &image_config)?;
    let env = parse_env(image_config.config.env.as_deref().unwrap_or_default());

    let blobs = download_layers(client, r, resolved, dir)?;
    let plan = layers::plan(&blobs)?;
    let path = env
        .iter()
        .rev()
        .find(|(k, _)| k == "PATH")
        .map_or(DEFAULT_PATH, |(_, v)| v.as_str());
    if !path
        .split(':')
        .any(|d| d.starts_with('/') && plan.contains(&format!("{d}/buildkite-agent")))
    {
        bail!("{r} cannot run jobs: no buildkite-agent on its PATH ({path})");
    }

    let rootfs = dir.join(ROOTFS_FILE);
    make_erofs(&blobs, &plan, &rootfs, compression)?;
    fs::remove_dir_all(dir.join("blobs"))?;
    Cmd::new("fsck.erofs")
        .arg(&rootfs)
        .run()
        .context("checking the new root filesystem")?;
    fs::set_permissions(&rootfs, fs::Permissions::from_mode(0o644))?;
    info!(
        "{}: {} paths, {} MiB",
        r,
        plan.path_count(),
        fs::metadata(&rootfs)?.len() >> 20
    );
    Ok(Meta {
        image: r.pinned(&resolved.digest),
        env,
    })
}

/// Bring the kernel and every pool's image up to date. A failure on one
/// leaves the others to be tried, and the whole run fails at the end.
pub fn update_all(config: &Config) -> Result<()> {
    fs::create_dir_all(&config.state_dir)?;
    fs::set_permissions(&config.state_dir, fs::Permissions::from_mode(0o711))?;
    let lock = File::create(config.state_dir.join("images.lock"))?;
    lock.lock()?;

    let mut client = Client::new(Credentials::load(&config.images.auth_file)?);
    let compression = &config.images.compression;
    let mut failures = vec![];

    match update(
        &mut client,
        &kernel_dir(config),
        &config.kernel.image,
        &mut build_kernel,
    ) {
        Ok(false) => info!("{}: up to date", config.kernel.image),
        Ok(true) => {}
        Err(e) => {
            error!("{}: {e:#}", config.kernel.image);
            failures.push(config.kernel.image.clone());
        }
    }
    for image in config.pool_images() {
        let mut build = |c: &mut Client, r: &Reference, res: &Resolved, d: &Path| {
            build_image(c, r, res, d, compression)
        };
        match update(&mut client, &image_dir(config, image), image, &mut build) {
            Ok(false) => info!("{image}: up to date"),
            Ok(true) => {}
            Err(e) => {
                error!("{image}: {e:#}");
                failures.push(image.to_string());
            }
        }
    }
    if !failures.is_empty() {
        bail!("could not update {}", failures.join(", "));
    }
    Ok(())
}

/// `arsonist image export`: the flattened image as a tar, for looking at
/// what a guest would get.
pub fn export(auth_file: &Path, image: &str, out: impl Write) -> Result<()> {
    let r = Reference::parse(image)?;
    let mut client = Client::new(Credentials::load(auth_file)?);
    let resolved = client.resolve(&r)?;
    info!("{}", r.pinned(&resolved.digest));
    let dir = std::env::temp_dir().join(format!("arsonist-export-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    let result = (|| {
        let blobs = download_layers(&mut client, &r, &resolved, &dir)?;
        let plan = layers::plan(&blobs)?;
        layers::write_tar(&blobs, &plan, out)
    })();
    let _ = fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_env_is_split_at_the_first_equals() {
        let env = parse_env(&[
            "PATH=/a:/b".into(),
            "EMPTY=".into(),
            "WITH_EQ=a=b".into(),
            "BROKEN".into(),
            "=x".into(),
        ]);
        assert_eq!(
            env,
            [
                ("PATH".into(), "/a:/b".into()),
                ("EMPTY".into(), "".into()),
                ("WITH_EQ".into(), "a=b".into())
            ]
        );
    }

    #[test]
    fn each_configured_ref_gets_its_own_directory() {
        let config = Config::parse(
            "[pools.a]\nimage = \"x\"\ncount = 1\nmemory = \"1G\"\ntags = [\"q\"]\n",
            Path::new("c.toml"),
            2,
        )
        .unwrap();
        assert_eq!(
            image_dir(
                &config,
                "ghcr.io/divvun/divvun-actions:ubuntu-latest@sha256:00"
            ),
            Path::new("/var/lib/arsonist/images/ghcr.io_divvun_divvun-actions_ubuntu-latest")
        );
        assert_ne!(
            image_dir(&config, "ghcr.io/divvun/divvun-actions:alpine-latest"),
            image_dir(&config, "ghcr.io/divvun/divvun-actions:ubuntu-latest")
        );
    }
}
