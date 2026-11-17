//! The host's config file: what pools of slots it runs, and how.

use std::fmt;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, de};

use crate::net::Subnet;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/arsonist/config.toml";
pub const KERNEL_IMAGE: &str = "ghcr.io/necessary-nu/arsonist-kernel:latest";

const MAX_POOL_NAME: usize = 32;
const MAX_VCPUS: u32 = 32;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(skip)]
    pub path: PathBuf,
    /// Images, kernels, cache disks and jails. One filesystem, because VMs
    /// boot from hard links into their jails.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Slot n runs as uid and gid `uid_base + n`.
    #[serde(default = "default_uid_base")]
    pub uid_base: u32,
    #[serde(default)]
    pub firecracker: Firecracker,
    #[serde(default)]
    pub buildkite: Buildkite,
    #[serde(default)]
    pub network: Network,
    #[serde(default)]
    pub kernel: Kernel,
    #[serde(default)]
    pub images: Images,
    #[serde(default)]
    pub cache: Cache,
    #[serde(default)]
    pub files: Vec<SharedFile>,
    pub pools: IndexMap<String, Pool>,
    #[serde(skip)]
    pub slots: Vec<Slot>,
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/arsonist")
}

fn default_uid_base() -> u32 {
    900_000
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Firecracker {
    pub firecracker: PathBuf,
    pub jailer: PathBuf,
}

impl Default for Firecracker {
    fn default() -> Self {
        Firecracker {
            firecracker: PathBuf::from("/usr/local/bin/firecracker"),
            jailer: PathBuf::from("/usr/local/bin/jailer"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Buildkite {
    /// Read at every boot, so a new token needs no restart.
    pub token_file: PathBuf,
    /// Added to `buildkite-agent start --disconnect-after-job`.
    pub args: Vec<String>,
}

impl Default for Buildkite {
    fn default() -> Self {
        Buildkite {
            token_file: PathBuf::from("/etc/arsonist/agent-token"),
            args: vec!["--tags-from-host".into()],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Network {
    pub subnet: Subnet,
    /// Empty: the host's own upstream resolvers, read at every boot.
    pub dns: Vec<Ipv4Addr>,
}

impl Default for Network {
    fn default() -> Self {
        Network {
            subnet: "172.30.0.0/16".parse().expect("a valid subnet"),
            dns: vec![],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Kernel {
    pub image: String,
    /// Appended to the kernel command line.
    pub args: String,
}

impl Default for Kernel {
    fn default() -> Self {
        Kernel {
            image: KERNEL_IMAGE.into(),
            args: "quiet".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Images {
    /// `mkfs.erofs -z`, or "none".
    pub compression: String,
    /// Registry credentials, in the format of Docker's `config.json`.
    pub auth_file: PathBuf,
}

impl Default for Images {
    fn default() -> Self {
        Images {
            compression: "lz4".into(),
            auth_file: PathBuf::from("/etc/arsonist/auth.json"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Cache {
    /// Guest paths kept on the slot's cache disk from one job to the next.
    pub paths: Vec<String>,
    pub reset_on_image_change: bool,
    /// Start the disk over at boot once it is this full.
    pub reset_usage: f64,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            paths: vec![],
            reset_on_image_change: true,
            reset_usage: 0.9,
        }
    }
}

/// A host file or directory copied into every guest's memory and bound at
/// `guest`, read at every boot.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedFile {
    pub host: PathBuf,
    pub guest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum IoEngine {
    Sync,
    Async,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pool {
    #[serde(skip)]
    pub name: String,
    pub image: String,
    pub count: u32,
    /// Defaults to the host's CPU count, capped and made even.
    pub vcpus: Option<u32>,
    pub memory: Size,
    #[serde(default = "default_scratch")]
    pub scratch: Size,
    #[serde(default = "default_cache")]
    pub cache: Size,
    pub tags: Vec<String>,
    #[serde(default = "default_io_engine")]
    pub io_engine: IoEngine,
    #[serde(default)]
    pub env: IndexMap<String, String>,
}

fn default_scratch() -> Size {
    Size(64 << 30)
}

fn default_cache() -> Size {
    Size(200 << 30)
}

fn default_io_engine() -> IoEngine {
    IoEngine::Sync
}

impl Pool {
    pub fn vcpus(&self) -> u32 {
        self.vcpus.expect("filled in by Config::parse")
    }

    pub fn memory_mib(&self) -> u64 {
        self.memory.0 >> 20
    }
}

#[derive(Debug, Clone)]
pub struct Slot {
    /// `<pool>-<n>`, n from 1: the jailer id and the systemd instance.
    pub name: String,
    /// The slot's pool, as an index into `Config::pools`.
    pub pool: usize,
    /// Position across every pool, in file order. It picks the slot's
    /// addresses, tap and uid, so new pools go at the end.
    pub index: u32,
}

/// Bytes, written as `"24G"` (binary units) or a plain integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size(pub u64);

impl Size {
    pub fn parse(text: &str) -> Result<Size> {
        let t = text.trim().to_ascii_uppercase();
        let t = t
            .strip_suffix("IB")
            .or_else(|| t.strip_suffix('B'))
            .unwrap_or(&t);
        let (num, shift) = match t.chars().last() {
            Some('K') => (&t[..t.len() - 1], 10),
            Some('M') => (&t[..t.len() - 1], 20),
            Some('G') => (&t[..t.len() - 1], 30),
            Some('T') => (&t[..t.len() - 1], 40),
            _ => (t, 0),
        };
        let value: f64 = num
            .trim()
            .parse()
            .with_context(|| format!("cannot read size {text:?}"))?;
        let bytes = (value * (1u64 << shift) as f64) as u64;
        if !(value.is_finite() && bytes > 0) {
            bail!("size {text:?} must be positive");
        }
        Ok(Size(bytes))
    }
}

impl<'de> Deserialize<'de> for Size {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl de::Visitor<'_> for V {
            type Value = Size;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(r#"a size like "24G", or bytes"#)
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Size, E> {
                Size::parse(v).map_err(|e| E::custom(format!("{e:#}")))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Size, E> {
                u64::try_from(v)
                    .ok()
                    .filter(|&v| v > 0)
                    .map(Size)
                    .ok_or_else(|| E::custom("size must be positive"))
            }
        }
        d.deserialize_any(V)
    }
}

/// Firecracker takes 1 or an even number of vCPUs, at most 32.
pub fn default_vcpus(host_cpus: u32) -> u32 {
    let n = host_cpus.min(MAX_VCPUS);
    if n <= 1 { 1 } else { n - n % 2 }
}

fn valid_pool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_POOL_NAME
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

fn check_guest_path(path: &str, what: &str) -> Result<()> {
    if !path.starts_with('/') || path == "/" || path.split('/').any(|c| c == ".." || c == ".") {
        bail!("{what}: {path:?} must be an absolute path below /, without . or ..");
    }
    Ok(())
}

impl Config {
    pub fn parse(text: &str, path: &Path, host_cpus: u32) -> Result<Config> {
        let mut config: Config =
            toml::from_str(text).with_context(|| format!("{}", path.display()))?;
        config.path = path.to_path_buf();
        config
            .validate(host_cpus)
            .with_context(|| format!("{}", path.display()))?;
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Config> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
                "{} does not exist; `arsonist setup` writes an example",
                path.display()
            ),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
        Config::parse(&text, path, cpus)
    }

    fn validate(&mut self, host_cpus: u32) -> Result<()> {
        if self.pools.is_empty() {
            bail!("no [pools.<name>] tables");
        }
        if !(self.cache.reset_usage > 0.0 && self.cache.reset_usage <= 1.0) {
            bail!("cache.reset_usage: a fraction above 0, at most 1");
        }
        if self.images.compression.is_empty() {
            bail!("images.compression: a mkfs.erofs -z algorithm, or \"none\"");
        }
        for p in &self.cache.paths {
            check_guest_path(p, "cache.paths")?;
        }
        for f in &self.files {
            check_guest_path(&f.guest, "files.guest")?;
        }

        for (name, pool) in self.pools.iter_mut() {
            let field = format!("pools.{name}");
            if !valid_pool_name(name) {
                bail!(
                    "{field}: pool names are up to {MAX_POOL_NAME} lowercase letters, digits and single hyphens"
                );
            }
            pool.name = name.clone();
            let vcpus = pool.vcpus.unwrap_or_else(|| default_vcpus(host_cpus));
            if vcpus == 0 || vcpus > MAX_VCPUS || (vcpus > 1 && vcpus % 2 != 0) {
                bail!("{field}.vcpus: Firecracker takes 1 or an even number up to {MAX_VCPUS}");
            }
            pool.vcpus = Some(vcpus);
            if pool.memory_mib() < 128 {
                bail!("{field}.memory: at least 128M");
            }
            if pool.tags.is_empty() {
                bail!(r#"{field}.tags: give at least the queue, e.g. ["queue=linux"]"#);
            }
        }

        self.slots.clear();
        for (pool_index, pool) in self.pools.values().enumerate() {
            for n in 1..=pool.count {
                let index = self.slots.len() as u32;
                self.slots.push(Slot {
                    name: format!("{}-{n}", pool.name),
                    pool: pool_index,
                    index,
                });
            }
        }
        if let Some(last) = self.slots.last() {
            self.network
                .subnet
                .slot(last.index)
                .context("network.subnet")?;
            self.uid_base
                .checked_add(last.index)
                .context("uid_base leaves no room for the slots")?;
        }
        Ok(())
    }

    pub fn pool(&self, slot: &Slot) -> &Pool {
        &self.pools[slot.pool]
    }

    pub fn find_slot(&self, name: &str) -> Result<&Slot> {
        self.slots.iter().find(|s| s.name == name).with_context(|| {
            let names: Vec<_> = self.slots.iter().map(|s| s.name.as_str()).collect();
            format!(
                "no slot {name} in {}; slots: {}",
                self.path.display(),
                names.join(", ")
            )
        })
    }

    pub fn slot_uid(&self, slot: &Slot) -> u32 {
        self.uid_base + slot.index
    }

    /// The image refs the pools boot, each once.
    pub fn pool_images(&self) -> Vec<&str> {
        let mut images: Vec<&str> = vec![];
        for pool in self.pools.values() {
            if !images.contains(&pool.image.as_str()) {
                images.push(&pool.image);
            }
        }
        images
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config> {
        Config::parse(text, Path::new("c.toml"), 16)
    }

    const MINIMAL: &str = r#"
[pools.linux]
image = "ghcr.io/divvun/divvun-actions:ubuntu-latest"
count = 2
memory = "24G"
tags = ["queue=linux"]

[pools.linux-large]
image = "ghcr.io/divvun/divvun-actions:ubuntu-latest"
count = 1
vcpus = 8
memory = "32G"
cache = "500G"
tags = ["queue=linux", "size=large"]
"#;

    #[test]
    fn slots_number_across_pools_in_file_order() {
        let c = parse(MINIMAL).unwrap();
        let slots: Vec<_> = c.slots.iter().map(|s| (s.name.as_str(), s.index)).collect();
        assert_eq!(
            slots,
            [("linux-1", 0), ("linux-2", 1), ("linux-large-1", 2)]
        );
        assert_eq!(c.pool(&c.slots[2]).name, "linux-large");
        assert_eq!(c.slot_uid(&c.slots[2]), 900_002);
        assert_eq!(
            c.pool_images(),
            ["ghcr.io/divvun/divvun-actions:ubuntu-latest"]
        );
    }

    #[test]
    fn defaults_fill_everything_outside_the_pools() {
        let c = parse(MINIMAL).unwrap();
        let linux = &c.pools["linux"];
        assert_eq!(linux.vcpus(), 16);
        assert_eq!(linux.memory_mib(), 24 * 1024);
        assert_eq!(linux.scratch, Size(64 << 30));
        assert_eq!(c.pools["linux-large"].cache, Size(500 << 30));
        assert_eq!(c.state_dir, Path::new("/var/lib/arsonist"));
        assert_eq!(c.kernel.image, KERNEL_IMAGE);
        assert_eq!(c.buildkite.args, ["--tags-from-host"]);
        assert!(c.cache.reset_on_image_change);
    }

    #[test]
    fn the_example_config_is_valid() {
        let c = Config::parse(
            include_str!("../config.example.toml"),
            Path::new("example.toml"),
            16,
        )
        .unwrap();
        assert_eq!(c.slots.len(), 4);
        assert!(c.cache.paths.contains(&"/var/lib/docker".to_string()));
        assert_eq!(c.files[0].guest, "/buildkite/hooks");
    }

    #[test]
    fn sizes() {
        assert_eq!(Size::parse("24G").unwrap(), Size(24 << 30));
        assert_eq!(Size::parse("1.5GiB").unwrap(), Size(3 << 29));
        assert_eq!(Size::parse("512m").unwrap(), Size(512 << 20));
        assert_eq!(Size::parse("4096").unwrap(), Size(4096));
        assert!(Size::parse("0G").is_err());
        assert!(Size::parse("lots").is_err());
    }

    #[test]
    fn vcpus_must_suit_firecracker() {
        assert_eq!(default_vcpus(1), 1);
        assert_eq!(default_vcpus(7), 6);
        assert_eq!(default_vcpus(128), 32);
        let odd = MINIMAL.replace("vcpus = 8", "vcpus = 7");
        assert!(format!("{:#}", parse(&odd).unwrap_err()).contains("even number"));
    }

    #[test]
    fn mistakes_are_refused() {
        let typo = MINIMAL.replace("count = 2", "count = 2\ncuont = 3");
        assert!(format!("{:#}", parse(&typo).unwrap_err()).contains("cuont"));
        let bad_name = MINIMAL.replace("[pools.linux]", "[pools.Linux_1]");
        assert!(format!("{:#}", parse(&bad_name).unwrap_err()).contains("pool names"));
        let no_tags = MINIMAL.replace(r#"tags = ["queue=linux"]"#, "tags = []");
        assert!(format!("{:#}", parse(&no_tags).unwrap_err()).contains("queue"));
        let relative = format!("[cache]\npaths = [\"var/lib/docker\"]\n{MINIMAL}");
        assert!(format!("{:#}", parse(&relative).unwrap_err()).contains("absolute"));
        let small_subnet = format!("[network]\nsubnet = \"10.0.0.0/29\"\n{MINIMAL}");
        assert!(format!("{:#}", parse(&small_subnet).unwrap_err()).contains("room for 2 slots"));
    }
}
