//! A slot: boot a VM, let it run one job, throw it away, boot the next.

use std::fs::{self, File};
use std::io::BufWriter;
use std::os::unix::fs::{MetadataExt, PermissionsExt, chown};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bao_ssh_agent::{Agent, Background, KeyStore, Serving, Transit};
use nix::sys::signal::Signal;

use crate::cmd::Cmd;
use crate::config::{Config, IoEngine, Slot, SshAgent};
use crate::images::{self, KERNEL_FILE, ROOTFS_FILE, Version};
use crate::net::{self, SlotAddress};
use crate::protocol::{
    CACHE_LABEL, GuestConfig, SCRATCH_LABEL, SSH_AGENT_PORT, SSH_AUTH_SOCK, VmInfo,
};
use crate::signals::{self, Signals};
use crate::vm::{self, jail};
use crate::{elf, error, firecracker, info, initramfs, warn};

const WAIT_FOR_IMAGES: Duration = Duration::from_secs(30);
const CTRL_ALT_DEL_EVERY: Duration = Duration::from_secs(10);
const BACKOFF_MIN: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(300);

pub struct CachePaths {
    pub disk: PathBuf,
    /// The image the disk was made under, for `reset_on_image_change`.
    pub marker: PathBuf,
}

pub fn cache_paths(config: &Config, slot: &Slot) -> CachePaths {
    let dir = config.state_dir.join("cache");
    CachePaths {
        disk: dir.join(format!("{}.ext4", slot.name)),
        marker: dir.join(format!("{}.image", slot.name)),
    }
}

/// `<chroot-base>/<exec-file-name>/<id>/root`, as the jailer lays it out.
struct JailPaths {
    base: PathBuf,
    id_dir: PathBuf,
    root: PathBuf,
}

fn jail_paths(config: &Config, slot: &Slot) -> JailPaths {
    let base = config.state_dir.join("jail");
    let exec_name = config
        .firecracker
        .firecracker
        .file_name()
        .expect("the firecracker path names a file");
    let id_dir = base.join(exec_name).join(&slot.name);
    JailPaths {
        root: id_dir.join("root"),
        id_dir,
        base,
    }
}

fn make_ext4(file: &Path, bytes: u64, label: &str) -> Result<()> {
    let f = File::create(file).with_context(|| format!("{}", file.display()))?;
    f.set_len(bytes)?;
    drop(f);
    Cmd::new("mkfs.ext4")
        .args(["-q", "-F", "-m", "0", "-L", label])
        .args(["-E", "lazy_itable_init=1,lazy_journal_init=1,nodiscard"])
        .arg(file)
        .run()?;
    Ok(())
}

/// How full an ext4 image is, from its superblock.
pub fn ext4_usage(file: &Path) -> Result<(u64, u64)> {
    let out = Cmd::new("dumpe2fs").arg("-h").arg(file).run()?.stdout;
    let field = |name: &str| -> Result<u64> {
        out.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(':').map(str::trim))
            .and_then(|v| v.parse().ok())
            .with_context(|| format!("dumpe2fs -h {} has no {name:?}", file.display()))
    };
    let block_size = field("Block size")?;
    let total = field("Block count")?;
    let free = field("Free blocks")?;
    Ok(((total - free) * block_size, total * block_size))
}

/// Why the slot's cache disk has to be made afresh, or None to keep it.
fn cache_reset_reason(config: &Config, slot: &Slot, image: &Version) -> Result<Option<String>> {
    let paths = cache_paths(config, slot);
    let Ok(meta) = fs::metadata(&paths.disk) else {
        return Ok(Some("there is none yet".into()));
    };
    if meta.len() != config.pool(slot).cache.0 {
        return Ok(Some("its configured size changed".into()));
    }
    if config.cache.reset_on_image_change {
        let made_for = fs::read_to_string(&paths.marker).unwrap_or_default();
        if made_for.trim() != image.meta.image {
            return Ok(Some(format!("the image is now {}", image.meta.image)));
        }
    }
    // 1 and 2 mean e2fsck repaired the filesystem.
    let fsck = Cmd::new("e2fsck")
        .arg("-p")
        .arg(&paths.disk)
        .ok_codes(&[1, 2, 4, 8])
        .run()?;
    if fsck.code >= 4 {
        return Ok(Some(format!(
            "e2fsck could not repair it: {}",
            fsck.stdout.trim()
        )));
    }
    let (used, total) = ext4_usage(&paths.disk)?;
    let usage = used as f64 / total.max(1) as f64;
    if usage >= config.cache.reset_usage {
        return Ok(Some(format!("it is {:.0}% full", usage * 100.0)));
    }
    Ok(None)
}

fn prepare_cache(config: &Config, slot: &Slot, image: &Version) -> Result<()> {
    let paths = cache_paths(config, slot);
    fs::create_dir_all(paths.disk.parent().expect("in the cache dir"))?;
    if let Some(reason) = cache_reset_reason(config, slot, image)? {
        info!("making a new cache disk for {}: {reason}", slot.name);
        let _ = fs::remove_file(&paths.disk);
        make_ext4(&paths.disk, config.pool(slot).cache.0, CACHE_LABEL)?;
        fs::write(&paths.marker, format!("{}\n", image.meta.image))?;
    }
    Ok(())
}

pub fn reset_cache(config: &Config, slot: &Slot) -> Result<()> {
    let paths = cache_paths(config, slot);
    match fs::remove_file(&paths.disk) {
        Ok(()) => info!(
            "removed {}; {} starts a new one at its next boot",
            paths.disk.display(),
            slot.name
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("{} has no cache disk", slot.name)
        }
        Err(e) => return Err(e).with_context(|| format!("{}", paths.disk.display())),
    }
    Ok(())
}

fn host_name() -> String {
    nix::unistd::gethostname()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "localhost".into())
}

struct Boot {
    addr: SlotAddress,
    jail: JailPaths,
    args: Vec<String>,
    /// Answering until the boot is over.
    ssh_agent: Option<Serving>,
}

fn guest_config(
    config: &Config,
    slot: &Slot,
    image: &Version,
    kernel: &Version,
    hostname: &str,
) -> Result<GuestConfig> {
    let pool = config.pool(slot);
    let token_file = &config.buildkite.token_file;
    let token = fs::read_to_string(token_file)
        .with_context(|| format!("reading {}", token_file.display()))?;
    let token = token.trim();
    if token.is_empty() {
        bail!("{} is empty", token_file.display());
    }
    let mut env = image.meta.env.clone();
    env.extend(pool.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    env.push(("BUILDKITE_AGENT_TOKEN".into(), token.into()));
    env.push(("BUILDKITE_AGENT_NAME".into(), hostname.into()));
    env.push(("BUILDKITE_AGENT_TAGS".into(), pool.tags.join(",")));
    if config.ssh_agent.is_some() {
        env.push(("SSH_AUTH_SOCK".into(), SSH_AUTH_SOCK.into()));
    }

    let mut agent: Vec<String> = ["buildkite-agent", "start", "--disconnect-after-job"]
        .map(String::from)
        .into();
    agent.extend(config.buildkite.args.iter().cloned());

    let dns = if config.network.dns.is_empty() {
        net::host_resolvers()?
    } else {
        config.network.dns.clone()
    };
    Ok(GuestConfig {
        hostname: hostname.into(),
        dns,
        env,
        agent,
        cache_paths: config.cache.paths.clone(),
        files: config.files.iter().map(|f| f.guest.clone()).collect(),
        discard: pool.io_engine == IoEngine::Sync,
        ssh_agent: config.ssh_agent.is_some(),
        info: VmInfo {
            slot: slot.name.clone(),
            host: host_name(),
            image: image.meta.image.clone(),
            kernel: kernel.meta.image.clone(),
            arsonist: env!("CARGO_PKG_VERSION").into(),
        },
    })
}

fn prepare_boot(
    config: &Config,
    slot: &Slot,
    kernel: &Version,
    image: &Version,
    init: &[u8],
    ssh_agent: Option<(&Background, Agent)>,
) -> Result<Boot> {
    let pool = config.pool(slot);
    let uid = config.slot_uid(slot);
    let jail = jail_paths(config, slot);
    let addr = config.network.subnet.slot(slot.index)?;
    let hostname = vm::guest_hostname(&host_name(), &slot.name);
    let guest = guest_config(config, slot, image, kernel, &hostname)?;

    let _ = fs::remove_dir_all(&jail.id_dir);
    fs::create_dir_all(&jail.root)?;
    let in_jail = |name: &str| jail.root.join(name);

    let link = |from: PathBuf, to: PathBuf| {
        fs::hard_link(&from, &to).with_context(|| {
            format!(
                "could not hard-link {} into the jail; {} must be one filesystem",
                from.display(),
                config.state_dir.display()
            )
        })
    };
    link(kernel.dir.join(KERNEL_FILE), in_jail(jail::KERNEL))?;
    link(image.dir.join(ROOTFS_FILE), in_jail(jail::ROOTFS))?;

    make_ext4(&in_jail(jail::SCRATCH), pool.scratch.0, SCRATCH_LABEL)?;
    chown(in_jail(jail::SCRATCH), Some(uid), Some(uid))?;

    prepare_cache(config, slot, image)?;
    let cache = cache_paths(config, slot);
    chown(&cache.disk, Some(uid), Some(uid))?;
    link(cache.disk, in_jail(jail::CACHE))?;

    let host_files: Vec<&Path> = config.files.iter().map(|f| f.host.as_path()).collect();
    let initrd = in_jail(jail::INITRD);
    {
        let out = BufWriter::new(File::create(&initrd)?);
        initramfs::write(out, init, &guest, &host_files)?;
    }
    chown(&initrd, Some(uid), Some(uid))?;
    fs::set_permissions(&initrd, fs::Permissions::from_mode(0o400))?;

    let boot_args = vm::boot_args(&addr, &hostname, &guest.dns, &config.kernel.args);
    let vm_config = vm::firecracker_config(pool, &addr, &boot_args, ssh_agent.is_some());
    fs::write(
        in_jail(jail::VM_CONFIG),
        serde_json::to_vec_pretty(&vm_config)?,
    )?;

    let ssh_agent = ssh_agent
        .map(|(background, agent)| {
            let path = in_jail(&jail::vsock_listener(SSH_AGENT_PORT));
            let listener = UnixListener::bind(&path)
                .with_context(|| format!("listening at {}", path.display()))?;
            // Firecracker connects to it as the slot's uid.
            chown(&path, Some(uid), Some(uid))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            background.serve(listener, agent)
        })
        .transpose()?;

    net::tap_up(&addr, uid)?;

    // cgroup v2 and no --cgroup: the jailer leaves Firecracker in this
    // unit's cgroup instead of making one outside it.
    let args = [
        "--id",
        &slot.name,
        "--exec-file",
        &config.firecracker.firecracker.to_string_lossy(),
        "--uid",
        &uid.to_string(),
        "--gid",
        &uid.to_string(),
        "--chroot-base-dir",
        &jail.base.to_string_lossy(),
        "--cgroup-version",
        "2",
        "--",
        "--level",
        "Warning",
        "--config-file",
        &format!("/{}", jail::VM_CONFIG),
        "--api-sock",
        &format!("/{}", jail::API_SOCKET),
    ]
    .map(String::from)
    .to_vec();
    info!(
        "booting {} as {hostname}: {}, kernel {}",
        slot.name, image.meta.image, kernel.meta.image
    );
    Ok(Boot {
        addr,
        jail,
        args,
        ssh_agent,
    })
}

/// Whether the arsonist binary this runs from was replaced on disk.
struct ExeWatch {
    path: PathBuf,
    running: (u64, u64),
}

impl ExeWatch {
    fn new() -> Result<ExeWatch> {
        let running = fs::metadata("/proc/self/exe")?;
        let path = fs::read_link("/proc/self/exe")?;
        let path = PathBuf::from(path.to_string_lossy().trim_end_matches(" (deleted)"));
        Ok(ExeWatch {
            path,
            running: (running.dev(), running.ino()),
        })
    }

    fn replaced(&self) -> bool {
        fs::metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) != self.running)
    }
}

/// Boot the slot's VM over and over, one job each, until told to stop. The
/// first SIGTERM lets the running job finish; a second kills the VM.
///
/// The config is read again before every boot, so an edit applies from the
/// slot's next job, as a new image does.
pub fn run(config_path: &Path, slot_name: &str) -> Result<()> {
    let init = fs::read("/proc/self/exe").context("reading this binary to boot guests with")?;
    elf::check_static(&init)?;
    let exe = ExeWatch::new()?;
    let signals = Signals::block(&[Signal::SIGTERM, Signal::SIGINT, Signal::SIGCHLD])?;
    let mut config = Config::load(config_path)?;

    let mut stopping = false;
    let mut backoff = BACKOFF_MIN;
    let mut unconfigured_logged = false;
    // Kept from boot to boot, with its OpenBao login, while the config
    // asks for the same key.
    let mut transit: Option<(SshAgent, Arc<Transit>)> = None;
    let mut background: Option<Background> = None;
    loop {
        if stopping {
            break;
        }
        if exe.replaced() {
            info!("{slot_name}: arsonist was upgraded; restarting into the new one");
            break;
        }
        match Config::load(config_path) {
            Ok(c) => config = c,
            Err(e) => error!("{slot_name}: {e:#}; booting with the config as it was read before"),
        }
        let Some(slot) = config.slots.iter().find(|s| s.name == slot_name).cloned() else {
            if !unconfigured_logged {
                info!(
                    "{slot_name}: not in {} any more; waiting for it to come back, or for `arsonist install` to remove it",
                    config_path.display()
                );
                unconfigured_logged = true;
            }
            sleep(&signals, WAIT_FOR_IMAGES, &mut stopping)?;
            continue;
        };
        unconfigured_logged = false;

        let Some((kernel, image)) = wait_for_versions(&config, &slot, &signals, &mut stopping)?
        else {
            break;
        };
        transit = match (&config.ssh_agent, transit.take()) {
            (Some(wanted), Some((had, kept))) if had == *wanted => Some((had, kept)),
            (Some(wanted), _) => Some((wanted.clone(), Arc::new(wanted.transit()?))),
            (None, _) => None,
        };
        if transit.is_some() && background.is_none() {
            background = Some(Background::new().context("starting the ssh agent")?);
        }
        let ssh_agent = transit
            .as_ref()
            .zip(background.as_ref())
            .map(|((_, transit), bg)| {
                let store: Arc<dyn KeyStore> = transit.clone();
                (bg, Agent::new(store, &slot.name))
            });
        let mut boot = match prepare_boot(&config, &slot, &kernel, &image, &init, ssh_agent) {
            Ok(boot) => boot,
            Err(e) => {
                error!(
                    "{slot_name}: could not prepare the VM: {e:#}; trying again in {}s",
                    backoff.as_secs()
                );
                let _ = fs::remove_dir_all(&jail_paths(&config, &slot).id_dir);
                sleep(&signals, backoff, &mut stopping)?;
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        while let Some(s) = signals.wait(Some(Duration::ZERO))? {
            if matches!(s, Signal::SIGTERM | Signal::SIGINT) {
                stopping = true;
            }
        }
        let status = if stopping {
            None
        } else {
            let child = signals::unblocked(&mut Command::new(&config.firecracker.jailer))
                .args(&boot.args)
                .stdin(Stdio::null())
                .spawn()
                .with_context(|| format!("starting {}", config.firecracker.jailer.display()))?;
            Some(supervise(child, &boot, &signals, &mut stopping, slot_name)?)
        };
        drop(boot.ssh_agent.take());
        let _ = fs::remove_dir_all(&boot.jail.id_dir);
        if let Err(e) = net::tap_down(&boot.addr) {
            warn!("{slot_name}: {e:#}");
        }
        match status {
            Some(true) => backoff = BACKOFF_MIN,
            Some(false) => {
                error!(
                    "{slot_name}: Firecracker failed; trying again in {}s",
                    backoff.as_secs()
                );
                sleep(&signals, backoff, &mut stopping)?;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
            None => {}
        }
    }
    info!("{slot_name}: stopped");
    Ok(())
}

/// Wait for Firecracker to exit, relaying stop requests to the guest.
/// Returns whether it exited cleanly.
fn supervise(
    mut child: Child,
    boot: &Boot,
    signals: &Signals,
    stopping: &mut bool,
    slot: &str,
) -> Result<bool> {
    let api_socket = boot.jail.root.join(jail::API_SOCKET);
    let ask_guest = || {
        if !firecracker::send_ctrl_alt_del(&api_socket) {
            info!(
                "{slot}: the guest is not listening yet; asking again in {}s",
                CTRL_ALT_DEL_EVERY.as_secs()
            );
        }
    };
    if *stopping {
        ask_guest();
    }
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        match signals.wait(stopping.then_some(CTRL_ALT_DEL_EVERY))? {
            Some(Signal::SIGTERM | Signal::SIGINT) if !*stopping => {
                info!("{slot}: stopping once the running job finishes");
                *stopping = true;
                ask_guest();
            }
            Some(Signal::SIGTERM | Signal::SIGINT) => {
                warn!("{slot}: second stop signal, killing the VM");
                let _ = child.kill();
            }
            // The guest misses Ctrl-Alt-Del while it is still booting.
            None if *stopping => ask_guest(),
            _ => {}
        }
    }
}

fn sleep(signals: &Signals, duration: Duration, stopping: &mut bool) -> Result<()> {
    let deadline = std::time::Instant::now() + duration;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Ok(());
        }
        if let Some(Signal::SIGTERM | Signal::SIGINT) = signals.wait(Some(left))? {
            *stopping = true;
            return Ok(());
        }
    }
}

fn wait_for_versions(
    config: &Config,
    slot: &Slot,
    signals: &Signals,
    stopping: &mut bool,
) -> Result<Option<(Version, Version)>> {
    let pool = config.pool(slot);
    let mut logged = false;
    loop {
        let kernel = images::current_version(&images::kernel_dir(config))?;
        let image = images::current_version(&images::image_dir(config, &pool.image))?;
        if let (Some(k), Some(i)) = (&kernel, &image) {
            return Ok(Some((k.clone(), i.clone())));
        }
        if !logged {
            let missing = if kernel.is_none() {
                &config.kernel.image
            } else {
                &pool.image
            };
            info!(
                "{}: waiting for {missing}; the arsonist-images timer converts it",
                slot.name
            );
            logged = true;
        }
        sleep(signals, WAIT_FOR_IMAGES, stopping)?;
        if *stopping {
            return Ok(None);
        }
    }
}
