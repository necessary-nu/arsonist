//! PID 1 of a guest, booted from the initramfs the host wrote for this one
//! boot. It puts the image (read-only erofs) under a scratch overlay,
//! switches into it, binds the cache disk and the host's files into place,
//! runs dockerd if the image has it, and then the Buildkite agent for one
//! job. When the agent exits, the VM resets, Firecracker exits, and the
//! host boots a fresh VM.
//!
//! The host asks for a graceful stop with Ctrl-Alt-Del, which arrives as
//! SIGINT. The agent then gets one SIGTERM, which lets its job finish; a
//! second would cancel the job.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use nix::mount::{MsFlags, mount};
use nix::sys::reboot::{RebootMode, reboot, set_cad_enabled};
use nix::sys::resource::{Resource, setrlimit};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, chdir, chroot, sethostname, sync};

use crate::images::DEFAULT_PATH;
use crate::protocol::{
    CACHE_LABEL, GuestConfig, INITRAMFS_CONFIG, INITRAMFS_DIR, SCRATCH_LABEL, VM_INFO_PATH,
    cache_subdir,
};
use crate::signals::{self, Signals};
use crate::{error, info, log, warn};

const NEW_ROOT: &str = "/newroot";
const RUN_DIR: &str = "/run/arsonist";
const CACHE_MOUNT: &str = "/run/arsonist/cache";
const FILES_DIR: &str = "/run/arsonist/files";
const DOCKER_SOCKET: &str = "/var/run/docker.sock";
const DOCKERD_LOG: &str = "/var/log/dockerd.log";

const FAIL_DELAY: Duration = Duration::from_secs(60);
const DRIVE_WAIT: Duration = Duration::from_secs(10);
const DOCKERD_WAIT: Duration = Duration::from_secs(60);
const DOCKERD_STOP_WAIT: Duration = Duration::from_secs(20);

pub fn main() -> ! {
    log::init_guest();
    match std::panic::catch_unwind(run) {
        Ok(Ok(())) => info!("done, resetting"),
        Ok(Err(e)) => fail(&format!("{e:#}")),
        Err(_) => fail("init panicked"),
    }
    reset()
}

/// A broken image or a bad token would otherwise have the host boot VMs in
/// a tight loop.
fn fail(why: &str) {
    error!("{why}; resetting in {}s", FAIL_DELAY.as_secs());
    std::thread::sleep(FAIL_DELAY);
}

fn reset() -> ! {
    sync();
    let _ = reboot(RebootMode::RB_AUTOBOOT);
    // Only reached if reboot failed. PID 1 exiting panics the kernel, and
    // panic=1 resets the VM all the same.
    std::process::exit(1)
}

fn mnt(source: &str, target: &str, fstype: &str, flags: MsFlags, data: &str) -> Result<()> {
    mount(
        Some(source),
        target,
        Some(fstype),
        flags,
        (!data.is_empty()).then_some(data),
    )
    .with_context(|| format!("mounting {fstype} {source} on {target}"))
}

fn move_mount(from: &str, to: &str) -> Result<()> {
    mount(Some(from), to, None::<&str>, MsFlags::MS_MOVE, None::<&str>)
        .with_context(|| format!("moving the mount at {from} to {to}"))
}

fn bind(from: &Path, to: &Path) -> Result<()> {
    mount(Some(from), to, None::<&str>, MsFlags::MS_BIND, None::<&str>)
        .with_context(|| format!("binding {} on {}", from.display(), to.display()))
}

fn mkdir(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))
}

struct Drives {
    rootfs: String,
    scratch: String,
    cache: String,
}

const EROFS_MAGIC: u32 = 0xE0F5_E1E2;
const EXT4_MAGIC: u16 = 0xEF53;

/// What a drive's superblock says it is: `Some("")` for an erofs, the label
/// for an ext4.
fn identify(dev: &Path) -> Option<String> {
    let mut sb = [0u8; 2048];
    File::open(dev).ok()?.read_exact(&mut sb).ok()?;
    if u32::from_le_bytes(sb[1024..1028].try_into().ok()?) == EROFS_MAGIC {
        return Some(String::new());
    }
    if u16::from_le_bytes(sb[1024 + 0x38..1024 + 0x3a].try_into().ok()?) == EXT4_MAGIC {
        let label = &sb[1024 + 0x78..1024 + 0x88];
        let end = label.iter().position(|&b| b == 0).unwrap_or(label.len());
        return Some(String::from_utf8_lossy(&label[..end]).into_owned());
    }
    None
}

fn find_drives() -> Result<Drives> {
    let deadline = Instant::now() + DRIVE_WAIT;
    loop {
        let (mut rootfs, mut scratch, mut cache) = (None, None, None);
        for entry in fs::read_dir("/sys/block")? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if !name.starts_with("vd") {
                continue;
            }
            let dev = format!("/dev/{name}");
            match identify(Path::new(&dev)).as_deref() {
                Some("") => rootfs = Some(dev),
                Some(SCRATCH_LABEL) => scratch = Some(dev),
                Some(CACHE_LABEL) => cache = Some(dev),
                _ => {}
            }
        }
        if let (Some(rootfs), Some(scratch), Some(cache)) = (&rootfs, &scratch, &cache) {
            return Ok(Drives {
                rootfs: rootfs.clone(),
                scratch: scratch.clone(),
                cache: cache.clone(),
            });
        }
        if Instant::now() > deadline {
            bail!(
                "drives missing: image {}, scratch {}, cache {}",
                rootfs.as_deref().unwrap_or("not found"),
                scratch.as_deref().unwrap_or("not found"),
                cache.as_deref().unwrap_or("not found")
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(from).with_context(|| format!("{}", from.display()))?;
    if meta.file_type().is_symlink() {
        symlink(fs::read_link(from)?, to)?;
    } else if meta.is_dir() {
        fs::create_dir(to).with_context(|| format!("creating {}", to.display()))?;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        }
        fs::set_permissions(to, meta.permissions())?;
    } else {
        fs::copy(from, to)
            .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    }
    Ok(())
}

/// Build the root (the image under a scratch overlay) and switch into it,
/// taking the host's files along in a tmpfs at /run.
fn enter_root(config: &GuestConfig, drives: &Drives) -> Result<()> {
    let discard = if config.discard { "discard" } else { "" };
    for dir in ["/lower", "/scratch", NEW_ROOT] {
        mkdir(dir)?;
    }
    mnt(&drives.rootfs, "/lower", "erofs", MsFlags::MS_RDONLY, "")?;
    mnt(
        &drives.scratch,
        "/scratch",
        "ext4",
        MsFlags::empty(),
        discard,
    )?;
    mkdir("/scratch/upper")?;
    mkdir("/scratch/work")?;
    mnt(
        "overlay",
        NEW_ROOT,
        "overlay",
        MsFlags::empty(),
        "lowerdir=/lower,upperdir=/scratch/upper,workdir=/scratch/work",
    )?;

    let in_root = |p: &str| format!("{NEW_ROOT}{p}");
    for dir in ["/dev", "/proc", "/sys", "/run"] {
        mkdir(in_root(dir))?;
    }
    mnt(
        "tmpfs",
        &in_root("/run"),
        "tmpfs",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        "mode=0755",
    )?;
    mkdir(in_root(RUN_DIR))?;
    fs::set_permissions(in_root(RUN_DIR), fs::Permissions::from_mode(0o755))?;
    copy_tree(
        &Path::new("/").join(INITRAMFS_DIR).join("files"),
        Path::new(&in_root(FILES_DIR)),
    )?;

    for dir in ["/dev", "/proc", "/sys"] {
        move_mount(dir, &in_root(dir))?;
    }
    chdir(NEW_ROOT)?;
    move_mount(".", "/")?;
    chroot(".")?;
    chdir("/")?;
    // As systemd does, so the guest's mounts propagate the way tools
    // written for systemd hosts expect.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_SHARED,
        None::<&str>,
    )
    .context("making / shared")?;
    Ok(())
}

/// What a container runtime would have set up, and the network names the
/// kernel's `ip=` configuration does not write anywhere.
fn set_up_system(config: &GuestConfig) -> Result<()> {
    mkdir("/sys/fs/cgroup")?;
    mnt(
        "cgroup2",
        "/sys/fs/cgroup",
        "cgroup2",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        "",
    )?;
    mkdir("/dev/pts")?;
    mkdir("/dev/shm")?;
    mnt(
        "devpts",
        "/dev/pts",
        "devpts",
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        "gid=5,mode=620,ptmxmode=666",
    )?;
    mnt(
        "shm",
        "/dev/shm",
        "tmpfs",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        "mode=1777",
    )?;
    for (link, target) in [
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
    ] {
        if fs::symlink_metadata(link).is_err() {
            symlink(target, link)?;
        }
    }
    let controllers = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").unwrap_or_default();
    for c in controllers.split_whitespace() {
        if fs::write("/sys/fs/cgroup/cgroup.subtree_control", format!("+{c}")).is_err() {
            warn!("cgroup controller {c} could not be enabled");
        }
    }

    sethostname(&config.hostname)?;
    mkdir("/etc")?;
    // An image may ship these as symlinks into /run, a fresh tmpfs here.
    for f in ["/etc/hostname", "/etc/hosts", "/etc/resolv.conf"] {
        let _ = fs::remove_file(f);
    }
    fs::write("/etc/hostname", format!("{}\n", config.hostname))?;
    fs::write(
        "/etc/hosts",
        format!(
            "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 {}\n",
            config.hostname
        ),
    )?;
    let resolv: String = config
        .dns
        .iter()
        .map(|d| format!("nameserver {d}\n"))
        .collect();
    fs::write("/etc/resolv.conf", resolv)?;
    Ok(())
}

fn mount_cache(config: &GuestConfig, drives: &Drives) -> Result<()> {
    let discard = if config.discard { "discard" } else { "" };
    mkdir(CACHE_MOUNT)?;
    mnt(
        &drives.cache,
        CACHE_MOUNT,
        "ext4",
        MsFlags::empty(),
        discard,
    )?;
    for path in &config.cache_paths {
        let src = Path::new(CACHE_MOUNT).join(cache_subdir(path));
        mkdir(&src)?;
        mkdir(path)?;
        bind(&src, Path::new(path))?;
    }
    Ok(())
}

fn bind_files(config: &GuestConfig) -> Result<()> {
    for (i, guest) in config.files.iter().enumerate() {
        let src = Path::new(FILES_DIR).join(i.to_string());
        let dest = Path::new(guest);
        if src.is_dir() {
            mkdir(dest)?;
        } else {
            mkdir(dest.parent().unwrap_or(Path::new("/")))?;
            if fs::symlink_metadata(dest).is_err() {
                File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
            }
        }
        bind(&src, dest)?;
    }
    Ok(())
}

/// Docker's defaults for a container's environment, then the image's, the
/// pool's and the agent's, each overriding the ones before.
fn environment(config: &GuestConfig) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = [
        ("PATH", DEFAULT_PATH),
        ("HOME", "/root"),
        ("HOSTNAME", &config.hostname),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    env.extend(config.env.iter().cloned());
    env
}

fn find_on_path(program: &str, env: &HashMap<String, String>) -> Option<PathBuf> {
    if program.contains('/') {
        return Some(PathBuf::from(program));
    }
    env.get("PATH")?
        .split(':')
        .map(|dir| Path::new(dir).join(program))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

#[derive(Default)]
struct Children {
    agent: Option<Pid>,
    agent_status: Option<WaitStatus>,
    dockerd: Option<Pid>,
    /// Set once init has told dockerd to stop, so its exit is expected.
    dockerd_stopping: bool,
    none_left: bool,
}

impl Children {
    /// Collect every exited child, as PID 1 has to for orphans too.
    fn reap(&mut self) {
        loop {
            match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => return,
                Err(e) => {
                    self.none_left = e == Errno::ECHILD;
                    return;
                }
                Ok(status) => {
                    let pid = status.pid();
                    if pid.is_some() && pid == self.agent {
                        self.agent = None;
                        self.agent_status = Some(status);
                    } else if pid.is_some() && pid == self.dockerd {
                        if !self.dockerd_stopping {
                            warn!("dockerd exited: {status:?}");
                        }
                        self.dockerd = None;
                    }
                }
            }
        }
    }
}

fn exit_status(status: WaitStatus) -> ExitStatus {
    match status {
        WaitStatus::Exited(_, code) => ExitStatus::from_raw(code << 8),
        WaitStatus::Signaled(_, sig, _) => ExitStatus::from_raw(sig as i32),
        _ => ExitStatus::from_raw(0),
    }
}

/// Wait for up to `timeout`, reaping children, until `done` holds. Stop
/// requests are noted in `stopping`.
fn wait_until(
    signals: &Signals,
    children: &mut Children,
    stopping: &mut bool,
    timeout: Duration,
    mut done: impl FnMut(&Children) -> bool,
) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        children.reap();
        if done(children) {
            return Ok(true);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(false);
        }
        if let Some(Signal::SIGINT | Signal::SIGTERM) =
            signals.wait(Some(left.min(Duration::from_millis(500))))?
        {
            if !*stopping {
                info!("asked to stop; not starting a job");
            }
            *stopping = true;
        }
    }
}

fn start_dockerd(
    dockerd: &Path,
    env: &HashMap<String, String>,
    signals: &Signals,
    children: &mut Children,
    stopping: &mut bool,
) -> Result<()> {
    let log = File::create(DOCKERD_LOG).with_context(|| format!("creating {DOCKERD_LOG}"))?;
    let child = signals::unblocked(&mut Command::new(dockerd))
        .args(["--host", &format!("unix://{DOCKER_SOCKET}")])
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .with_context(|| format!("starting {}", dockerd.display()))?;
    children.dockerd = Some(Pid::from_raw(child.id() as i32));
    let up = wait_until(signals, children, stopping, DOCKERD_WAIT, |c| {
        c.dockerd.is_none() || UnixStream::connect(DOCKER_SOCKET).is_ok()
    })?;
    if !up || children.dockerd.is_none() {
        let tail = fs::read_to_string(DOCKERD_LOG).unwrap_or_default();
        let tail: Vec<&str> = tail.lines().rev().take(30).collect();
        for line in tail.iter().rev() {
            eprintln!("dockerd: {line}");
        }
        bail!("dockerd did not come up within {}s", DOCKERD_WAIT.as_secs());
    }
    Ok(())
}

/// Stop everything left, so the cache disk can be put away cleanly.
fn wind_down(signals: &Signals, children: &mut Children, stopping: &mut bool) -> Result<()> {
    if let Some(pid) = children.dockerd {
        children.dockerd_stopping = true;
        let _ = kill(pid, Signal::SIGTERM);
        wait_until(signals, children, stopping, DOCKERD_STOP_WAIT, |c| {
            c.dockerd.is_none()
        })?;
    }
    // Every process but PID 1.
    let _ = kill(Pid::from_raw(-1), Signal::SIGTERM);
    wait_until(signals, children, stopping, Duration::from_secs(2), |_| {
        false
    })?;
    let _ = kill(Pid::from_raw(-1), Signal::SIGKILL);
    wait_until(signals, children, stopping, Duration::from_secs(5), |c| {
        c.none_left
    })?;
    sync();
    if let Err(e) = mount(
        None::<&str>,
        CACHE_MOUNT,
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    ) {
        warn!("could not remount the cache disk read-only: {e}");
    }
    Ok(())
}

fn run() -> Result<()> {
    // Without this Ctrl-Alt-Del resets the VM on the spot, killing the job,
    // instead of reaching PID 1 as SIGINT.
    set_cad_enabled(false).context("routing Ctrl-Alt-Del to init")?;
    let signals = Signals::block(&[Signal::SIGCHLD, Signal::SIGINT, Signal::SIGTERM])?;

    mkdir("/proc")?;
    mkdir("/sys")?;
    mnt("proc", "/proc", "proc", MsFlags::empty(), "")?;
    mnt("sysfs", "/sys", "sysfs", MsFlags::empty(), "")?;
    mnt(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        MsFlags::MS_NOSUID,
        "mode=0755",
    )?;

    let config_path = Path::new("/").join(INITRAMFS_CONFIG);
    let config: GuestConfig =
        serde_json::from_slice(&fs::read(&config_path)?).context("reading the boot's config")?;
    let drives = find_drives()?;
    enter_root(&config, &drives)?;
    set_up_system(&config)?;
    mount_cache(&config, &drives)?;
    bind_files(&config)?;
    fs::write(VM_INFO_PATH, serde_json::to_vec_pretty(&config.info)?)?;
    fs::set_permissions(VM_INFO_PATH, fs::Permissions::from_mode(0o644))?;
    // Docker's default for containers; the 1024 PID 1 starts with is too few
    // for some builds.
    if let Err(e) = setrlimit(Resource::RLIMIT_NOFILE, 1 << 20, 1 << 20) {
        warn!("could not raise the open file limit: {e}");
    }

    let env = environment(&config);
    let mut children = Children::default();
    let mut stopping = false;

    if let Some(dockerd) = find_on_path("dockerd", &env) {
        start_dockerd(&dockerd, &env, &signals, &mut children, &mut stopping)?;
    }

    if stopping {
        wind_down(&signals, &mut children, &mut stopping)?;
        return Ok(());
    }

    let program = config.agent.first().context("no agent command")?;
    let program = find_on_path(program, &env)
        .with_context(|| format!("{program} is not on the image's PATH"))?;
    let agent = signals::unblocked(&mut Command::new(&program))
        .args(&config.agent[1..])
        .env_clear()
        .envs(&env)
        .current_dir("/")
        .stdin(Stdio::null())
        .spawn()
        .with_context(|| format!("starting {}", program.display()))?;
    let agent = Pid::from_raw(agent.id() as i32);
    children.agent = Some(agent);
    info!("started {} as {}", config.agent.join(" "), config.hostname);

    let mut agent_signalled = false;
    while children.agent_status.is_none() {
        match signals.wait(None)? {
            Some(Signal::SIGINT | Signal::SIGTERM) if !agent_signalled => {
                info!("asked to stop; the agent finishes its job first");
                let _ = kill(agent, Signal::SIGTERM);
                agent_signalled = true;
            }
            _ => children.reap(),
        }
    }
    let status = exit_status(children.agent_status.take().expect("loop ended on it"));
    wind_down(&signals, &mut children, &mut stopping)?;
    if !status.success() {
        bail!("the agent exited with {status}");
    }
    Ok(())
}
