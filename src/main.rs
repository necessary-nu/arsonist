use std::fs::{self, File};
use std::io::{self, BufWriter};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use arsonist::config::{Config, DEFAULT_CONFIG_PATH, Images};
use arsonist::{error, guest, host, images, info, log, net, slot, systemd};

/// Buildkite agents in single-use Firecracker microVMs, booted from OCI
/// images.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Install Firecracker, the packages arsonist needs, and an example config.
    Setup,
    /// Write the systemd units and enable exactly the configured slots.
    Install,
    /// The converted kernel and images, and each slot's state.
    Status,
    #[command(subcommand)]
    Images(ImagesCommand),
    #[command(subcommand)]
    Network(NetworkCommand),
    #[command(subcommand)]
    Slot(SlotCommand),
    #[command(subcommand)]
    Auth(AuthCommand),
    #[command(subcommand)]
    SshAgent(SshAgentCommand),
}

#[derive(Subcommand)]
enum ImagesCommand {
    /// Convert new releases of the kernel and the pools' images.
    Update,
    /// Write an image's flattened filesystem as a tar, as a guest would see it.
    Export {
        image: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum NetworkCommand {
    /// Enable forwarding and load the NAT and firewall rules.
    Up,
    Down,
}

#[derive(Subcommand)]
enum SlotCommand {
    /// Boot the slot's VM, one job at a time, until stopped.
    Run { slot: String },
    /// Empty the slot's cache disk from its next boot.
    ResetCache { slot: String },
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Save credentials for a registry; the password or token is read from stdin.
    Login {
        registry: String,
        #[arg(short, long)]
        username: String,
    },
}

#[derive(Subcommand)]
enum SshAgentCommand {
    /// The transit key as an authorized_keys line, to register with the git
    /// host.
    PublicKey,
    /// Answer as the guests' agent does, on a unix socket, to try it from
    /// the host: `SSH_AUTH_SOCK=<socket> ssh -T git@github.com`.
    Serve { socket: PathBuf },
}

fn ssh_agent_config(config_path: &Path) -> Result<arsonist::config::SshAgent> {
    Config::load(config_path)?
        .ssh_agent
        .with_context(|| format!("no [ssh_agent] in {}", config_path.display()))
}

fn auth_file(config_path: &Path) -> PathBuf {
    Config::load(config_path)
        .map(|c| c.images.auth_file)
        .unwrap_or_else(|_| Images::default().auth_file)
}

/// For commands whose output is piped into `head` and the like: end quietly
/// when the reader goes away, as Unix tools do, instead of panicking.
fn die_on_broken_pipe() {
    // SAFETY: setting a signal disposition before any threads exist.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Setup => host::setup(&cli.config),
        Command::Install => systemd::install(&Config::load(&cli.config)?),
        Command::Status => {
            die_on_broken_pipe();
            host::status(&Config::load(&cli.config)?)
        }
        Command::Images(ImagesCommand::Update) => images::update_all(&Config::load(&cli.config)?),
        Command::Images(ImagesCommand::Export { image, output }) => {
            die_on_broken_pipe();
            let auth = auth_file(&cli.config);
            match output {
                Some(path) => images::export(&auth, &image, BufWriter::new(File::create(path)?)),
                None => images::export(&auth, &image, BufWriter::new(io::stdout().lock())),
            }
        }
        Command::Network(NetworkCommand::Up) => {
            let network = Config::load(&cli.config)?.network;
            net::network_up(network.subnet, network.uplink.as_deref())
        }
        Command::Network(NetworkCommand::Down) => net::network_down(),
        Command::Slot(SlotCommand::Run { slot }) => slot::run(&cli.config, &slot),
        Command::Slot(SlotCommand::ResetCache { slot }) => {
            let config = Config::load(&cli.config)?;
            slot::reset_cache(&config, config.find_slot(&slot)?)
        }
        Command::Auth(AuthCommand::Login { registry, username }) => {
            host::login(&auth_file(&cli.config), &registry, &username)
        }
        Command::SshAgent(SshAgentCommand::PublicKey) => {
            let transit = ssh_agent_config(&cli.config)?.transit()?;
            println!("{}", bao_ssh_agent::public_key(&transit)?);
            Ok(())
        }
        Command::SshAgent(SshAgentCommand::Serve { socket }) => {
            let transit = Arc::new(ssh_agent_config(&cli.config)?.transit()?);
            let background = bao_ssh_agent::Background::new()?;
            let _ = fs::remove_file(&socket);
            let listener = UnixListener::bind(&socket)
                .with_context(|| format!("listening at {}", socket.display()))?;
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
            let agent = bao_ssh_agent::Agent::new(transit, "ssh-agent");
            let _serving = background.serve(listener, agent)?;
            info!("ssh agent at {}", socket.display());
            loop {
                std::thread::park();
            }
        }
    }
}

fn main() -> ExitCode {
    if std::process::id() == 1 {
        guest::main();
    }
    log::init();
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}
