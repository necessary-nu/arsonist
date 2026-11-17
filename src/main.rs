use std::fs::File;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

use arsonist::config::{Config, DEFAULT_CONFIG_PATH, Images};
use arsonist::{error, guest, host, images, log, net, slot, systemd};

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

fn auth_file(config_path: &Path) -> PathBuf {
    Config::load(config_path)
        .map(|c| c.images.auth_file)
        .unwrap_or_else(|_| Images::default().auth_file)
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Setup => host::setup(&cli.config),
        Command::Install => systemd::install(&Config::load(&cli.config)?),
        Command::Status => host::status(&Config::load(&cli.config)?),
        Command::Images(ImagesCommand::Update) => images::update_all(&Config::load(&cli.config)?),
        Command::Images(ImagesCommand::Export { image, output }) => {
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
        Command::Slot(SlotCommand::Run { slot }) => {
            let config = Config::load(&cli.config)?;
            let slot = config.find_slot(&slot)?.clone();
            slot::run(&config, &slot)
        }
        Command::Slot(SlotCommand::ResetCache { slot }) => {
            let config = Config::load(&cli.config)?;
            slot::reset_cache(&config, config.find_slot(&slot)?)
        }
        Command::Auth(AuthCommand::Login { registry, username }) => {
            host::login(&auth_file(&cli.config), &registry, &username)
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
