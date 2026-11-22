use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::{Level, LevelFilter, Log, Metadata, Record};

use bao_ssh_agent::{Agent, Login, OpenBao, Transit, public_key};

/// An ssh agent whose one key stays in OpenBao's transit engine.
///
/// It logs in with an AppRole (--approle-file), or else with the token in
/// BAO_TOKEN.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// OpenBao's address, such as https://vault.example.
    #[arg(long, env = "BAO_ADDR")]
    address: String,
    /// The transit key, an Ed25519 key.
    #[arg(long, env = "BAO_SSH_AGENT_KEY")]
    key: String,
    #[arg(long, default_value = "transit")]
    transit_mount: String,
    /// A file holding {"role_id": "…", "secret_id": "…"}.
    #[arg(long, env = "BAO_SSH_AGENT_APPROLE_FILE")]
    approle_file: Option<PathBuf>,
    #[arg(long, default_value = "approle")]
    approle_mount: String,
    /// Log every request, ssh-agent-lib's messages included.
    #[arg(short, long)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// The key as an authorized_keys line, to register with a git host.
    PublicKey,
    /// Answer as an ssh agent until interrupted.
    Serve {
        /// The socket to listen at, for SSH_AUTH_SOCK.
        #[cfg(unix)]
        #[arg(long)]
        socket: PathBuf,
        /// The named pipe to listen at; Windows' OpenSSH looks for its own.
        #[cfg(windows)]
        #[arg(long, default_value = r"\\.\pipe\openssh-ssh-agent")]
        pipe: String,
    },
}

struct Stderr {
    verbose: bool,
}

impl Log for Stderr {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // ssh-agent-lib logs every refused request as an error; this crate
        // logs its own failures.
        self.verbose || metadata.target().starts_with("bao_ssh_agent")
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            match record.level() {
                Level::Error => eprintln!("error: {}", record.args()),
                Level::Warn => eprintln!("warning: {}", record.args()),
                _ => eprintln!("{}", record.args()),
            }
        }
    }

    fn flush(&self) {}
}

fn transit(cli: &Cli) -> Result<Transit> {
    let login = match &cli.approle_file {
        Some(file) => Login::AppRole {
            mount: cli.approle_mount.clone(),
            file: file.clone(),
        },
        None => Login::Token(
            std::env::var("BAO_TOKEN").context("no --approle-file, and no token in BAO_TOKEN")?,
        ),
    };
    Ok(Transit::new(
        OpenBao::new(&cli.address, login)?,
        &cli.transit_mount,
        &cli.key,
    ))
}

fn run(cli: Cli) -> Result<()> {
    let transit = Arc::new(transit(&cli)?);
    match cli.command {
        Command::PublicKey => {
            println!("{}", public_key(&*transit)?);
            Ok(())
        }
        #[cfg(unix)]
        Command::Serve { socket } => {
            let agent = Agent::new(transit, "bao-ssh-agent");
            tokio::runtime::Runtime::new()?.block_on(async {
                log::info!("listening at {}", socket.display());
                let served = tokio::select! {
                    served = bao_ssh_agent::agent::serve_unix(&socket, agent) => served,
                    _ = tokio::signal::ctrl_c() => Ok(()),
                };
                let _ = std::fs::remove_file(&socket);
                served
            })
        }
        #[cfg(windows)]
        Command::Serve { pipe } => {
            let agent = Agent::new(transit, "bao-ssh-agent");
            tokio::runtime::Runtime::new()?.block_on(async {
                log::info!("listening at {pipe}");
                tokio::select! {
                    served = bao_ssh_agent::agent::serve_pipe(&pipe, agent) => served,
                    _ = tokio::signal::ctrl_c() => Ok(()),
                }
            })
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let verbose = cli.verbose;
    log::set_logger(Box::leak(Box::new(Stderr { verbose }))).expect("the only logger");
    log::set_max_level(if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    });
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
