//! Running the external tools arsonist still leans on: e2fsprogs,
//! erofs-utils, iproute2, nftables and systemctl.

use std::ffi::OsStr;
use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

pub struct Output {
    pub code: i32,
    pub stdout: String,
}

pub struct Cmd {
    command: Command,
    display: String,
    ok_codes: Vec<i32>,
    stdin: Option<Vec<u8>>,
}

impl Cmd {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        let display = program.as_ref().to_string_lossy().into_owned();
        let mut command = Command::new(program);
        crate::signals::unblocked(&mut command);
        Cmd {
            command,
            display,
            ok_codes: vec![0],
            stdin: None,
        }
    }

    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.display.push(' ');
        self.display.push_str(&arg.as_ref().to_string_lossy());
        self.command.arg(arg);
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self = self.arg(arg);
        }
        self
    }

    /// Exit codes besides 0 that are not a failure.
    pub fn ok_codes(mut self, codes: &[i32]) -> Self {
        self.ok_codes.extend_from_slice(codes);
        self
    }

    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    pub fn run(mut self) -> Result<Output> {
        self.command
            .stdin(if self.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = self
            .command
            .spawn()
            .with_context(|| format!("could not run {}", self.display))?;
        if let Some(data) = self.stdin.take() {
            let mut stdin = child.stdin.take().expect("stdin is piped");
            stdin
                .write_all(&data)
                .with_context(|| format!("writing to {}", self.display))?;
        }
        let out = child
            .wait_with_output()
            .with_context(|| format!("waiting for {}", self.display))?;
        let code = out.status.code().unwrap_or(-1);
        if !self.ok_codes.contains(&code) {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let detail = if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            };
            bail!("{} exited with {}: {}", self.display, out.status, detail);
        }
        Ok(Output {
            code,
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        })
    }

    /// Whether it exits 0. Not being able to run it at all counts as no.
    pub fn succeeds(mut self) -> bool {
        self.command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}
