//! Signals as events to wait for, with a timeout, on a signalfd. Used by
//! the slot loop on the host and by init in the guest, both single-threaded.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};

pub struct Signals {
    fd: SignalFd,
}

impl Signals {
    /// Block `signals` for this thread and the threads it starts, so they
    /// arrive here. Start children through [`unblocked`], or they inherit
    /// the mask too.
    pub fn block(signals: &[Signal]) -> Result<Signals> {
        let mut set = SigSet::empty();
        for &s in signals {
            set.add(s);
        }
        set.thread_block().context("blocking signals")?;
        let fd = SignalFd::with_flags(&set, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)
            .context("creating a signalfd")?;
        Ok(Signals { fd })
    }

    fn take(&self) -> Result<Option<Signal>> {
        match self.fd.read_signal() {
            Ok(Some(info)) => Ok(Signal::try_from(info.ssi_signo as i32).ok()),
            Ok(None) => Ok(None),
            Err(e) => Err(e).context("reading the signalfd"),
        }
    }

    /// The next signal, or None once `timeout` passes. No timeout waits for
    /// as long as it takes.
    pub fn wait(&self, timeout: Option<Duration>) -> Result<Option<Signal>> {
        if let Some(s) = self.take()? {
            return Ok(Some(s));
        }
        let timeout = match timeout {
            None => PollTimeout::NONE,
            Some(d) => PollTimeout::try_from(d).unwrap_or(PollTimeout::MAX),
        };
        let mut fds = [PollFd::new(self.fd.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, timeout) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(e) => return Err(e).context("waiting for signals"),
        }
        self.take()
    }
}

/// A child inherits its parent's signal mask, and std's `Command` leaves it
/// as it is, so a child started after [`Signals::block`] would never see
/// those signals: an agent would ignore the SIGTERM that lets it finish.
pub fn unblocked(cmd: &mut Command) -> &mut Command {
    // SAFETY: sigprocmask is async-signal-safe, so fine between fork and exec.
    unsafe { cmd.pre_exec(|| SigSet::empty().thread_set_mask().map_err(io::Error::from)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked_in_child(cmd: &mut Command) -> String {
        let out = cmd
            .args(["-E", "^SigBlk", "/proc/self/status"])
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn children_start_with_nothing_blocked() {
        let _signals = Signals::block(&[Signal::SIGUSR2]).unwrap();
        assert_ne!(
            blocked_in_child(&mut Command::new("grep")),
            "SigBlk:\t0000000000000000",
            "std's Command now resets the mask itself; unblocked() can go"
        );
        assert_eq!(
            blocked_in_child(unblocked(&mut Command::new("grep"))),
            "SigBlk:\t0000000000000000"
        );
    }
}
