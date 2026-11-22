//! Log lines on stderr. Under systemd (and in a guest, whose console ends up
//! in the slot unit's journal) each line carries the `<N>` priority prefix
//! journald reads, so `journalctl -p warning` finds problems.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

static PRIORITY_PREFIX: AtomicBool = AtomicBool::new(false);

pub fn init() {
    PRIORITY_PREFIX.store(
        std::env::var_os("JOURNAL_STREAM").is_some(),
        Ordering::Relaxed,
    );
    if ::log::set_logger(&Bridge).is_ok() {
        ::log::set_max_level(::log::LevelFilter::Info);
    }
}

/// The ssh agent's log lines, written as arsonist's own. ssh-agent-lib's
/// are left out: it logs every request it refuses as an error, and the
/// agent logs its own failures.
struct Bridge;

impl ::log::Log for Bridge {
    fn enabled(&self, metadata: &::log::Metadata) -> bool {
        metadata.target().starts_with("bao_ssh_agent")
    }

    fn log(&self, record: &::log::Record) {
        if self.enabled(record.metadata()) {
            let priority = match record.level() {
                ::log::Level::Error => 3,
                ::log::Level::Warn => 4,
                _ => 6,
            };
            write(priority, *record.args());
        }
    }

    fn flush(&self) {}
}

pub fn init_guest() {
    PRIORITY_PREFIX.store(true, Ordering::Relaxed);
}

#[doc(hidden)]
pub fn write(priority: u8, args: fmt::Arguments) {
    if PRIORITY_PREFIX.load(Ordering::Relaxed) {
        eprintln!("<{priority}>arsonist: {args}");
    } else {
        let label = match priority {
            0..=3 => "error: ",
            4 => "warning: ",
            _ => "",
        };
        eprintln!("{label}{args}");
    }
}

#[macro_export]
macro_rules! error {
    ($($t:tt)*) => { $crate::log::write(3, format_args!($($t)*)) };
}

#[macro_export]
macro_rules! warn {
    ($($t:tt)*) => { $crate::log::write(4, format_args!($($t)*)) };
}

#[macro_export]
macro_rules! info {
    ($($t:tt)*) => { $crate::log::write(6, format_args!($($t)*)) };
}
