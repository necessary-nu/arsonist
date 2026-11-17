//! The systemd units that run arsonist on a host.

use std::fs;
use std::path::Path;

use anyhow::Result;

use crate::cmd::Cmd;
use crate::config::Config;
use crate::info;

const UNIT_DIR: &str = "/etc/systemd/system";
const WANTS_DIR: &str = "/etc/systemd/system/multi-user.target.wants";
const NETWORK_UNIT: &str = "arsonist-network.service";
const IMAGES_UNIT: &str = "arsonist-images.service";
const IMAGES_TIMER: &str = "arsonist-images.timer";

pub fn slot_unit(slot: &str) -> String {
    format!("arsonist@{slot}.service")
}

pub fn render_units(exe: &Path, config: &Path) -> Vec<(&'static str, String)> {
    let run = |args: &str| format!("{} --config {} {args}", exe.display(), config.display());
    let header = "# Written by `arsonist install`; run it again after changing the config.\n";
    vec![
        (
            NETWORK_UNIT,
            format!(
                "{header}
[Unit]
Description=arsonist: host networking for the microVMs
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={}
ExecStop={}

[Install]
WantedBy=multi-user.target
",
                run("network up"),
                run("network down")
            ),
        ),
        (
            "arsonist@.service",
            format!(
                "{header}
[Unit]
Description=arsonist: Buildkite microVM slot %i
Requires={NETWORK_UNIT}
After={NETWORK_UNIT}

[Service]
ExecStart={}
Restart=always
RestartSec=10
# SIGTERM to arsonist alone: it asks the guest to finish its job and shut
# down, which can take as long as the job does.
KillMode=mixed
TimeoutStopSec=infinity

[Install]
WantedBy=multi-user.target
",
                run("slot run %i")
            ),
        ),
        (
            IMAGES_UNIT,
            format!(
                "{header}
[Unit]
Description=arsonist: convert new kernel and image releases for the microVMs
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart={}
",
                run("images update")
            ),
        ),
        (
            IMAGES_TIMER,
            format!(
                "{header}
[Unit]
Description=arsonist: look for new kernel and image releases

[Timer]
OnBootSec=1min
OnUnitInactiveSec=5min

[Install]
WantedBy=timers.target
"
            ),
        ),
    ]
}

fn enabled_slots() -> Result<Vec<String>> {
    let mut slots = vec![];
    let entries = match fs::read_dir(WANTS_DIR) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(slots),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(slot) = name
            .strip_prefix("arsonist@")
            .and_then(|n| n.strip_suffix(".service"))
        {
            slots.push(slot.to_string());
        }
    }
    Ok(slots)
}

/// Write the units, then make the enabled slots exactly the configured
/// ones. Slots that went away stop without waiting here, since a graceful
/// stop lasts as long as the job in it.
pub fn install(config: &Config) -> Result<()> {
    let exe = std::env::current_exe()?;
    let config_path = fs::canonicalize(&config.path)?;
    for (name, text) in render_units(&exe, &config_path) {
        let path = Path::new(UNIT_DIR).join(name);
        fs::write(&path, text)?;
        info!("wrote {}", path.display());
    }
    Cmd::new("systemctl").arg("daemon-reload").run()?;
    Cmd::new("systemctl")
        .args(["enable", "--now", NETWORK_UNIT, IMAGES_TIMER])
        .run()?;
    Cmd::new("systemctl")
        .args(["start", "--no-block", IMAGES_UNIT])
        .run()?;

    for name in enabled_slots()? {
        if !config.slots.iter().any(|s| s.name == name) {
            info!("removing slot {name} once its job finishes");
            Cmd::new("systemctl")
                .args(["disable", "--now", "--no-block"])
                .arg(slot_unit(&name))
                .run()?;
        }
    }
    for slot in &config.slots {
        Cmd::new("systemctl")
            .args(["enable", "--now", "--no-block"])
            .arg(slot_unit(&slot.name))
            .run()?;
    }
    let names: Vec<_> = config.slots.iter().map(|s| s.name.as_str()).collect();
    info!("enabled {} slot(s): {}", names.len(), names.join(", "));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_run_this_binary_with_the_hosts_config() {
        let units = render_units(
            Path::new("/usr/local/bin/arsonist"),
            Path::new("/etc/arsonist/config.toml"),
        );
        let names: Vec<_> = units.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            [
                "arsonist-network.service",
                "arsonist@.service",
                "arsonist-images.service",
                "arsonist-images.timer"
            ]
        );
        let slot = &units[1].1;
        assert!(slot.contains(
            "ExecStart=/usr/local/bin/arsonist --config /etc/arsonist/config.toml slot run %i\n"
        ));
        assert!(slot.contains("TimeoutStopSec=infinity"));
        assert!(slot.contains("KillMode=mixed"));
    }
}
