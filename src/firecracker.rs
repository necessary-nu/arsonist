//! Firecracker itself: installing the pinned release, and its API.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::info;
use crate::registry::sha256_hex;

pub const VERSION: &str = "v1.17.0";
const SHA256: &str = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558";
const ARCH: &str = "x86_64";

/// Ask the guest to finish up, as Ctrl-Alt-Del on its keyboard. True if
/// Firecracker took the request.
pub fn send_ctrl_alt_del(api_socket: &Path) -> bool {
    let attempt = || -> std::io::Result<bool> {
        let mut s = UnixStream::connect(api_socket)?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        s.set_write_timeout(Some(Duration::from_secs(5)))?;
        let body = r#"{"action_type":"SendCtrlAltDel"}"#;
        write!(
            s,
            "PUT /actions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        let mut status = [0u8; 12];
        s.read_exact(&mut status)?;
        Ok(status.starts_with(b"HTTP/1.1 2"))
    };
    attempt().unwrap_or(false)
}

fn installed_version(bin: &Path) -> Option<String> {
    let out = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn install(bin_dir: &Path) -> Result<()> {
    if installed_version(&bin_dir.join("firecracker")).is_some_and(|v| v.contains(VERSION)) {
        info!("Firecracker {VERSION} is already installed");
        return Ok(());
    }
    let url = format!(
        "https://github.com/firecracker-microvm/firecracker/releases/download/{VERSION}/firecracker-{VERSION}-{ARCH}.tgz"
    );
    info!("downloading {url}");
    let mut resp = ureq::get(&url)
        .call()
        .with_context(|| format!("GET {url}"))?;
    let data = resp
        .body_mut()
        .with_config()
        .limit(256 << 20)
        .read_to_vec()?;
    let actual = sha256_hex(&data);
    if actual != SHA256 {
        bail!("{url}: sha256 is {actual}, arsonist pins {SHA256}");
    }
    let dir = format!("release-{VERSION}-{ARCH}");
    let wanted = [
        (format!("{dir}/firecracker-{VERSION}-{ARCH}"), "firecracker"),
        (format!("{dir}/jailer-{VERSION}-{ARCH}"), "jailer"),
    ];
    let mut found = 0;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&data[..]));
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        let Some((_, name)) = wanted.iter().find(|(p, _)| *p == path) else {
            continue;
        };
        let dest = bin_dir.join(name);
        let tmp = bin_dir.join(format!(".{name}.new"));
        let mut out = fs::File::create(&tmp)?;
        std::io::copy(&mut entry, &mut out)?;
        drop(out);
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
        fs::rename(&tmp, &dest)?;
        info!("installed {}", dest.display());
        found += 1;
    }
    if found != wanted.len() {
        bail!("{url} does not hold firecracker and jailer where expected");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernel_is_configured_for_the_installed_firecracker() {
        let dockerfile = include_str!("../kernel/Dockerfile");
        let pinned = dockerfile
            .lines()
            .find_map(|l| l.strip_prefix("ARG FIRECRACKER_VERSION="))
            .expect("kernel/Dockerfile pins FIRECRACKER_VERSION");
        assert_eq!(pinned, VERSION);
    }
}
