//! Write a guest's initramfs the way a slot does, for booting a guest
//! outside Firecracker, as scripts/qemu-boot.sh does.
//!
//! cargo run --example initramfs -- <static arsonist> <guest-config.json> <out.cpio> [host files...]

use std::fs::{self, File};
use std::io::BufWriter;
use std::path::Path;

use anyhow::{Result, bail};
use arsonist::protocol::GuestConfig;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [init, config, out, files @ ..] = args.as_slice() else {
        bail!("usage: initramfs <static arsonist> <guest-config.json> <out.cpio> [host files...]");
    };
    let init = fs::read(init)?;
    arsonist::elf::check_static(&init)?;
    let config: GuestConfig = serde_json::from_slice(&fs::read(config)?)?;
    let files: Vec<&Path> = files.iter().map(Path::new).collect();
    arsonist::initramfs::write(BufWriter::new(File::create(out)?), &init, &config, &files)
}
