//! The guest boots this binary as its init from an initramfs that holds
//! nothing else, so it must not need a dynamic loader or libc.

use anyhow::{Result, bail};

const PT_INTERP: u32 = 3;

/// Whether a 64-bit little-endian ELF executable names a dynamic loader.
pub fn needs_interpreter(elf: &[u8]) -> Result<bool> {
    if elf.len() < 64 || &elf[..4] != b"\x7fELF" || elf[4] != 2 || elf[5] != 1 {
        bail!("not a 64-bit little-endian ELF file");
    }
    let u16_at = |o: usize| u16::from_le_bytes([elf[o], elf[o + 1]]) as usize;
    let phoff = u64::from_le_bytes(elf[0x20..0x28].try_into().expect("8 bytes")) as usize;
    let phentsize = u16_at(0x36);
    let phnum = u16_at(0x38);
    for i in 0..phnum {
        let at = phoff + i * phentsize;
        let Some(ph) = elf.get(at..at + 4) else {
            bail!("program header {i} is past the end of the file");
        };
        if u32::from_le_bytes(ph.try_into().expect("4 bytes")) == PT_INTERP {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn check_static(elf: &[u8]) -> Result<()> {
    if needs_interpreter(elf)? {
        bail!(
            "this arsonist is dynamically linked, so it cannot be a guest's init; \
             use a static build (x86_64-unknown-linux-musl), as the releases are"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_binary_itself_is_read() {
        let me = std::fs::read("/proc/self/exe").unwrap();
        let dynamic = needs_interpreter(&me).unwrap();
        assert_eq!(dynamic, cfg!(target_env = "gnu"));
    }

    #[test]
    fn non_elf_is_refused() {
        assert!(needs_interpreter(b"#!/bin/sh\n").is_err());
    }
}
