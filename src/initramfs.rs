//! Each boot's initramfs: this very binary as `/init`, plus the boot's
//! config and shared files. The guest kernel needs no compression support
//! for it, and nothing in the image has to know about arsonist.

use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};

use crate::protocol::{GuestConfig, INITRAMFS_CONFIG, INITRAMFS_DIR};

const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;

/// A `newc` cpio archive, the format the kernel unpacks an initramfs from.
pub struct Cpio<W: Write> {
    out: W,
    written: u64,
    next_ino: u32,
}

impl<W: Write> Cpio<W> {
    pub fn new(out: W) -> Self {
        Cpio {
            out,
            written: 0,
            next_ino: 1,
        }
    }

    fn put(&mut self, data: &[u8]) -> io::Result<()> {
        self.out.write_all(data)?;
        self.written += data.len() as u64;
        Ok(())
    }

    fn pad(&mut self) -> io::Result<()> {
        let n = (4 - (self.written % 4) as usize) % 4;
        self.put(&[0; 3][..n])
    }

    fn entry(
        &mut self,
        name: &str,
        mode: u32,
        mtime: u32,
        rdev: (u32, u32),
        data: &[u8],
    ) -> io::Result<()> {
        let ino = self.next_ino;
        self.next_ino += 1;
        let nlink = if mode & 0o170000 == S_IFDIR { 2 } else { 1 };
        let header = format!(
            "070701{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{size:08x}{maj:08x}{min:08x}{rmaj:08x}{rmin:08x}{namesize:08x}{check:08x}",
            uid = 0,
            gid = 0,
            size = data.len(),
            maj = 0,
            min = 0,
            rmaj = rdev.0,
            rmin = rdev.1,
            namesize = name.len() + 1,
            check = 0,
        );
        self.put(header.as_bytes())?;
        self.put(name.as_bytes())?;
        self.put(&[0])?;
        self.pad()?;
        self.put(data)?;
        self.pad()
    }

    pub fn dir(&mut self, name: &str, perm: u32) -> io::Result<()> {
        self.entry(name, S_IFDIR | perm, 0, (0, 0), &[])
    }

    pub fn file(&mut self, name: &str, perm: u32, data: &[u8]) -> io::Result<()> {
        self.entry(name, S_IFREG | perm, 0, (0, 0), data)
    }

    pub fn char_device(&mut self, name: &str, perm: u32, major: u32, minor: u32) -> io::Result<()> {
        self.entry(name, S_IFCHR | perm, 0, (major, minor), &[])
    }

    /// Copy a host file or directory tree in as `name`, keeping permissions
    /// and symlinks. Everything is owned by root.
    pub fn copy_from_host(&mut self, host: &Path, name: &str) -> Result<()> {
        let meta =
            std::fs::symlink_metadata(host).with_context(|| format!("{}", host.display()))?;
        let perm = meta.permissions().mode() & 0o7777;
        let mtime = meta.mtime().clamp(0, u32::MAX as i64) as u32;
        let ft = meta.file_type();
        if ft.is_symlink() {
            let target = std::fs::read_link(host)?;
            self.entry(
                name,
                S_IFLNK | 0o777,
                mtime,
                (0, 0),
                target.as_os_str().as_encoded_bytes(),
            )?;
        } else if ft.is_dir() {
            self.entry(name, S_IFDIR | perm, mtime, (0, 0), &[])?;
            let mut children: Vec<_> = std::fs::read_dir(host)
                .with_context(|| format!("{}", host.display()))?
                .collect::<io::Result<_>>()?;
            children.sort_by_key(|e| e.file_name());
            for child in children {
                let child_name = child.file_name();
                let child_name = child_name.to_str().with_context(|| {
                    format!("{}: a name that is not UTF-8", child.path().display())
                })?;
                self.copy_from_host(&child.path(), &format!("{name}/{child_name}"))?;
            }
        } else if ft.is_file() {
            let data = std::fs::read(host).with_context(|| format!("{}", host.display()))?;
            self.entry(name, S_IFREG | perm, mtime, (0, 0), &data)?;
        } else {
            crate::warn!(
                "{}: not a file, directory or symlink; left out of the guest",
                host.display()
            );
        }
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.entry("TRAILER!!!", 0, 0, (0, 0), &[])?;
        self.out.flush()?;
        Ok(self.out)
    }
}

/// The whole initramfs for one boot.
pub fn write(out: impl Write, init: &[u8], config: &GuestConfig, files: &[&Path]) -> Result<()> {
    let mut cpio = Cpio::new(out);
    cpio.dir("dev", 0o755)?;
    // The kernel opens it for init's stdin, stdout and stderr before devtmpfs
    // is mounted.
    cpio.char_device("dev/console", 0o600, 5, 1)?;
    cpio.file("init", 0o755, init)?;
    cpio.dir(INITRAMFS_DIR, 0o700)?;
    cpio.file(INITRAMFS_CONFIG, 0o600, &serde_json::to_vec(config)?)?;
    cpio.dir(&format!("{INITRAMFS_DIR}/files"), 0o700)?;
    for (i, host) in files.iter().enumerate() {
        cpio.copy_from_host(host, &format!("{INITRAMFS_DIR}/files/{i}"))?;
    }
    cpio.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (name, mode, rdev major, rdev minor, data) for each entry.
    fn parse(mut data: &[u8]) -> Vec<(String, u32, u32, u32, Vec<u8>)> {
        let mut out = vec![];
        let mut offset = 0usize;
        let field = |h: &[u8], i: usize| {
            u32::from_str_radix(std::str::from_utf8(&h[6 + i * 8..14 + i * 8]).unwrap(), 16)
                .unwrap()
        };
        loop {
            assert_eq!(&data[..6], b"070701", "at {offset}");
            let h = &data[..110];
            let mode = field(h, 1);
            let size = field(h, 6) as usize;
            let rmaj = field(h, 9);
            let rmin = field(h, 10);
            let namesize = field(h, 11) as usize;
            let name = std::str::from_utf8(&data[110..110 + namesize - 1])
                .unwrap()
                .to_string();
            let data_start = (110 + namesize).next_multiple_of(4);
            let body = data[data_start..data_start + size].to_vec();
            let next = (data_start + size).next_multiple_of(4);
            offset += next;
            data = &data[next..];
            if name == "TRAILER!!!" {
                assert!(data.is_empty());
                return out;
            }
            out.push((name, mode, rmaj, rmin, body));
        }
    }

    #[test]
    fn the_archive_is_newc_with_everything_aligned() {
        let mut buf = vec![];
        let mut cpio = Cpio::new(&mut buf);
        cpio.dir("dev", 0o755).unwrap();
        cpio.char_device("dev/console", 0o600, 5, 1).unwrap();
        cpio.file("init", 0o755, b"\x7fELF...").unwrap();
        cpio.finish().unwrap();
        assert_eq!(buf.len() % 4, 0);
        let entries = parse(&buf);
        assert_eq!(
            entries,
            [
                ("dev".into(), 0o040755, 0, 0, vec![]),
                ("dev/console".into(), 0o020600, 5, 1, vec![]),
                ("init".into(), 0o100755, 0, 0, b"\x7fELF...".to_vec()),
            ]
        );
    }

    #[test]
    fn host_trees_come_in_whole() {
        let dir = std::env::temp_dir().join(format!("arsonist-cpio-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("hooks/sub")).unwrap();
        std::fs::write(dir.join("hooks/environment"), "export A=1\n").unwrap();
        std::fs::set_permissions(
            dir.join("hooks/environment"),
            std::fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        std::os::unix::fs::symlink("environment", dir.join("hooks/env-link")).unwrap();

        let mut buf = vec![];
        let mut cpio = Cpio::new(&mut buf);
        cpio.copy_from_host(&dir.join("hooks"), "arsonist/files/0")
            .unwrap();
        cpio.finish().unwrap();
        let entries: Vec<_> = parse(&buf)
            .into_iter()
            .map(|(n, m, _, _, d)| (n, m, d))
            .collect();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(entries[0].0, "arsonist/files/0");
        assert_eq!(entries[0].1 & 0o170000, S_IFDIR);
        assert_eq!(
            entries[1],
            (
                "arsonist/files/0/env-link".into(),
                S_IFLNK | 0o777,
                b"environment".to_vec()
            )
        );
        assert_eq!(
            entries[2],
            (
                "arsonist/files/0/environment".into(),
                S_IFREG | 0o750,
                b"export A=1\n".to_vec()
            )
        );
        assert_eq!(entries[3].0, "arsonist/files/0/sub");
    }
}
