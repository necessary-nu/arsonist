//! A tar writer emitting ustar headers, with a PAX header in front wherever
//! a value does not fit ustar or the source entry carried PAX records
//! (xattrs such as file capabilities).

use std::io::{self, Read, Write};

const BLOCK: usize = 512;

pub const REGULAR: u8 = b'0';
pub const HARDLINK: u8 = b'1';
pub const SYMLINK: u8 = b'2';
pub const CHAR: u8 = b'3';
pub const BLOCK_DEVICE: u8 = b'4';
pub const DIRECTORY: u8 = b'5';
pub const FIFO: u8 = b'6';

#[derive(Debug, Default)]
pub struct Header<'a> {
    pub path: &'a [u8],
    pub typeflag: u8,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
    pub size: u64,
    pub link: &'a [u8],
    pub uname: &'a [u8],
    pub gname: &'a [u8],
    pub device: (u32, u32),
    /// Carried over as they are, except `path`, `linkpath` and `size`,
    /// which follow the fields above.
    pub pax: &'a [(Vec<u8>, Vec<u8>)],
}

fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
    // "<len> <key>=<value>\n", where <len> counts its own digits.
    let base = key.len() + value.len() + 3;
    let mut len = base + 1;
    while base + len.to_string().len() != len {
        len = base + len.to_string().len();
    }
    let mut out = format!("{len} ").into_bytes();
    out.extend_from_slice(key);
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

/// Write `value` as zero-padded octal filling `field` but its last byte.
/// Returns false, leaving zeros, if it does not fit.
fn octal(field: &mut [u8], value: u64) -> bool {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    if text.len() > digits {
        field[..digits].fill(b'0');
        return false;
    }
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
    true
}

fn copy_truncated(field: &mut [u8], value: &[u8]) {
    let n = value.len().min(field.len());
    field[..n].copy_from_slice(&value[..n]);
}

pub struct TarWriter<W: Write> {
    out: W,
}

impl<W: Write> TarWriter<W> {
    pub fn new(out: W) -> Self {
        TarWriter { out }
    }

    fn pad(&mut self, len: u64) -> io::Result<()> {
        let rem = (len % BLOCK as u64) as usize;
        if rem != 0 {
            self.out.write_all(&[0; BLOCK][..BLOCK - rem])?;
        }
        Ok(())
    }

    fn header_block(
        &mut self,
        h: &Header,
        pax_needed: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        copy_truncated(&mut b[0..100], h.path);
        if h.path.len() > 100 {
            pax_needed.push((b"path".to_vec(), h.path.to_vec()));
        }
        octal(&mut b[100..108], u64::from(h.mode & 0o7777));
        let has = |key: &[u8]| h.pax.iter().any(|(k, _)| k == key);
        if !octal(&mut b[108..116], h.uid) && !has(b"uid") {
            pax_needed.push((b"uid".to_vec(), h.uid.to_string().into_bytes()));
        }
        if !octal(&mut b[116..124], h.gid) && !has(b"gid") {
            pax_needed.push((b"gid".to_vec(), h.gid.to_string().into_bytes()));
        }
        if !octal(&mut b[124..136], h.size) {
            pax_needed.push((b"size".to_vec(), h.size.to_string().into_bytes()));
        }
        if !octal(&mut b[136..148], h.mtime) && !has(b"mtime") {
            pax_needed.push((b"mtime".to_vec(), h.mtime.to_string().into_bytes()));
        }
        b[156] = h.typeflag;
        copy_truncated(&mut b[157..257], h.link);
        if h.link.len() > 100 {
            pax_needed.push((b"linkpath".to_vec(), h.link.to_vec()));
        }
        b[257..263].copy_from_slice(b"ustar\0");
        b[263..265].copy_from_slice(b"00");
        copy_truncated(&mut b[265..296], h.uname);
        copy_truncated(&mut b[297..328], h.gname);
        octal(&mut b[329..337], u64::from(h.device.0));
        octal(&mut b[337..345], u64::from(h.device.1));
        b
    }

    fn write_block(&mut self, mut b: [u8; BLOCK]) -> io::Result<()> {
        b[148..156].fill(b' ');
        let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
        let text = format!("{sum:06o}\0 ");
        b[148..156].copy_from_slice(text.as_bytes());
        self.out.write_all(&b)
    }

    /// Append one entry. `data` must hold exactly `h.size` bytes.
    pub fn append(&mut self, h: &Header, data: &mut dyn Read) -> io::Result<()> {
        let mut extra = vec![];
        let block = self.header_block(h, &mut extra);
        let mut records = vec![];
        for (k, v) in h.pax.iter().chain(&extra) {
            records.extend(pax_record(k, v));
        }
        if !records.is_empty() {
            let pax_header = Header {
                path: b"././@PaxHeader",
                typeflag: b'x',
                mode: 0o644,
                size: records.len() as u64,
                ..Header::default()
            };
            let pax_block = self.header_block(&pax_header, &mut vec![]);
            self.write_block(pax_block)?;
            self.out.write_all(&records)?;
            self.pad(records.len() as u64)?;
        }
        self.write_block(block)?;
        let copied = io::copy(&mut data.take(h.size), &mut self.out)?;
        if copied != h.size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "{}: {copied} of {} bytes",
                    String::from_utf8_lossy(h.path),
                    h.size
                ),
            ));
        }
        self.pad(h.size)
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.out.write_all(&[0; BLOCK * 2])?;
        self.out.flush()?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pax_record_lengths_count_themselves() {
        assert_eq!(pax_record(b"path", b"a"), b"9 path=a\n");
        for n in 0..1100 {
            let r = pax_record(b"k", &vec![b'v'; n]);
            let space = r.iter().position(|&b| b == b' ').unwrap();
            let len: usize = std::str::from_utf8(&r[..space]).unwrap().parse().unwrap();
            assert_eq!(len, r.len(), "value of {n} bytes");
        }
    }

    #[test]
    fn what_ustar_cannot_hold_goes_into_pax() {
        let long_path = "d/".repeat(70) + "file";
        let xattrs = vec![(
            b"SCHILY.xattr.security.capability".to_vec(),
            vec![1, 0, 0, 2],
        )];
        let mut w = TarWriter::new(vec![]);
        w.append(
            &Header {
                path: long_path.as_bytes(),
                typeflag: REGULAR,
                mode: 0o4755,
                uid: 3_000_000,
                size: 5,
                pax: &xattrs,
                ..Header::default()
            },
            &mut &b"hello"[..],
        )
        .unwrap();
        w.append(
            &Header {
                path: b"link",
                typeflag: SYMLINK,
                mode: 0o777,
                link: b"d/d/file",
                ..Header::default()
            },
            &mut io::empty(),
        )
        .unwrap();
        let bytes = w.finish().unwrap();

        let mut archive = tar::Archive::new(&bytes[..]);
        let mut entries = archive.entries().unwrap();
        let mut first = entries.next().unwrap().unwrap();
        assert_eq!(first.path_bytes().as_ref(), long_path.as_bytes());
        assert_eq!(first.header().uid().unwrap(), 3_000_000);
        assert_eq!(first.header().mode().unwrap(), 0o4755);
        let pax: Vec<_> = first
            .pax_extensions()
            .unwrap()
            .unwrap()
            .map(|e| e.unwrap().key().unwrap().to_string())
            .collect();
        assert!(pax.contains(&"SCHILY.xattr.security.capability".to_string()));
        let mut body = String::new();
        first.read_to_string(&mut body).unwrap();
        assert_eq!(body, "hello");
        let second = entries.next().unwrap().unwrap();
        assert_eq!(second.link_name_bytes().unwrap().as_ref(), b"d/d/file");
        assert!(entries.next().is_none());
    }
}
