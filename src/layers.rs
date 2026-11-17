//! Flatten an image's layers into the one tar stream of its final
//! filesystem, which `mkfs.erofs --tar` turns into the guests' root.
//!
//! Two passes over the downloaded layers. The first walks them top layer
//! first, as overlayfs would look them up, and decides for every entry
//! whether it survives: a path is hidden by the same path in a higher layer,
//! by a non-directory or a whiteout at one of its ancestors, or by an opaque
//! directory above it. The second pass writes the survivors base layer
//! first, so parents come before their children.
//!
//! A directory's entry comes from the highest layer that has it, which can
//! be after lower layers' entries inside it. So the second pass writes each
//! entry's missing parents first, with the metadata the first pass kept
//! for them, and skips their own entries when it reaches them.
//!
//! A hard link whose target a higher layer replaced keeps the old contents,
//! as it does on overlayfs. The first pass spots those, and the second
//! writes the target's data under the link's name.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use tar::EntryType;

use crate::tarball::{self, TarWriter};

const WHITEOUT: &[u8] = b".wh.";
const OPAQUE: &[u8] = b".wh..wh..opq";

/// A zstd stream of any number of frames, skippable ones included.
struct Zstd<R: BufRead> {
    source: R,
    decoder: FrameDecoder,
    in_frame: bool,
}

impl<R: BufRead> Read for Zstd<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.in_frame {
                if self.source.fill_buf()?.is_empty() {
                    return Ok(0);
                }
                match self.decoder.reset(&mut self.source) {
                    Ok(()) => self.in_frame = true,
                    Err(FrameDecoderError::ReadFrameHeaderError(
                        ReadFrameHeaderError::SkipFrame { length, .. },
                    )) => {
                        io::copy(
                            &mut (&mut self.source).take(u64::from(length)),
                            &mut io::sink(),
                        )?;
                        continue;
                    }
                    Err(e) => return Err(io::Error::other(e)),
                }
            }
            while self.decoder.can_collect() == 0 && !self.decoder.is_finished() {
                self.decoder
                    .decode_blocks(&mut self.source, BlockDecodingStrategy::UptoBlocks(1))
                    .map_err(io::Error::other)?;
            }
            let n = self.decoder.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            if self.decoder.is_finished() {
                self.in_frame = false;
            }
        }
    }
}

/// A layer blob as its uncompressed tar, whatever it was compressed with.
pub fn open_layer(path: &Path) -> Result<Box<dyn Read>> {
    let mut file = BufReader::with_capacity(
        1 << 20,
        File::open(path).with_context(|| format!("{}", path.display()))?,
    );
    let magic = file.fill_buf()?;
    Ok(if magic.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::bufread::MultiGzDecoder::new(file))
    } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Box::new(Zstd {
            source: file,
            decoder: FrameDecoder::new(),
            in_frame: false,
        })
    } else {
        Box::new(file)
    })
}

/// `./a//b/` → `a/b`. None for paths climbing out with `..`.
fn normalize(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    for part in raw.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => return None,
            part => {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(part);
            }
        }
    }
    Some(out)
}

fn split_parent(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (&[], path),
    }
}

fn show(path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}

/// A directory's metadata, for writing it ahead of its own entry.
#[derive(Debug, Clone)]
struct DirMeta {
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
    uname: Vec<u8>,
    gname: Vec<u8>,
    pax: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Default for DirMeta {
    fn default() -> Self {
        DirMeta {
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
            uname: vec![],
            gname: vec![],
            pax: vec![],
        }
    }
}

/// What the first pass needs of an entry.
enum Info {
    /// Not part of the filesystem: a global PAX header, or the root itself.
    Ignore,
    Whiteout(Vec<u8>),
    Opaque(Vec<u8>),
    Item {
        path: Vec<u8>,
        dir: Option<DirMeta>,
        hardlink: Option<Vec<u8>>,
    },
}

fn read_info(entry: &mut tar::Entry<impl Read>, layer: &Path) -> Result<Info> {
    let raw = entry.path_bytes();
    let path = normalize(&raw)
        .with_context(|| format!("{}: {} leaves the root", layer.display(), show(&raw)))?;
    let kind = entry.header().entry_type();
    match kind {
        EntryType::XGlobalHeader => return Ok(Info::Ignore),
        EntryType::GNUSparse => bail!(
            "{}: {} is a sparse file, which is not supported",
            layer.display(),
            show(&path)
        ),
        EntryType::Regular
        | EntryType::Continuous
        | EntryType::Directory
        | EntryType::Symlink
        | EntryType::Link
        | EntryType::Char
        | EntryType::Block
        | EntryType::Fifo => {}
        other => bail!(
            "{}: {} has unsupported tar type {other:?}",
            layer.display(),
            show(&path)
        ),
    }
    if path.is_empty() {
        return Ok(Info::Ignore);
    }
    let (parent, name) = split_parent(&path);
    if name == OPAQUE {
        return Ok(Info::Opaque(parent.to_vec()));
    }
    if let Some(hidden) = name.strip_prefix(WHITEOUT) {
        if hidden.starts_with(WHITEOUT) {
            // Other AUFS bookkeeping, e.g. .wh..wh.plnk.
            return Ok(Info::Ignore);
        }
        let mut target = parent.to_vec();
        if !target.is_empty() {
            target.push(b'/');
        }
        target.extend_from_slice(hidden);
        return Ok(Info::Whiteout(target));
    }
    let hardlink = if kind == EntryType::Link {
        let raw = entry.link_name_bytes().unwrap_or_default();
        Some(normalize(&raw).with_context(|| {
            format!(
                "{}: hard link {} to {} leaves the root",
                layer.display(),
                show(&path),
                show(&raw)
            )
        })?)
    } else {
        None
    };
    let dir = if kind == EntryType::Directory {
        let h = entry.header().clone();
        Some(DirMeta {
            mode: h.mode()?,
            uid: h.uid()?,
            gid: h.gid()?,
            mtime: h.mtime()?,
            uname: h.username_bytes().unwrap_or_default().to_vec(),
            gname: h.groupname_bytes().unwrap_or_default().to_vec(),
            pax: pax_records(entry)
                .with_context(|| format!("{}: {}", layer.display(), show(&path)))?,
        })
    } else {
        None
    };
    Ok(Info::Item {
        path,
        dir,
        hardlink,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    Skip,
    Emit,
    /// Emit this entry's data under another path: the first surviving hard
    /// link to it, the entry itself being hidden.
    EmitAs(Vec<u8>),
    /// Emit this hard link pointing at another path instead.
    HardlinkTo(Vec<u8>),
}

/// Which entries of which layers make up the final filesystem.
pub struct Plan {
    /// Per layer, base first; per entry, in tar order.
    layers: Vec<Vec<Action>>,
    /// Everything in the final filesystem, implied parents included.
    paths: HashSet<Vec<u8>>,
    /// The surviving entry's metadata for every directory.
    dirs: HashMap<Vec<u8>, DirMeta>,
}

impl Plan {
    /// Whether the final filesystem has anything at `path`.
    pub fn contains(&self, path: &str) -> bool {
        normalize(path.as_bytes()).is_some_and(|p| self.paths.contains(&p))
    }

    pub fn path_count(&self) -> usize {
        self.paths.len()
    }
}

/// What the layers above hide.
#[derive(Default)]
struct Hidden {
    /// Paths a higher layer has; true if what it has there also hides
    /// everything below the path (a non-directory, or a whiteout).
    paths: HashMap<Vec<u8>, bool>,
    /// Directories whose lower contents are hidden.
    opaque: HashSet<Vec<u8>>,
}

impl Hidden {
    fn hides(&self, path: &[u8]) -> bool {
        if self.paths.contains_key(path) || self.opaque.contains(&b""[..]) {
            return true;
        }
        let mut end = path.len();
        while let Some(i) = path[..end].iter().rposition(|&b| b == b'/') {
            let ancestor = &path[..i];
            if self.opaque.contains(ancestor) || self.paths.get(ancestor) == Some(&true) {
                return true;
            }
            end = i;
        }
        false
    }

    fn add(&mut self, path: &[u8], hides_below: bool) {
        *self.paths.entry(path.to_vec()).or_insert(false) |= hides_below;
    }
}

fn plan_layer(infos: &[Info], hidden: &Hidden, layer: &Path) -> Vec<Action> {
    let mut last: HashMap<&[u8], usize> = HashMap::new();
    for (i, info) in infos.iter().enumerate() {
        if let Info::Item { path, .. } = info {
            last.insert(path, i);
        }
    }
    let mut actions: Vec<Action> = infos
        .iter()
        .enumerate()
        .map(|(i, info)| match info {
            Info::Item { path, .. } if last[path.as_slice()] == i && !hidden.hides(path) => {
                Action::Emit
            }
            _ => Action::Skip,
        })
        .collect();

    // Surviving hard links whose target did not survive.
    let mut moved: HashMap<usize, Vec<u8>> = HashMap::new();
    for (i, info) in infos.iter().enumerate() {
        let Info::Item {
            path,
            hardlink: Some(target),
            ..
        } = info
        else {
            continue;
        };
        if actions[i] != Action::Emit {
            continue;
        }
        let target_index = infos[..i]
            .iter()
            .rposition(|t| matches!(t, Info::Item { path: p, .. } if p == target));
        let Some(t) = target_index else {
            crate::warn!(
                "{}: hard link {} points at {}, which is not in the same layer",
                layer.display(),
                show(path),
                show(target)
            );
            continue;
        };
        if actions[t] == Action::Emit {
            continue;
        }
        if let Some(first) = moved.get(&t) {
            actions[i] = Action::HardlinkTo(first.clone());
        } else if actions[t] == Action::Skip {
            actions[t] = Action::EmitAs(path.clone());
            actions[i] = Action::Skip;
            moved.insert(t, path.clone());
        }
    }
    actions
}

fn entries_of(layer: &Path) -> Result<tar::Archive<Box<dyn Read>>> {
    Ok(tar::Archive::new(open_layer(layer)?))
}

/// The first pass. `layers` are the blobs, base layer first.
pub fn plan(layers: &[PathBuf]) -> Result<Plan> {
    let mut hidden = Hidden::default();
    let mut per_layer = vec![];
    let mut paths = HashSet::new();
    let mut dirs = HashMap::new();
    for layer in layers.iter().rev() {
        let mut archive = entries_of(layer)?;
        let mut infos = vec![];
        for entry in archive
            .entries()
            .with_context(|| format!("{}", layer.display()))?
        {
            let mut entry = entry.with_context(|| format!("reading {}", layer.display()))?;
            infos.push(read_info(&mut entry, layer)?);
        }
        let actions = plan_layer(&infos, &hidden, layer);

        for (info, action) in infos.iter().zip(&actions) {
            match (info, action) {
                (Info::Item { path, dir, .. }, Action::Emit | Action::HardlinkTo(_)) => {
                    paths.insert(path.clone());
                    if let Some(meta) = dir {
                        dirs.insert(path.clone(), meta.clone());
                    }
                }
                (Info::Item { .. }, Action::EmitAs(as_path)) => {
                    paths.insert(as_path.clone());
                }
                _ => {}
            }
        }
        let mut last: HashMap<&[u8], bool> = HashMap::new();
        for info in &infos {
            if let Info::Item { path, dir, .. } = info {
                last.insert(path, dir.is_some());
            }
        }
        for (path, is_dir) in last {
            hidden.add(path, !is_dir);
        }
        for info in &infos {
            match info {
                Info::Whiteout(path) => hidden.add(path, true),
                Info::Opaque(dir) => {
                    hidden.opaque.insert(dir.clone());
                }
                _ => {}
            }
        }
        per_layer.push(actions);
    }
    per_layer.reverse();
    let implied: Vec<Vec<u8>> = paths
        .iter()
        .flat_map(|p| ancestors(p).map(<[u8]>::to_vec))
        .filter(|a| !paths.contains(a))
        .collect();
    paths.extend(implied);
    Ok(Plan {
        layers: per_layer,
        paths,
        dirs,
    })
}

/// `a/b/c` → `a`, `a/b`.
fn ancestors(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.iter()
        .enumerate()
        .filter(|&(_, &b)| b == b'/')
        .map(|(i, _)| &path[..i])
}

fn write_dir<W: Write>(out: &mut TarWriter<W>, path: &[u8], meta: &DirMeta) -> io::Result<()> {
    out.append(
        &tarball::Header {
            path,
            typeflag: tarball::DIRECTORY,
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            mtime: meta.mtime,
            uname: &meta.uname,
            gname: &meta.gname,
            pax: &meta.pax,
            ..tarball::Header::default()
        },
        &mut io::empty(),
    )
}

fn pax_records(entry: &mut tar::Entry<impl Read>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = vec![];
    if let Some(exts) = entry.pax_extensions()? {
        for ext in exts {
            let ext = ext?;
            let key = ext.key_bytes();
            if matches!(key, b"path" | b"linkpath" | b"size") {
                continue;
            }
            if key.starts_with(b"GNU.sparse.") {
                bail!("sparse files are not supported");
            }
            out.push((key.to_vec(), ext.value_bytes().to_vec()));
        }
    }
    Ok(out)
}

/// Copy the regular file at `wanted` in the final filesystem to `out`.
/// Returns whether there is one.
pub fn extract(
    layers: &[PathBuf],
    plan: &Plan,
    wanted: &str,
    out: &mut impl Write,
) -> Result<bool> {
    let wanted = normalize(wanted.as_bytes()).context("not a path")?;
    for (layer, actions) in layers.iter().zip(&plan.layers) {
        let mut archive = entries_of(layer)?;
        for (i, entry) in archive.entries()?.enumerate() {
            let mut entry = entry.with_context(|| format!("reading {}", layer.display()))?;
            let path = match &actions[i] {
                Action::Emit => normalize(&entry.path_bytes()).expect("checked in the first pass"),
                Action::EmitAs(p) => p.clone(),
                _ => continue,
            };
            if path == wanted
                && matches!(
                    entry.header().entry_type(),
                    EntryType::Regular | EntryType::Continuous
                )
            {
                io::copy(&mut entry, out)?;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The second pass: write the final filesystem as one tar stream.
pub fn write_tar(layers: &[PathBuf], plan: &Plan, out: impl Write) -> Result<()> {
    let mut tar_out = TarWriter::new(out);
    let mut dirs_written: HashSet<Vec<u8>> = HashSet::new();
    for (layer, actions) in layers.iter().zip(&plan.layers) {
        let mut archive = entries_of(layer)?;
        for (i, entry) in archive.entries()?.enumerate() {
            let mut entry = entry.with_context(|| format!("reading {}", layer.display()))?;
            let action = actions
                .get(i)
                .with_context(|| format!("{} changed between passes", layer.display()))?;
            if *action == Action::Skip {
                continue;
            }
            let own_path = normalize(&entry.path_bytes()).expect("checked in the first pass");
            let path = match action {
                Action::EmitAs(p) => p.clone(),
                _ => own_path,
            };
            let header = entry.header().clone();
            let kind = header.entry_type();
            let link = match action {
                Action::HardlinkTo(target) => target.clone(),
                _ if kind == EntryType::Link => {
                    normalize(&entry.link_name_bytes().unwrap_or_default())
                        .expect("checked in the first pass")
                }
                _ => entry
                    .link_name_bytes()
                    .map(|l| l.into_owned())
                    .unwrap_or_default(),
            };
            let typeflag = match (action, kind) {
                (Action::HardlinkTo(_), _) => tarball::HARDLINK,
                (_, EntryType::Regular | EntryType::Continuous) => tarball::REGULAR,
                (_, EntryType::Link) => tarball::HARDLINK,
                (_, EntryType::Symlink) => tarball::SYMLINK,
                (_, EntryType::Char) => tarball::CHAR,
                (_, EntryType::Block) => tarball::BLOCK_DEVICE,
                (_, EntryType::Directory) => tarball::DIRECTORY,
                (_, EntryType::Fifo) => tarball::FIFO,
                (_, other) => bail!(
                    "{}: unexpected {other:?} at {}",
                    layer.display(),
                    show(&path)
                ),
            };

            for parent in ancestors(&path) {
                if !dirs_written.contains(parent) {
                    let meta = plan.dirs.get(parent).cloned().unwrap_or_default();
                    write_dir(&mut tar_out, parent, &meta)?;
                    dirs_written.insert(parent.to_vec());
                }
            }
            if typeflag == tarball::DIRECTORY {
                if !dirs_written.insert(path.clone()) {
                    continue;
                }
                let meta = plan.dirs.get(&path).cloned().unwrap_or_default();
                write_dir(&mut tar_out, &path, &meta)?;
                continue;
            }

            let pax = pax_records(&mut entry)
                .with_context(|| format!("{}: {}", layer.display(), show(&path)))?;
            let size = if typeflag == tarball::REGULAR {
                entry.size()
            } else {
                0
            };
            let h = tarball::Header {
                path: &path,
                typeflag,
                mode: header.mode()?,
                uid: header.uid()?,
                gid: header.gid()?,
                mtime: header.mtime()?,
                size,
                link: &link,
                uname: header.username_bytes().unwrap_or_default(),
                gname: header.groupname_bytes().unwrap_or_default(),
                device: if matches!(typeflag, tarball::CHAR | tarball::BLOCK_DEVICE) {
                    (
                        header.device_major()?.unwrap_or(0),
                        header.device_minor()?.unwrap_or(0),
                    )
                } else {
                    (0, 0)
                },
                pax: &pax,
            };
            let data: &mut dyn Read = if size > 0 {
                &mut entry
            } else {
                &mut io::empty()
            };
            tar_out
                .append(&h, data)
                .with_context(|| format!("{}: {}", layer.display(), show(&path)))?;
        }
    }
    tar_out.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    enum E<'a> {
        Dir(&'a str),
        File(&'a str, &'a str),
        Link(&'a str, &'a str),
        Sym(&'a str, &'a str),
    }

    fn layer(dir: &Path, n: usize, entries: &[E], gzip: bool) -> PathBuf {
        let mut b = tar::Builder::new(vec![]);
        for e in entries {
            let mut h = tar::Header::new_gnu();
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(1_700_000_000);
            match e {
                E::Dir(p) => {
                    h.set_entry_type(EntryType::Directory);
                    h.set_mode(0o755);
                    h.set_size(0);
                    b.append_data(&mut h, p, io::empty()).unwrap();
                }
                E::File(p, body) => {
                    h.set_entry_type(EntryType::Regular);
                    h.set_mode(0o644);
                    h.set_size(body.len() as u64);
                    b.append_data(&mut h, p, body.as_bytes()).unwrap();
                }
                E::Link(p, target) => {
                    h.set_entry_type(EntryType::Link);
                    h.set_mode(0o644);
                    h.set_size(0);
                    b.append_link(&mut h, p, target).unwrap();
                }
                E::Sym(p, target) => {
                    h.set_entry_type(EntryType::Symlink);
                    h.set_mode(0o777);
                    h.set_size(0);
                    b.append_link(&mut h, p, target).unwrap();
                }
            }
        }
        let tar = b.into_inner().unwrap();
        let path = dir.join(format!("layer{n}"));
        if gzip {
            let mut gz = flate2::write::GzEncoder::new(
                File::create(&path).unwrap(),
                flate2::Compression::fast(),
            );
            gz.write_all(&tar).unwrap();
            gz.finish().unwrap();
        } else {
            std::fs::write(&path, tar).unwrap();
        }
        path
    }

    /// Flatten, then list (path, what) in output order. Files show their
    /// contents, links their target.
    fn flatten(layers: &[&[E]]) -> Vec<(String, String)> {
        let dir = std::env::temp_dir().join(format!(
            "arsonist-layers-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths: Vec<_> = layers
            .iter()
            .enumerate()
            .map(|(n, entries)| layer(&dir, n, entries, n % 2 == 0))
            .collect();
        let plan = plan(&paths).unwrap();
        let mut out = vec![];
        write_tar(&paths, &plan, &mut out).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        let mut listing = vec![];
        let mut archive = tar::Archive::new(&out[..]);
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = String::from_utf8(entry.path_bytes().into_owned()).unwrap();
            let what = match entry.header().entry_type() {
                EntryType::Directory => "dir".to_string(),
                EntryType::Link => format!(
                    "link {}",
                    String::from_utf8_lossy(&entry.link_name_bytes().unwrap())
                ),
                EntryType::Symlink => format!(
                    "-> {}",
                    String::from_utf8_lossy(&entry.link_name_bytes().unwrap())
                ),
                _ => {
                    let mut s = String::new();
                    entry.read_to_string(&mut s).unwrap();
                    s
                }
            };
            listing.push((path, what));
        }
        for (p, _) in &listing {
            assert!(plan.contains(p), "{p} is written but not in the plan");
        }
        assert_eq!(plan.path_count(), listing.len());
        listing
    }

    fn l(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn higher_layers_win_and_parents_come_first() {
        let out = flatten(&[
            &[
                E::Dir("etc/"),
                E::File("./etc/os-release", "base"),
                E::File("etc/hosts", "h"),
            ],
            &[
                E::Dir("etc"),
                E::File("etc/os-release", "top"),
                E::Dir("usr"),
            ],
        ]);
        assert_eq!(
            out,
            l(&[
                ("etc", "dir"),
                ("etc/hosts", "h"),
                ("etc/os-release", "top"),
                ("usr", "dir")
            ])
        );
    }

    #[test]
    fn parents_no_layer_lists_are_made_up() {
        let out = flatten(&[&[E::File("usr/local/bin/tool", "t")]]);
        assert_eq!(
            out,
            l(&[
                ("usr", "dir"),
                ("usr/local", "dir"),
                ("usr/local/bin", "dir"),
                ("usr/local/bin/tool", "t")
            ])
        );
    }

    #[test]
    fn whiteouts_delete_paths_and_everything_below_them() {
        let out = flatten(&[
            &[
                E::Dir("a"),
                E::File("a/x", "1"),
                E::Dir("b"),
                E::File("b/y", "2"),
                E::File("c", "3"),
            ],
            &[E::File("a/.wh.x", ""), E::File(".wh.b", "")],
        ]);
        assert_eq!(out, l(&[("a", "dir"), ("c", "3")]));
    }

    #[test]
    fn opaque_directories_hide_lower_contents_only() {
        let out = flatten(&[
            &[
                E::Dir("d"),
                E::File("d/old", "1"),
                E::Dir("d/sub"),
                E::File("d/sub/deep", "2"),
            ],
            &[
                E::Dir("d"),
                E::File("d/.wh..wh..opq", ""),
                E::File("d/new", "3"),
            ],
        ]);
        assert_eq!(out, l(&[("d", "dir"), ("d/new", "3")]));
    }

    #[test]
    fn a_file_replacing_a_directory_hides_its_old_contents() {
        let out = flatten(&[
            &[E::Dir("a"), E::File("a/x", "1")],
            &[E::File("a", "now a file")],
            &[E::Dir("a"), E::File("a/y", "2")],
        ]);
        assert_eq!(out, l(&[("a", "dir"), ("a/y", "2")]));
    }

    #[test]
    fn a_deletion_in_between_survives_a_recreated_directory() {
        let out = flatten(&[
            &[E::Dir("a"), E::File("a/x", "1")],
            &[E::File(".wh.a", "")],
            &[E::Dir("a")],
        ]);
        assert_eq!(out, l(&[("a", "dir")]));
    }

    #[test]
    fn hard_links_keep_contents_a_higher_layer_replaced() {
        let out = flatten(&[
            &[
                E::Dir("bin"),
                E::File("bin/python3.12", "old"),
                E::Link("bin/python3", "bin/python3.12"),
                E::Link("bin/python", "bin/python3.12"),
                E::File("bin/kept", "k"),
                E::Link("bin/kept-link", "bin/kept"),
            ],
            &[E::File("bin/python3.12", "new")],
        ]);
        assert_eq!(
            out,
            l(&[
                ("bin", "dir"),
                ("bin/python3", "old"),
                ("bin/python", "link bin/python3"),
                ("bin/kept", "k"),
                ("bin/kept-link", "link bin/kept"),
                ("bin/python3.12", "new"),
            ])
        );
    }

    #[test]
    fn symlinks_and_duplicates_within_a_layer() {
        let out = flatten(&[&[
            E::File("f", "first"),
            E::Sym("s", "../../etc/passwd"),
            E::File("f", "second"),
        ]]);
        assert_eq!(out, l(&[("s", "-> ../../etc/passwd"), ("f", "second")]));
    }

    #[test]
    fn zstd_with_several_frames_and_a_skippable_one() {
        let body = b"hello, ".to_vec();
        let world = b"world".to_vec();
        let mut stream = ruzstd::encoding::compress_to_vec(
            &body[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        stream.extend_from_slice(&[0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 9, 9, 9]);
        stream.extend(ruzstd::encoding::compress_to_vec(
            &world[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        ));
        let path = std::env::temp_dir().join(format!("arsonist-zstd-{}", std::process::id()));
        std::fs::write(&path, &stream).unwrap();
        let mut out = String::new();
        open_layer(&path).unwrap().read_to_string(&mut out).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(out, "hello, world");
    }

    #[test]
    fn paths_are_normalized_and_escapes_refused() {
        assert_eq!(normalize(b"./a//b/").unwrap(), b"a/b");
        assert_eq!(normalize(b"/").unwrap(), b"");
        assert!(normalize(b"a/../../etc").is_none());
    }
}
