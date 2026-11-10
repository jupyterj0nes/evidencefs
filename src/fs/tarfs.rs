//! A tar archive as a file system, read in place: the archive is indexed once (every
//! header: name, kind, size, where its data starts, times, link target) and a member is
//! read straight from the archive by offset when asked. No member is ever written to disk,
//! so an archive full of attacker tooling never lands on the analyst's disk file by file
//! (where an antivirus would quarantine members in the middle of a run).
//!
//! A compressed tar (`.tar.gz`/`.tgz`, `.tar.bz2`, `.tar.xz`) is decompressed once,
//! streaming, into a single temporary `.tar` file, then read in place the same way; the
//! temporary file belongs to the caller's temporary folder.
//!
//! Long names (GNU `L`/`K`, PAX `path`/`linkpath`) are resolved; PAX `mtime`, `atime` and
//! `ctime` keep their fractions; hard links read as their target; symbolic links are listed
//! with their target and never followed; devices, fifos and sockets are listed without
//! content; GNU sparse members are read by replaying the archive up to them, so their holes
//! come back as zeros.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::archive::{code, ArchiveKind};
use crate::diag;
use crate::error::{Error, Result};
use crate::fs::{code as fscode, escapes, join, normalize, Entry, EntryKind, FileSystem, FsKind, Progress, Sink};
use crate::time::{Timestamp, Timestamps};

/// Bytes read from the archive per lock when a member is copied out.
const CHUNK: usize = 1 << 20;

#[derive(Clone, Debug)]
struct Member {
    kind: EntryKind,
    /// Offset of the member's data in the tar file.
    offset: u64,
    /// Bytes of data present in the archive (the declared size, or less when truncated).
    size: u64,
    times: Timestamps,
    link_target: Option<String>,
    /// A hard link: the normalized path of the member whose content it shares.
    hard_of: Option<String>,
    /// A GNU sparse member: read by replaying the archive to entry `index`.
    sparse: bool,
    /// Position of the member among the archive's entries (for the sparse replay).
    index: usize,
}

/// A tar archive as a file system.
pub struct TarFs {
    /// The archive shown in messages (the evidence, not the temporary copy).
    shown: String,
    /// The plain tar that is read (the evidence itself, or the decompressed copy).
    tar: PathBuf,
    file: Mutex<BufReader<File>>,
    file_len: u64,
    members: BTreeMap<String, Member>,
    /// Lower-cased path -> path, for lookups that ignore case (the first spelling wins).
    folded: BTreeMap<String, String>,
    /// Directory -> child names (sorted), including directories implied by member paths.
    dirs: BTreeMap<String, Vec<String>>,
    /// Name of the archive (the evidence's file name).
    name: Option<String>,
}

/// What indexing found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TarStats {
    pub files: usize,
    pub dirs: usize,
    pub links: usize,
    pub others: usize,
    pub bytes: u64,
}

impl TarFs {
    /// Indexes a plain tar and reads it in place.
    pub fn open(path: &Path) -> Result<Self> {
        Self::index(path, path)
    }

    /// Decompresses a compressed tar once into the single file `dest` (created, replaced
    /// if present) and reads that in place. `kind` says how the archive is compressed.
    pub fn open_compressed(path: &Path, kind: ArchiveKind, dest: &Path) -> Result<Self> {
        decompress(path, kind, dest)?;
        Self::index(dest, path)
    }

    /// Opens a tar of any supported kind: a plain tar in place, a compressed one through
    /// a single decompressed copy at `dest`.
    pub fn open_kind(path: &Path, kind: ArchiveKind, dest: &Path) -> Result<Self> {
        match kind {
            ArchiveKind::Tar => Self::open(path),
            ArchiveKind::TarGz | ArchiveKind::TarBz2 | ArchiveKind::TarXz => Self::open_compressed(path, kind, dest),
            other => Err(Error::recorded(code::ARCHIVE_UNSUPPORTED, format!("{}: {}", path.display(), other.label()))),
        }
    }

    fn index(tar: &Path, shown_path: &Path) -> Result<Self> {
        let shown = shown_path.display().to_string();
        let f = File::open(tar).map_err(|e| Error::recorded(code::ARCHIVE_OPEN, format!("{shown}: {e}")))?;
        let file_len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let mut archive = tar::Archive::new(BufReader::new(f));
        let mut members: BTreeMap<String, Member> = BTreeMap::new();
        let mut dirs: BTreeMap<String, Vec<String>> = BTreeMap::new();
        dirs.insert("/".to_string(), Vec::new());
        let mut stats = TarStats::default();
        let mut entries_seen = 0usize;
        let entries = archive.entries_with_seek().map_err(|e| Error::recorded(code::ARCHIVE_OPEN, format!("{shown}: {e}")))?;
        for (index, entry) in entries.enumerate() {
            let mut entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    diag::warn(code::TAR_HEADER_CORRUPT, format!("{shown}: after {entries_seen} member(s): {e}"));
                    break;
                }
            };
            entries_seen += 1;
            let raw_name = String::from_utf8_lossy(&entry.path_bytes()).to_string();
            if raw_name.contains('\u{FFFD}') {
                diag::warn(fscode::WALK_NAME_UNDECODABLE, format!("{shown}: {raw_name}"));
            }
            let norm = match safe_path(&raw_name) {
                Some(p) => p,
                None => {
                    let s = sanitize_name(&raw_name);
                    diag::warn(code::ARCHIVE_ENTRY_UNSAFE, format!("{shown}: {raw_name} listed as {s}"));
                    normalize(&s)
                }
            };
            if norm == "/" {
                continue;
            }
            let header = entry.header().clone();
            let ty = header.entry_type();
            let mut times = Timestamps { modified: header.mtime().ok().map(|s| Timestamp::from_unix(s as i64, 0)), ..Default::default() };
            if let Some(gnu) = header.as_gnu() {
                times.accessed = gnu.atime().ok().filter(|t| *t > 0).map(|s| Timestamp::from_unix(s as i64, 0));
                times.changed = gnu.ctime().ok().filter(|t| *t > 0).map(|s| Timestamp::from_unix(s as i64, 0));
            }
            let mut pax_sparse = false;
            if let Ok(Some(exts)) = entry.pax_extensions() {
                for ext in exts.flatten() {
                    let (Ok(k), Ok(v)) = (ext.key(), ext.value()) else {
                        diag::warn(code::TAR_PAX_INVALID, format!("{shown}: {norm}"));
                        continue;
                    };
                    match k {
                        "mtime" => times.modified = pax_time(v).or(times.modified),
                        "atime" => times.accessed = pax_time(v),
                        "ctime" => times.changed = pax_time(v),
                        k if k.starts_with("GNU.sparse.") => pax_sparse = true,
                        _ => {}
                    }
                }
            }
            if times.accessed.is_some() || times.changed.is_some() {
                diag::info(code::TAR_EXTRA_TIMES, format!("{shown}: {norm}"));
            }
            let offset = entry.raw_file_position();
            let declared = entry.size();
            let link = entry.link_name().ok().flatten().map(|p| p.to_string_lossy().replace('\\', "/"));
            let kind = if ty.is_dir() {
                EntryKind::Dir
            } else if ty.is_symlink() {
                EntryKind::Symlink
            } else if ty.is_file() || ty.is_hard_link() || ty.is_gnu_sparse() || ty.is_contiguous() {
                EntryKind::File
            } else {
                EntryKind::Other
            };
            let mut size = if kind == EntryKind::File && !ty.is_hard_link() { declared } else { 0 };
            let stored = header.entry_size().unwrap_or(declared);
            if kind == EntryKind::File && !ty.is_hard_link() && !ty.is_gnu_sparse() && offset.saturating_add(stored) > file_len {
                let present = file_len.saturating_sub(offset);
                diag::warn(code::TAR_MEMBER_TRUNCATED, format!("{shown}: {norm}: {present} of {stored} bytes present"));
                size = present.min(size);
            }
            if ty.is_gnu_sparse() {
                diag::info(code::TAR_SPARSE_MEMBER, format!("{shown}: {norm}: {declared} bytes, read by replaying the archive"));
            }
            if pax_sparse {
                diag::warn(code::TAR_SPARSE_PAX, format!("{shown}: {norm}: PAX sparse member read as stored, holes not expanded"));
            }
            if kind == EntryKind::Other {
                diag::info(code::TAR_SPECIAL_MEMBER, format!("{shown}: {norm}: {ty:?}"));
            }
            let hard_of = if ty.is_hard_link() { link.as_deref().and_then(safe_path) } else { None };
            let link_target = if ty.is_symlink() || ty.is_hard_link() { link.clone() } else { None };
            match kind {
                EntryKind::File => {
                    stats.files += 1;
                    stats.bytes += size;
                }
                EntryKind::Dir => stats.dirs += 1,
                EntryKind::Symlink => stats.links += 1,
                EntryKind::Other => stats.others += 1,
            }
            let m = Member { kind, offset, size, times, link_target, hard_of, sparse: ty.is_gnu_sparse(), index };
            if let Some(old) = members.insert(norm.clone(), m) {
                diag::info(code::TAR_DUPLICATE_MEMBER, format!("{shown}: {norm} (the later copy is read)"));
                // A directory restated as a file, or the reverse, keeps the later kind.
                let _ = old;
            }
            // Every ancestor is a directory.
            let mut child = norm.clone();
            while let Some((p, name)) = child.rsplit_once('/') {
                let p = if p.is_empty() { "/".to_string() } else { p.to_string() };
                let children = dirs.entry(p.clone()).or_default();
                if !children.iter().any(|c| c == name) {
                    children.push(name.to_string());
                }
                if p == "/" {
                    break;
                }
                child = p;
            }
            if kind == EntryKind::Dir {
                dirs.entry(norm.clone()).or_default();
            }
        }
        // Hard links take the content (size) of their target.
        let resolved: Vec<(String, Option<u64>)> = members
            .iter()
            .filter(|(_, m)| m.hard_of.is_some())
            .map(|(p, m)| (p.clone(), m.hard_of.as_ref().and_then(|t| members.get(t)).filter(|t| t.kind == EntryKind::File && t.hard_of.is_none()).map(|t| t.size)))
            .collect();
        for (p, size) in resolved {
            let m = members.get_mut(&p).expect("listed above");
            match size {
                Some(s) => {
                    m.size = s;
                    stats.bytes += s;
                    diag::info(code::TAR_HARDLINK, format!("{shown}: {p} -> {}", m.hard_of.clone().unwrap_or_default()));
                }
                None => {
                    diag::warn(code::TAR_HARDLINK_DANGLING, format!("{shown}: {p} -> {}", m.link_target.clone().unwrap_or_default()));
                    m.hard_of = None;
                    m.size = 0;
                    m.kind = EntryKind::Other;
                }
            }
        }
        for children in dirs.values_mut() {
            children.sort();
        }
        if entries_seen == 0 {
            diag::warn(code::ARCHIVE_EMPTY, shown.clone());
        }
        let mut folded = BTreeMap::new();
        for p in members.keys().chain(dirs.keys()) {
            folded.entry(p.to_lowercase()).or_insert_with(|| p.clone());
        }
        diag::info(code::TAR_INDEXED, format!("{shown}: {} files, {} directories, {} links, {} others, {} bytes; read in place from {}", stats.files, stats.dirs, stats.links, stats.others, stats.bytes, tar.display()));
        let f = File::open(tar).map_err(|e| Error::recorded(code::ARCHIVE_OPEN, format!("{shown}: {e}")))?;
        Ok(TarFs {
            shown,
            tar: tar.to_path_buf(),
            file: Mutex::new(BufReader::with_capacity(CHUNK, f)),
            file_len,
            members,
            folded,
            dirs,
            name: shown_path.file_name().map(|n| n.to_string_lossy().to_string()),
        })
    }

    /// The plain tar this reads (the evidence, or the decompressed copy).
    pub fn tar_path(&self) -> &Path {
        &self.tar
    }

    /// Members indexed (files, directories, links, others; implied directories excluded).
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// The spelling of `path` in the archive: exact first, then ignoring case.
    fn resolve(&self, path: &str) -> Result<String> {
        if escapes(path) {
            return Err(Error::recorded(fscode::FS_PATH_ESCAPES, path.to_string()));
        }
        let norm = normalize(path);
        if norm == "/" || self.members.contains_key(&norm) || self.dirs.contains_key(&norm) {
            return Ok(norm);
        }
        match self.folded.get(&norm.to_lowercase()) {
            Some(p) => Ok(p.clone()),
            None => Err(Error::new(fscode::FS_NOT_FOUND, path.to_string())),
        }
    }

    fn entry_for(&self, norm: &str) -> Entry {
        match self.members.get(norm) {
            Some(m) if self.dirs.contains_key(norm) && m.kind != EntryKind::Dir => {
                // A file and a directory of the same name: the directory (it has content).
                let mut e = Entry::new(norm, EntryKind::Dir);
                e.times = m.times;
                e
            }
            Some(m) => {
                let mut e = Entry::new(norm, m.kind);
                e.size = if m.kind == EntryKind::File { m.size } else { 0 };
                e.times = m.times;
                e.link_target = m.link_target.clone();
                e
            }
            None => Entry::new(norm, EntryKind::Dir),
        }
    }

    /// Reads `len` bytes at `offset` of the tar into `sink`, a chunk per lock.
    fn copy_range(&self, path: &str, offset: u64, len: u64, sink: Sink<'_>, mut progress: Option<Progress<'_>>) -> Result<u64> {
        let mut done = 0u64;
        let mut buf = vec![0u8; CHUNK.min(len.max(1) as usize)];
        while done < len {
            let want = ((len - done) as usize).min(buf.len());
            {
                let mut f = self.file.lock().unwrap_or_else(|p| p.into_inner());
                f.seek(SeekFrom::Start(offset + done)).map_err(|e| Error::recorded(code::TAR_READ, format!("{}: {path}: after {done} bytes: {e}", self.shown)))?;
                f.read_exact(&mut buf[..want]).map_err(|e| Error::recorded(code::TAR_READ, format!("{}: {path}: after {done} bytes: {e}", self.shown)))?;
            }
            sink.write_all(&buf[..want]).map_err(|e| Error::recorded(crate::extract::code::EXTRACT_WRITE, format!("{path}: {e}")))?;
            done += want as u64;
            if let Some(p) = progress.as_deref_mut() {
                p(done, len);
            }
        }
        if len == 0 {
            if let Some(p) = progress {
                p(0, 0);
            }
        }
        Ok(done)
    }

    /// A GNU sparse member: the archive is read from the start up to it and the member is
    /// read through the tar reader, which expands the holes.
    fn copy_sparse(&self, path: &str, m: &Member, sink: Sink<'_>, mut progress: Option<Progress<'_>>) -> Result<u64> {
        let f = File::open(&self.tar).map_err(|e| Error::recorded(code::TAR_READ, format!("{}: {path}: {e}", self.shown)))?;
        let mut archive = tar::Archive::new(BufReader::new(f));
        let mut entries = archive.entries_with_seek().map_err(|e| Error::recorded(code::TAR_READ, format!("{}: {path}: {e}", self.shown)))?;
        let mut entry = match entries.nth(m.index) {
            Some(Ok(e)) => e,
            Some(Err(e)) => return Err(Error::recorded(code::TAR_READ, format!("{}: {path}: {e}", self.shown))),
            None => return Err(Error::recorded(code::TAR_READ, format!("{}: {path}: member {} is gone", self.shown, m.index))),
        };
        let total = m.size;
        let mut done = 0u64;
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = entry.read(&mut buf).map_err(|e| Error::recorded(code::TAR_READ, format!("{}: {path}: after {done} bytes: {e}", self.shown)))?;
            if n == 0 {
                break;
            }
            sink.write_all(&buf[..n]).map_err(|e| Error::recorded(crate::extract::code::EXTRACT_WRITE, format!("{path}: {e}")))?;
            done += n as u64;
            if let Some(p) = progress.as_deref_mut() {
                p(done, total);
            }
        }
        Ok(done)
    }
}

impl FileSystem for TarFs {
    fn kind(&self) -> FsKind {
        FsKind::Tar
    }

    fn label(&self) -> Option<String> {
        self.name.clone()
    }

    fn size(&self) -> Option<u64> {
        Some(self.file_len)
    }

    fn metadata(&self, path: &str) -> Result<Entry> {
        let norm = self.resolve(path)?;
        Ok(self.entry_for(&norm))
    }

    fn read_dir(&self, path: &str) -> Result<Vec<Entry>> {
        let norm = self.resolve(path)?;
        let Some(children) = self.dirs.get(&norm) else {
            return Err(Error::new(fscode::FS_NOT_A_DIR, path.to_string()));
        };
        Ok(children.iter().map(|c| self.entry_for(&join(&norm, c))).collect())
    }

    fn copy_to(&self, path: &str, stream: Option<&str>, sink: Sink<'_>, progress: Option<Progress<'_>>) -> Result<u64> {
        let norm = self.resolve(path)?;
        let entry = self.entry_for(&norm);
        if entry.kind != EntryKind::File {
            return Err(Error::new(if entry.kind == EntryKind::Symlink { fscode::FS_SYMLINK_NOT_FOLLOWED } else { fscode::FS_NOT_A_FILE }, path.to_string()));
        }
        if stream.is_some_and(|s| !s.is_empty()) {
            return Err(Error::new(fscode::FS_STREAM_NOT_FOUND, format!("{path}:{}", stream.unwrap_or(""))));
        }
        let mut m = self.members.get(&norm).cloned().ok_or_else(|| Error::new(fscode::FS_NOT_FOUND, path.to_string()))?;
        if let Some(target) = m.hard_of.clone() {
            m = self.members.get(&target).cloned().ok_or_else(|| Error::recorded(code::TAR_HARDLINK_DANGLING, format!("{}: {path} -> {target}", self.shown)))?;
        }
        if m.sparse {
            return self.copy_sparse(path, &m, sink, progress);
        }
        self.copy_range(path, m.offset, m.size, sink, progress)
    }
}

impl std::fmt::Debug for TarFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TarFs({}, {} members)", self.shown, self.members.len())
    }
}

/// A member path when it stays inside the archive: no `..` climbing above the root, no
/// absolute or drive-letter root. `./etc/x` and `etc/x` are the same path.
fn safe_path(raw: &str) -> Option<String> {
    let unified = raw.replace('\\', "/");
    if unified.starts_with('/') || unified.len() >= 2 && unified.as_bytes()[1] == b':' {
        return None;
    }
    let mut depth = 0i32;
    for c in unified.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            _ => depth += 1,
        }
    }
    Some(normalize(&unified))
}

/// A name that climbs out of the archive, kept visible: `..` components become `__`, the
/// root and drive letter are dropped (`/etc/x` -> `/etc/x`, `../../x` -> `/__/__/x`).
fn sanitize_name(raw: &str) -> String {
    let unified = raw.replace('\\', "/");
    let without_drive = if unified.len() >= 2 && unified.as_bytes()[1] == b':' { &unified[2..] } else { &unified[..] };
    without_drive.split('/').filter(|c| !c.is_empty() && *c != ".").map(|c| if c == ".." { "__" } else { c }).collect::<Vec<_>>().join("/")
}

/// A PAX time: seconds since 1970 with an optional fraction (`1699999999.123456789`),
/// negative allowed.
fn pax_time(v: &str) -> Option<Timestamp> {
    let v = v.trim();
    let (int, frac) = v.split_once('.').unwrap_or((v, ""));
    let secs: i64 = int.parse().ok()?;
    let digits: String = frac.chars().take(9).collect();
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let nanos: u32 = if digits.is_empty() { 0 } else { format!("{digits:0<9}").parse().ok()? };
    if secs < 0 && nanos > 0 {
        // -1.25 is 1.25 seconds before the epoch: -2 s + 0.75 s.
        return Some(Timestamp::from_unix(secs - 1, 1_000_000_000 - nanos));
    }
    Some(Timestamp::from_unix(secs, nanos))
}

/// Decompresses `path` (gzip, bzip2 or xz around a tar) into the single file `dest`.
fn decompress(path: &Path, kind: ArchiveKind, dest: &Path) -> Result<u64> {
    let shown = path.display().to_string();
    let f = File::open(path).map_err(|e| Error::recorded(code::ARCHIVE_OPEN, format!("{shown}: {e}")))?;
    let input = f.metadata().map(|m| m.len()).unwrap_or(0);
    let reader = BufReader::with_capacity(CHUNK, f);
    let mut decoder: Box<dyn Read> = match kind {
        ArchiveKind::TarGz => Box::new(flate2::read::MultiGzDecoder::new(reader)),
        ArchiveKind::TarBz2 => Box::new(bzip2::read::MultiBzDecoder::new(reader)),
        ArchiveKind::TarXz => Box::new(lzma_rust2::XzReader::new(reader, true)),
        other => return Err(Error::recorded(code::ARCHIVE_UNSUPPORTED, format!("{shown}: {}", other.label()))),
    };
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir).map_err(|e| Error::recorded(code::ARCHIVE_TEMP_DIR, format!("{}: {e}", dir.display())))?;
    }
    let out = File::create(dest).map_err(|e| Error::recorded(code::TAR_TEMP_WRITE, format!("{}: {e}", dest.display())))?;
    let mut out = std::io::BufWriter::with_capacity(CHUNK, out);
    let mut buf = vec![0u8; CHUNK];
    let mut written = 0u64;
    loop {
        let n = match decoder.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                // The members before the damage are still read: keep what was decoded.
                diag::warn(code::ARCHIVE_GZIP, format!("{shown}: {} stream damaged after {written} bytes: {e}", kind.label()));
                break;
            }
        };
        out.write_all(&buf[..n]).map_err(|e| Error::recorded(code::TAR_TEMP_WRITE, format!("{}: {e}", dest.display())))?;
        written += n as u64;
    }
    out.flush().map_err(|e| Error::recorded(code::TAR_TEMP_WRITE, format!("{}: {e}", dest.display())))?;
    diag::info(code::TAR_DECOMPRESSED, format!("{shown}: {} bytes ({}) into one file of {written} bytes: {}", input, kind.label(), dest.display()));
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{find, walk, Glob, WalkOptions, WalkStep};

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("evidencefs-tarfs-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// One raw ustar header block (+ data padded to 512).
    fn raw(name: &str, data: &[u8], typeflag: u8, link: &str, mtime: u64, size_field: Option<u64>) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        let n = name.len().min(100);
        h[..n].copy_from_slice(&name.as_bytes()[..n]);
        h[100..107].copy_from_slice(b"0000644");
        h[108..115].copy_from_slice(b"0001750");
        h[116..123].copy_from_slice(b"0001750");
        h[124..135].copy_from_slice(format!("{:011o}", size_field.unwrap_or(data.len() as u64)).as_bytes());
        h[136..147].copy_from_slice(format!("{mtime:011o}").as_bytes());
        h[148..156].copy_from_slice(b"        ");
        h[156] = typeflag;
        let l = link.len().min(100);
        h[157..157 + l].copy_from_slice(&link.as_bytes()[..l]);
        h[257..262].copy_from_slice(b"ustar");
        h[263..265].copy_from_slice(b"00");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        let mut out = h;
        out.extend_from_slice(data);
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
        out
    }

    fn pax_record(key: &str, value: &str) -> String {
        let body = format!(" {key}={value}\n");
        let mut len = body.len() + 1;
        while format!("{len}{body}").len() != len {
            len += 1;
        }
        format!("{len}{body}")
    }

    fn finish(mut v: Vec<u8>) -> Vec<u8> {
        v.extend_from_slice(&[0u8; 1024]);
        v
    }

    /// A tar exercising what collectors produce: `./` prefixes, a GNU long name, a PAX long
    /// name with fractional times, a hard link, a symlink, a fifo, an empty file, a member
    /// spanning several chunks, a directory with its own time.
    pub fn rich_tar() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(raw("./etc/", b"", b'5', "", 1_600_000_000, None));
        v.extend(raw("./etc/hostname", b"lab-host\n", b'0', "", 1_700_000_000, None));
        v.extend(raw("./etc/empty.conf", b"", b'0', "", 1_700_000_001, None));
        let long = format!("home/alice/{}/notes.txt", "deep".repeat(40));
        v.extend(raw("././@LongLink", format!("{long}\0").as_bytes(), b'L', "", 0, None));
        v.extend(raw(&long[..99], b"gnu long", b'0', "", 1_700_000_002, None));
        let pax_name = format!("var/log/{}/syslog", "p".repeat(120));
        let records = pax_record("path", &pax_name) + &pax_record("mtime", "1700000003.5") + &pax_record("atime", "1700000004.25") + &pax_record("ctime", "1700000005");
        v.extend(raw("./PaxHeaders/x", records.as_bytes(), b'x', "", 0, None));
        v.extend(raw("short-pax-name", b"pax body", b'0', "", 1, None));
        v.extend(raw("etc/hostname.bak", b"", b'1', "./etc/hostname", 1_700_000_006, Some(0)));
        v.extend(raw("etc/link", b"", b'2', "/etc/hostname", 1_700_000_007, None));
        v.extend(raw("dev/fifo", b"", b'6', "", 1_700_000_008, None));
        let big: Vec<u8> = (0..(CHUNK as u32 * 2 + 777)).map(|i| (i % 251) as u8).collect();
        v.extend(raw("data/big.bin", &big, b'0', "", 1_700_000_009, None));
        finish(v)
    }

    #[test]
    fn indexes_and_reads_in_place() {
        crate::diag::set_quiet(true);
        let d = tmp("rich");
        let p = d.join("rich.tar");
        std::fs::write(&p, rich_tar()).unwrap();
        let fs = TarFs::open(&p).unwrap();
        assert_eq!(fs.kind(), FsKind::Tar);
        assert_eq!(fs.label().as_deref(), Some("rich.tar"));
        let top: Vec<String> = fs.read_dir("/").unwrap().iter().map(|e| e.name.clone()).collect();
        assert_eq!(top, vec!["data", "dev", "etc", "home", "var"]);
        assert_eq!(fs.read_to_string("/etc/hostname", 100).unwrap(), "lab-host\n");
        let e = fs.metadata("/etc/hostname").unwrap();
        assert_eq!(e.times.modified, Some(Timestamp::from_unix(1_700_000_000, 0)));
        assert!(e.times.created.is_none() && e.times.accessed.is_none());
        // The directory keeps its own time.
        assert_eq!(fs.metadata("/etc").unwrap().times.modified, Some(Timestamp::from_unix(1_600_000_000, 0)));
        // Implied directories have no time.
        assert!(fs.metadata("/home").unwrap().times.modified.is_none());
        // Empty file.
        let empty = fs.metadata("/etc/empty.conf").unwrap();
        assert!(empty.is_file() && empty.size == 0);
        assert_eq!(fs.read("/etc/empty.conf", None, 10).unwrap(), b"");
        // GNU long name.
        let long = format!("/home/alice/{}/notes.txt", "deep".repeat(40));
        assert_eq!(fs.read(&long, None, 100).unwrap(), b"gnu long");
        // PAX long name, fractional times.
        let pax = format!("/var/log/{}/syslog", "p".repeat(120));
        let pe = fs.metadata(&pax).unwrap();
        assert_eq!(fs.read(&pax, None, 100).unwrap(), b"pax body");
        assert_eq!(pe.times.modified, Some(Timestamp::from_unix(1_700_000_003, 500_000_000)));
        assert_eq!(pe.times.accessed, Some(Timestamp::from_unix(1_700_000_004, 250_000_000)));
        assert_eq!(pe.times.changed, Some(Timestamp::from_unix(1_700_000_005, 0)));
        // Hard link reads its target; symlink is listed, not followed; fifo has no content.
        let hl = fs.metadata("/etc/hostname.bak").unwrap();
        assert!(hl.is_file());
        assert_eq!(hl.size, 9);
        assert_eq!(fs.read("/etc/hostname.bak", None, 100).unwrap(), b"lab-host\n");
        let sl = fs.metadata("/etc/link").unwrap();
        assert_eq!(sl.kind, EntryKind::Symlink);
        assert_eq!(sl.link_target.as_deref(), Some("/etc/hostname"));
        assert_eq!(fs.read("/etc/link", None, 100).unwrap_err().code, fscode::FS_SYMLINK_NOT_FOLLOWED);
        assert_eq!(fs.metadata("/dev/fifo").unwrap().kind, EntryKind::Other);
        assert_eq!(fs.read("/dev/fifo", None, 100).unwrap_err().code, fscode::FS_NOT_A_FILE);
        // A member over several chunks, with progress.
        let mut sink = Vec::new();
        let mut seen = Vec::new();
        let n = fs.copy_to("/data/big.bin", None, &mut sink, Some(&mut |a, b| seen.push((a, b)))).unwrap();
        assert_eq!(n, CHUNK as u64 * 2 + 777);
        assert!(sink.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
        assert_eq!(seen.len(), 3);
        assert_eq!(seen.last(), Some(&(n, n)));
        // Case is ignored when there is no exact spelling.
        assert_eq!(fs.read("/ETC/HOSTNAME", None, 100).unwrap(), b"lab-host\n");
        // Errors.
        assert_eq!(fs.metadata("/nope").unwrap_err().code, fscode::FS_NOT_FOUND);
        assert_eq!(fs.read_dir("/etc/hostname").unwrap_err().code, fscode::FS_NOT_A_DIR);
        assert_eq!(fs.copy_to("/etc", None, &mut Vec::new(), None).unwrap_err().code, fscode::FS_NOT_A_FILE);
        assert_eq!(fs.copy_to("/etc/hostname", Some("ads"), &mut Vec::new(), None).unwrap_err().code, fscode::FS_STREAM_NOT_FOUND);
        assert_eq!(fs.metadata("../../x").unwrap_err().code, fscode::FS_PATH_ESCAPES);
        // Walk and find behave as on any file system.
        let mut order = Vec::new();
        walk(&fs, "/", &WalkOptions::default(), &mut |e| {
            order.push(e.path.clone());
            WalkStep::Continue
        });
        assert!(order.iter().position(|p| p == "/etc").unwrap() < order.iter().position(|p| p == "/etc/hostname").unwrap());
        let found = find(&fs, "/", &[Glob::new("**/syslog").unwrap()], &WalkOptions::default());
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn unsafe_names_are_listed_under_a_sanitised_name() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let d = tmp("unsafe");
        let p = d.join("u.tar");
        let mut v = raw("../../escape.txt", b"x", b'0', "", 1, None);
        v.extend(raw("/abs/root.txt", b"y", b'0', "", 1, None));
        v.extend(raw("ok/../fine.txt", b"z", b'0', "", 1, None));
        std::fs::write(&p, finish(v)).unwrap();
        let fs = TarFs::open(&p).unwrap();
        assert_eq!(fs.read("/__/__/escape.txt", None, 10).unwrap(), b"x");
        assert_eq!(fs.read("/abs/root.txt", None, 10).unwrap(), b"y");
        assert_eq!(fs.read("/fine.txt", None, 10).unwrap(), b"z");
        assert!(crate::diag::has(code::ARCHIVE_ENTRY_UNSAFE));
    }

    #[test]
    fn duplicates_take_the_later_copy() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let d = tmp("dup");
        let p = d.join("d.tar");
        let mut v = raw("a.txt", b"first", b'0', "", 1, None);
        v.extend(raw("a.txt", b"second", b'0', "", 2, None));
        std::fs::write(&p, finish(v)).unwrap();
        let fs = TarFs::open(&p).unwrap();
        assert_eq!(fs.read("/a.txt", None, 10).unwrap(), b"second");
        assert!(crate::diag::has(code::TAR_DUPLICATE_MEMBER));
    }

    #[test]
    fn truncated_archive_keeps_what_is_there() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let d = tmp("trunc");
        let p = d.join("t.tar");
        let mut v = raw("first.txt", b"complete", b'0', "", 1, None);
        let second = raw("second.bin", &vec![7u8; 5000], b'0', "", 1, None);
        v.extend_from_slice(&second[..512 + 1000]);
        std::fs::write(&p, v).unwrap();
        let fs = TarFs::open(&p).unwrap();
        assert_eq!(fs.read("/first.txt", None, 100).unwrap(), b"complete");
        let s = fs.metadata("/second.bin").unwrap();
        assert_eq!(s.size, 1000);
        assert_eq!(fs.read("/second.bin", None, 10_000).unwrap(), vec![7u8; 1000]);
        assert!(crate::diag::has(code::TAR_MEMBER_TRUNCATED));
    }

    #[test]
    fn corrupt_header_stops_the_index_there() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let d = tmp("corrupt");
        let p = d.join("c.tar");
        let mut v = raw("good.txt", b"ok", b'0', "", 1, None);
        let mut bad = raw("bad.txt", b"no", b'0', "", 1, None);
        bad[148] = b'9'; // checksum field broken
        bad[149] = b'9';
        v.extend(bad);
        v.extend(raw("after.txt", b"lost", b'0', "", 1, None));
        std::fs::write(&p, finish(v)).unwrap();
        let fs = TarFs::open(&p).unwrap();
        assert_eq!(fs.read("/good.txt", None, 10).unwrap(), b"ok");
        assert!(!fs.exists("/after.txt"));
        assert!(crate::diag::has(code::TAR_HEADER_CORRUPT));
    }

    #[test]
    fn empty_and_garbage_archives() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let d = tmp("empty");
        let e = d.join("e.tar");
        std::fs::write(&e, [0u8; 1024]).unwrap();
        let fs = TarFs::open(&e).unwrap();
        assert!(fs.read_dir("/").unwrap().is_empty());
        assert!(crate::diag::has(code::ARCHIVE_EMPTY));
        assert_eq!(TarFs::open(&d.join("missing.tar")).unwrap_err().code, code::ARCHIVE_OPEN);
    }

    #[test]
    fn dangling_hard_link_is_listed_without_content() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let d = tmp("dangling");
        let p = d.join("h.tar");
        std::fs::write(&p, finish(raw("x/link", b"", b'1', "nowhere/target", 1, Some(0)))).unwrap();
        let fs = TarFs::open(&p).unwrap();
        assert_eq!(fs.metadata("/x/link").unwrap().kind, EntryKind::Other);
        assert!(crate::diag::has(code::TAR_HARDLINK_DANGLING));
    }

    #[test]
    fn compressed_tars_become_one_file_and_no_member_is_written() {
        crate::diag::set_quiet(true);
        let d = tmp("compressed");
        let tar = rich_tar();
        // gzip
        let gz = d.join("rich.tgz");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&tar).unwrap();
        std::fs::write(&gz, enc.finish().unwrap()).unwrap();
        // bzip2
        let bz = d.join("rich.tar.bz2");
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(1));
        enc.write_all(&tar).unwrap();
        std::fs::write(&bz, enc.finish().unwrap()).unwrap();
        // xz
        let xz = d.join("rich.tar.xz");
        let mut out = Vec::new();
        {
            let mut w = lzma_rust2::XzWriter::new(&mut out, lzma_rust2::XzOptions::with_preset(1)).unwrap();
            w.write_all(&tar).unwrap();
            w.finish().unwrap();
        }
        std::fs::write(&xz, out).unwrap();
        for (path, kind) in [(&gz, ArchiveKind::TarGz), (&bz, ArchiveKind::TarBz2), (&xz, ArchiveKind::TarXz)] {
            let work = d.join(format!("work-{}", kind.label()));
            std::fs::create_dir_all(&work).unwrap();
            let dest = work.join("one.tar");
            let fs = TarFs::open_kind(path, kind, &dest).unwrap();
            assert_eq!(fs.read_to_string("/etc/hostname", 100).unwrap(), "lab-host\n", "{}", kind.label());
            assert_eq!(fs.tar_path(), dest.as_path());
            // The work folder holds the single decompressed tar, nothing else.
            let listed: Vec<String> = std::fs::read_dir(&work).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
            assert_eq!(listed, vec!["one.tar".to_string()], "{}", kind.label());
            assert_eq!(std::fs::metadata(&dest).unwrap().len(), tar.len() as u64);
        }
        assert_eq!(TarFs::open_kind(&gz, ArchiveKind::SevenZip, &d.join("x.tar")).unwrap_err().code, code::ARCHIVE_UNSUPPORTED);
    }

    #[test]
    fn damaged_gzip_keeps_the_members_before_the_damage() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let d = tmp("badgz");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&rich_tar()).unwrap();
        let mut gz = enc.finish().unwrap();
        let cut = gz.len() * 2 / 3;
        gz.truncate(cut);
        let p = d.join("cut.tgz");
        std::fs::write(&p, gz).unwrap();
        let fs = TarFs::open_kind(&p, ArchiveKind::TarGz, &d.join("cut.tar")).unwrap();
        assert_eq!(fs.read_to_string("/etc/hostname", 100).unwrap(), "lab-host\n");
        assert!(crate::diag::has(code::ARCHIVE_GZIP));
    }

    #[test]
    fn gnu_sparse_member_reads_with_its_holes() {
        crate::diag::set_quiet(true);
        let d = tmp("sparse");
        let p = d.join("s.tar");
        // Built with the tar crate's writer: a GNU sparse header is easiest from a real
        // sparse-looking file, so build the old-GNU sparse header by hand: one data chunk of
        // 512 bytes at offset 4096, real size 8192.
        let mut h = tar::Header::new_gnu();
        h.set_path("sparse.bin").unwrap();
        h.set_entry_type(tar::EntryType::GNUSparse);
        h.set_size(512);
        h.set_mode(0o644);
        h.set_mtime(1);
        {
            let gnu = h.as_gnu_mut().unwrap();
            gnu.sparse[0].offset = *b"00000010000\0"; // 4096 octal
            gnu.sparse[0].numbytes = *b"00000001000\0"; // 512 octal
            // GNU tar ends the map with an empty chunk at the real size.
            gnu.sparse[1].offset = *b"00000020000\0";
            gnu.sparse[1].numbytes = *b"00000000000\0";
            gnu.realsize = *b"00000020000\0"; // 8192 octal
        }
        h.set_cksum();
        let mut v = h.as_bytes().to_vec();
        v.extend(vec![9u8; 512]);
        std::fs::write(&p, finish(v)).unwrap();
        let fs = TarFs::open(&p).unwrap();
        let e = fs.metadata("/sparse.bin").unwrap();
        assert_eq!(e.size, 8192);
        let data = fs.read("/sparse.bin", None, 100_000).unwrap();
        assert_eq!(data.len(), 8192);
        assert!(data[..4096].iter().all(|b| *b == 0));
        assert!(data[4096..4608].iter().all(|b| *b == 9));
        assert!(data[4608..].iter().all(|b| *b == 0));
    }

    #[test]
    fn pax_times_and_names() {
        assert_eq!(pax_time("1700000000"), Some(Timestamp::from_unix(1_700_000_000, 0)));
        assert_eq!(pax_time("1700000000.123456789123"), Some(Timestamp::from_unix(1_700_000_000, 123_456_789)));
        assert_eq!(pax_time("-1.25"), Some(Timestamp::from_unix(-2, 750_000_000)));
        assert_eq!(pax_time("x"), None);
        assert_eq!(pax_time("1.x"), None);
        assert_eq!(safe_path("./etc/x").as_deref(), Some("/etc/x"));
        assert_eq!(safe_path("a/../b").as_deref(), Some("/b"));
        assert_eq!(safe_path("../b"), None);
        assert_eq!(safe_path("/etc/x"), None);
        assert_eq!(safe_path("C:/x"), None);
        assert_eq!(sanitize_name("../../x"), "__/__/x");
        assert_eq!(sanitize_name("C:\\win\\x"), "win/x");
        assert_eq!(sanitize_name("/etc/./x"), "etc/x");
    }

    #[test]
    fn same_index_every_time() {
        crate::diag::set_quiet(true);
        let d = tmp("determinism");
        let p = d.join("r.tar");
        std::fs::write(&p, rich_tar()).unwrap();
        let list = |fs: &TarFs| {
            let mut out = Vec::new();
            walk(fs, "/", &WalkOptions::default(), &mut |e| {
                out.push(format!("{:?}", e));
                WalkStep::Continue
            });
            out
        };
        let a = list(&TarFs::open(&p).unwrap());
        let b = list(&TarFs::open(&p).unwrap());
        assert_eq!(a, b);
        assert!(a.len() > 10);
    }
}
