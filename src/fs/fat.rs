//! FAT12, FAT16 and FAT32 volumes, read-only: the EFI system partition of every GPT disk,
//! USB sticks, SD cards, camera and phone storage.
//!
//! Long file names (VFAT) are used when their checksum matches the short entry, the 8.3
//! name otherwise (with the Windows NT lower-case flags). Times are what the directory
//! entry holds: created (to 10 ms), modified (to 2 s) and accessed (a date). FAT stores
//! local time without a zone; they are returned as if UTC, like zip times, and say so in
//! the log. Deleted entries (first byte 0xE5) are listed under [`DELETED_DIR`] with their
//! name rebuilt from the long name when it survived; their content is read back when the
//! clusters a contiguous file would occupy are all still free.
//!
//! References: Microsoft, *FAT32 File System Specification* (FAT: General Overview of
//! On-Disk Format, 1.03, 2000); Brian Carrier, *File System Forensic Analysis*, ch. 9-10.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::diag;
use crate::error::{Error, Result};
use crate::fs::{code as fscode, deleted_path, is_deleted_root, join, normalize, parse_deleted, Entry, EntryKind, FileSystem, FsKind, Progress, Sink, DELETED_DIR};
use crate::source::SharedReader;
use crate::time::{Timestamp, Timestamps};

pub mod code {
    crate::codes! {
        FAT_OPEN = 800, "the volume's boot sector could not be parsed as FAT: bytes per sector, sectors per cluster, the FAT count or size, or the cluster count is impossible; the partition offset is wrong or the boot sector is damaged (FAT32 keeps a backup at sector 6)";
        FAT_OPENED = 801, "a FAT volume was opened: FAT12, FAT16 or FAT32, cluster size, clusters, size and label";
        FAT_TABLE_TOO_BIG = 802, "the file allocation table is larger than 256 MB (a FAT32 volume of several TB): it is not loaded and the volume is not read";
        FAT_TABLE_READ = 803, "the file allocation table could not be read; the image is truncated inside it";
        FAT_CHAIN = 804, "a cluster chain ends early (a free, bad or out-of-range cluster) or loops; the content read up to there is kept, a directory lists what was read";
        FAT_LFN_MISMATCH = 805, "a long file name's checksum does not match the short entry after it (left by a tool that ignores long names); the 8.3 name is used";
        FAT_DELETED = 806, "deleted directory entries (first byte 0xE5) were found and listed under $DELETED; the message says how many and how many can still be read back";
        FAT_DELETED_REUSED = 807, "a deleted entry's clusters are allocated again: its name, size and times are listed, its content is not read back";
        FAT_DIR_LOOP = 808, "a directory's first cluster is one of its ancestors' (damage or a crafted volume); it was not descended into";
        FAT_LOCAL_TIME = 809, "FAT stores local time without a zone; this volume's times are shown as if they were UTC";
        FAT_READ = 810, "reading clusters failed; the image is truncated or the medium is failing there";
    }
}

/// Largest allocation table loaded (in bytes).
const MAX_FAT_BYTES: u64 = 256 << 20;
/// Directory entries flags.
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_LFN: u8 = 0x0F;

/// Which FAT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

impl FatType {
    pub fn label(self) -> &'static str {
        match self {
            FatType::Fat12 => "FAT12",
            FatType::Fat16 => "FAT16",
            FatType::Fat32 => "FAT32",
        }
    }

    fn end_of_chain(self) -> u32 {
        match self {
            FatType::Fat12 => 0xFF8,
            FatType::Fat16 => 0xFFF8,
            FatType::Fat32 => 0x0FFF_FFF8,
        }
    }
}

/// A live directory entry and where its data starts.
#[derive(Clone, Debug)]
struct Item {
    entry: Entry,
    first: u32,
}

/// A deleted directory entry.
#[derive(Clone, Debug)]
struct Gone {
    entry: Entry,
    first: u32,
}

/// What one directory's entries say.
#[derive(Default)]
struct Parsed {
    live: Vec<Item>,
    gone: Vec<Gone>,
    label: Option<String>,
}

/// A FAT12/16/32 volume.
pub struct FatFs {
    r: SharedReader,
    ty: FatType,
    cluster: u64,
    data_start: u64,
    /// FAT12/16: the fixed root directory region.
    root_start: u64,
    root_len: u64,
    /// FAT32: the root directory's first cluster.
    root_cluster: u32,
    clusters: u32,
    fat: Vec<u32>,
    label: Option<String>,
    size: u64,
    dirs: Mutex<HashMap<String, Arc<Vec<Item>>>>,
    gone: Mutex<Option<Arc<Vec<Gone>>>>,
    label_for_logs: String,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// A FAT date and time (local, taken as UTC); `hundredths` is the creation fine time
/// (0-199, in units of 10 ms).
fn fat_time(date: u16, time: u16, hundredths: u8) -> Option<Timestamp> {
    if date == 0 {
        return None;
    }
    let year = 1980 + i32::from(date >> 9);
    let month = u32::from((date >> 5) & 0x0F);
    let day = u32::from(date & 0x1F);
    let hour = u32::from(time >> 11);
    let minute = u32::from((time >> 5) & 0x3F);
    let second = u32::from(time & 0x1F) * 2 + u32::from(hundredths) / 100;
    let t = Timestamp::from_civil(year, month, day, hour, minute, second.min(59))?;
    Some(Timestamp::from_unix(t.secs, (u32::from(hundredths) % 100) * 10_000_000))
}

/// The checksum a long name's entries carry of their short name.
fn lfn_checksum(short: &[u8]) -> u8 {
    short.iter().fold(0u8, |sum, &b| (if sum & 1 != 0 { 0x80u8 } else { 0 }).wrapping_add(sum >> 1).wrapping_add(b))
}

/// The UTF-16 units of one long-name entry, in order.
fn lfn_units(e: &[u8]) -> Vec<u16> {
    let mut v = Vec::with_capacity(13);
    for range in [1..11, 14..26, 28..32] {
        for i in range.step_by(2) {
            v.push(u16_at(e, i));
        }
    }
    v
}

/// A long name from its entries in sequence order (1, 2, ...).
fn lfn_text(parts: &[Vec<u16>]) -> String {
    let units: Vec<u16> = parts.iter().flatten().copied().take_while(|&u| u != 0x0000).filter(|&u| u != 0xFFFF).collect();
    String::from_utf16_lossy(&units)
}

/// The 8.3 name of a short entry, with the NT lower-case flags (byte 12).
fn short_name(e: &[u8]) -> String {
    let mut base: Vec<u8> = e[0..8].to_vec();
    if base[0] == 0x05 {
        base[0] = 0xE5;
    }
    let text = |b: &[u8], lower: bool| -> String {
        let s: String = b.iter().map(|&c| c as char).collect::<String>().trim_end().to_string();
        if lower {
            s.to_ascii_lowercase()
        } else {
            s
        }
    };
    let flags = e[12];
    let b = text(&base, flags & 0x08 != 0);
    let x = text(&e[8..11], flags & 0x10 != 0);
    if x.is_empty() {
        b
    } else {
        format!("{b}.{x}")
    }
}

impl FatFs {
    /// Opens the volume whose first byte is the boot sector.
    pub fn open(volume: SharedReader, label_for_logs: &str) -> Result<Self> {
        let bad = |why: &str| Error::recorded(code::FAT_OPEN, format!("{label_for_logs}: {why}"));
        let bs = volume.bytes_at(0, 512).ok_or_else(|| bad("boot sector unreadable"))?;
        let bps = u64::from(u16_at(&bs, 11));
        let spc = u64::from(bs[13]);
        let reserved = u64::from(u16_at(&bs, 14));
        let nfats = u64::from(bs[16]);
        let root_entries = u64::from(u16_at(&bs, 17));
        let total16 = u64::from(u16_at(&bs, 19));
        let fatsz16 = u64::from(u16_at(&bs, 22));
        let total32 = u64::from(u32_at(&bs, 32));
        let fatsz32 = u64::from(u32_at(&bs, 36));
        if !matches!(bps, 512 | 1024 | 2048 | 4096) {
            return Err(bad(&format!("bytes per sector {bps}")));
        }
        if spc == 0 || !spc.is_power_of_two() || spc * bps > 256 * 1024 {
            return Err(bad(&format!("sectors per cluster {spc}")));
        }
        if reserved == 0 || nfats == 0 || nfats > 4 {
            return Err(bad(&format!("reserved sectors {reserved}, FAT count {nfats}")));
        }
        let fatsz = if fatsz16 != 0 { fatsz16 } else { fatsz32 };
        let total = if total16 != 0 { total16 } else { total32 };
        if fatsz == 0 || total == 0 {
            return Err(bad("FAT size or sector count is zero"));
        }
        let root_sectors = (root_entries * 32).div_ceil(bps);
        let meta = reserved + nfats * fatsz + root_sectors;
        if meta >= total {
            return Err(bad(&format!("{meta} metadata sectors for {total} sectors")));
        }
        let clusters64 = (total - meta) / spc;
        if clusters64 == 0 || clusters64 > 0x0FFF_FFF5 {
            return Err(bad(&format!("{clusters64} clusters")));
        }
        let clusters = clusters64 as u32;
        let ty = if clusters < 4085 {
            FatType::Fat12
        } else if clusters < 65525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        };
        if ty == FatType::Fat32 && root_entries != 0 {
            return Err(bad("FAT32 with a fixed root directory"));
        }
        let entries = u64::from(clusters) + 2;
        let fat_bytes = match ty {
            FatType::Fat12 => (entries * 3).div_ceil(2),
            FatType::Fat16 => entries * 2,
            FatType::Fat32 => entries * 4,
        }
        .min(fatsz * bps);
        if fat_bytes > MAX_FAT_BYTES {
            return Err(Error::recorded(code::FAT_TABLE_TOO_BIG, format!("{label_for_logs}: {fat_bytes} bytes")));
        }
        let raw = volume.bytes_at(reserved * bps, fat_bytes as usize).ok_or_else(|| Error::recorded(code::FAT_TABLE_READ, format!("{label_for_logs}: {fat_bytes} bytes at {}", reserved * bps)))?;
        let fat: Vec<u32> = (0..entries as usize)
            .map(|i| match ty {
                FatType::Fat12 => {
                    let at = i + i / 2;
                    if at + 1 >= raw.len() {
                        return 0;
                    }
                    let v = u16_at(&raw, at);
                    u32::from(if i % 2 == 0 { v & 0x0FFF } else { v >> 4 })
                }
                FatType::Fat16 => raw.get(i * 2..i * 2 + 2).map_or(0, |b| u32::from(u16_at(b, 0))),
                FatType::Fat32 => raw.get(i * 4..i * 4 + 4).map_or(0, |b| u32_at(b, 0) & 0x0FFF_FFFF),
            })
            .collect();
        let label_at = if ty == FatType::Fat32 { 71 } else { 43 };
        let boot_label = bs.get(label_at..label_at + 11).map(|b| b.iter().map(|&c| c as char).collect::<String>().trim_end().to_string()).filter(|s| !s.is_empty() && s != "NO NAME");
        let mut fs = FatFs {
            ty,
            cluster: spc * bps,
            data_start: meta * bps,
            root_start: (reserved + nfats * fatsz) * bps,
            root_len: root_sectors * bps,
            root_cluster: if ty == FatType::Fat32 { u32_at(&bs, 44) } else { 0 },
            clusters,
            fat,
            label: boot_label,
            size: total * bps,
            dirs: Mutex::new(HashMap::new()),
            gone: Mutex::new(None),
            label_for_logs: label_for_logs.to_string(),
            r: volume,
        };
        if let Ok(root) = fs.dir_bytes(0, "/") {
            if let Some(l) = parse(&root, "/", 0, &fs).label {
                fs.label = Some(l);
            }
        }
        diag::info(code::FAT_OPENED, format!("{label_for_logs}: {}, cluster {} bytes, {} clusters, {}{}", ty.label(), fs.cluster, clusters, crate::volume::human_size(fs.size), fs.label.as_deref().map(|l| format!(", label {l}")).unwrap_or_default()));
        diag::info(code::FAT_LOCAL_TIME, label_for_logs.to_string());
        Ok(fs)
    }

    /// FAT12, FAT16 or FAT32.
    pub fn fat_type(&self) -> FatType {
        self.ty
    }

    fn valid(&self, c: u32) -> bool {
        c >= 2 && c < self.clusters + 2
    }

    fn offset(&self, c: u32) -> u64 {
        self.data_start + u64::from(c - 2) * self.cluster
    }

    /// The clusters of a chain, in order; `want` stops it once enough are collected.
    fn chain(&self, first: u32, want: Option<u64>, what: &str) -> Vec<u32> {
        let mut out = Vec::new();
        let mut c = first;
        let eoc = self.ty.end_of_chain();
        while self.valid(c) {
            out.push(c);
            if want.is_some_and(|w| out.len() as u64 >= w) {
                return out;
            }
            if out.len() > self.clusters as usize {
                diag::warn(code::FAT_CHAIN, format!("{}: {what}: loop at cluster {c}", self.label_for_logs));
                return out;
            }
            let next = self.fat[c as usize];
            if next >= eoc {
                return out;
            }
            if !self.valid(next) {
                diag::warn(code::FAT_CHAIN, format!("{}: {what}: cluster {c} points to {next:#x}", self.label_for_logs));
                return out;
            }
            c = next;
        }
        if first != 0 && out.is_empty() {
            diag::warn(code::FAT_CHAIN, format!("{}: {what}: first cluster {first:#x} out of range", self.label_for_logs));
        }
        out
    }

    /// Reads runs of clusters, joining contiguous ones into one read.
    fn read_clusters(&self, clusters: &[u32], mut each: impl FnMut(&[u8]) -> Result<bool>) -> Result<()> {
        let mut i = 0;
        while i < clusters.len() {
            let mut j = i + 1;
            while j < clusters.len() && clusters[j] == clusters[j - 1] + 1 && j - i < 256 {
                j += 1;
            }
            let mut buf = vec![0u8; (j - i) * self.cluster as usize];
            self.r.read_at(self.offset(clusters[i]), &mut buf).map_err(|e| Error::recorded(code::FAT_READ, format!("{}: cluster {}: {e}", self.label_for_logs, clusters[i])))?;
            if !each(&buf)? {
                return Ok(());
            }
            i = j;
        }
        Ok(())
    }

    /// The raw entries of a directory (`first` 0: the root).
    fn dir_bytes(&self, first: u32, what: &str) -> Result<Vec<u8>> {
        if first == 0 && self.ty != FatType::Fat32 {
            let mut buf = vec![0u8; self.root_len as usize];
            self.r.read_at(self.root_start, &mut buf).map_err(|e| Error::recorded(code::FAT_READ, format!("{}: root directory: {e}", self.label_for_logs)))?;
            return Ok(buf);
        }
        let start = if first == 0 { self.root_cluster } else { first };
        let mut out = Vec::new();
        let chain = self.chain(start, None, what);
        self.read_clusters(&chain, |b| {
            out.extend_from_slice(b);
            Ok(out.len() < 64 << 20)
        })?;
        Ok(out)
    }

    fn root_entry(&self) -> Entry {
        Entry::new("/", EntryKind::Dir)
    }

    fn deleted_root_entry(&self) -> Entry {
        let mut e = Entry::new(&format!("/{DELETED_DIR}"), EntryKind::Dir);
        e.deleted = true;
        e
    }

    /// The live entries of a directory, cached.
    fn list(&self, path: &str) -> Result<Arc<Vec<Item>>> {
        let norm = normalize(path);
        let key = norm.to_lowercase();
        if let Some(v) = self.dirs.lock().map_err(|_| Error::new(fscode::FS_READ, "FAT directory cache"))?.get(&key) {
            return Ok(Arc::clone(v));
        }
        // The folder's path as the volume spells it (lookups ignore case, paths do not).
        let (first, canonical) = if norm == "/" {
            (0, norm.clone())
        } else {
            let (parent, name) = norm.rsplit_once('/').map(|(p, n)| (if p.is_empty() { "/" } else { p }, n)).unwrap_or(("/", norm.as_str()));
            let siblings = self.list(parent)?;
            let it = siblings.iter().find(|i| i.entry.name.eq_ignore_ascii_case(name) || i.entry.name.to_lowercase() == name.to_lowercase()).ok_or_else(|| Error::new(fscode::FS_NOT_FOUND, path.to_string()))?;
            if it.entry.kind != EntryKind::Dir {
                return Err(Error::new(fscode::FS_NOT_A_DIR, path.to_string()));
            }
            (it.first, it.entry.path.clone())
        };
        let bytes = self.dir_bytes(first, &canonical)?;
        let mut parsed = parse(&bytes, &canonical, first, self);
        parsed.live.sort_by(|a, b| a.entry.name.cmp(&b.entry.name));
        let v = Arc::new(parsed.live);
        self.dirs.lock().map_err(|_| Error::new(fscode::FS_READ, "FAT directory cache"))?.insert(key, Arc::clone(&v));
        Ok(v)
    }

    fn find(&self, path: &str) -> Result<Item> {
        let norm = normalize(path);
        if norm == "/" {
            return Ok(Item { entry: self.root_entry(), first: 0 });
        }
        let (parent, name) = norm.rsplit_once('/').map(|(p, n)| (if p.is_empty() { "/" } else { p }, n)).unwrap_or(("/", norm.as_str()));
        let siblings = self.list(parent)?;
        siblings.iter().find(|i| i.entry.name.eq_ignore_ascii_case(name) || i.entry.name.to_lowercase() == name.to_lowercase()).cloned().ok_or_else(|| Error::new(fscode::FS_NOT_FOUND, path.to_string()))
    }

    /// Every deleted entry of the volume: a walk of the live tree, done once.
    fn gone_list(&self) -> Result<Arc<Vec<Gone>>> {
        if let Some(g) = self.gone.lock().map_err(|_| Error::new(fscode::FS_READ, "FAT deleted cache"))?.as_ref() {
            return Ok(Arc::clone(g));
        }
        let mut all = Vec::new();
        let mut stack: Vec<(String, u32, Vec<u32>)> = vec![("/".to_string(), 0, Vec::new())];
        while let Some((path, first, ancestors)) = stack.pop() {
            let bytes = match self.dir_bytes(first, &path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let parsed = parse(&bytes, &path, first, self);
            all.extend(parsed.gone);
            for it in parsed.live {
                if it.entry.kind == EntryKind::Dir && it.first != 0 {
                    if it.first == first || ancestors.contains(&it.first) {
                        diag::warn(code::FAT_DIR_LOOP, format!("{}: {}", self.label_for_logs, it.entry.path));
                        continue;
                    }
                    let mut a = ancestors.clone();
                    a.push(first);
                    stack.push((it.entry.path.clone(), it.first, a));
                }
            }
        }
        all.sort_by(|a, b| a.entry.path.cmp(&b.entry.path));
        let readable = all.iter().filter(|g| g.entry.recoverable).count();
        if !all.is_empty() {
            diag::info(code::FAT_DELETED, format!("{}: {} deleted entr{}, {readable} readable", self.label_for_logs, all.len(), if all.len() == 1 { "y" } else { "ies" }));
        }
        let v = Arc::new(all);
        *self.gone.lock().map_err(|_| Error::new(fscode::FS_READ, "FAT deleted cache"))? = Some(Arc::clone(&v));
        Ok(v)
    }

    fn find_gone(&self, path: &str) -> Result<Gone> {
        let norm = normalize(path);
        self.gone_list()?.iter().find(|g| g.entry.path.eq_ignore_ascii_case(&norm)).cloned().ok_or_else(|| Error::new(fscode::FS_NOT_FOUND, path.to_string()))
    }

    /// Whether the clusters a contiguous file of `size` bytes from `first` would take are all free.
    fn contiguous_free(&self, first: u32, size: u64) -> bool {
        let n = size.div_ceil(self.cluster);
        if n == 0 {
            return true;
        }
        if !self.valid(first) || u64::from(first) + n > u64::from(self.clusters) + 2 {
            return false;
        }
        (first..first + n as u32).all(|c| self.fat[c as usize] == 0)
    }

    fn stream(&self, clusters: &[u32], size: u64, sink: Sink<'_>, mut progress: Option<Progress<'_>>) -> Result<u64> {
        let mut left = size;
        let mut done = 0u64;
        self.read_clusters(clusters, |b| {
            let take = (b.len() as u64).min(left) as usize;
            sink.write_all(&b[..take]).map_err(|e| Error::new(fscode::FS_READ, e.to_string()))?;
            left -= take as u64;
            done += take as u64;
            if let Some(p) = progress.as_mut() {
                p(done, size);
            }
            Ok(left > 0)
        })?;
        Ok(done)
    }
}

/// Parses the 32-byte entries of a directory whose path is `dir`.
fn parse(bytes: &[u8], dir: &str, dir_first: u32, fs: &FatFs) -> Parsed {
    let mut out = Parsed::default();
    let mut lfn: Vec<(u8, u8, Vec<u16>)> = Vec::new();
    let mut gone_lfn: Vec<(u8, Vec<u16>)> = Vec::new();
    for (slot, e) in bytes.chunks_exact(32).enumerate() {
        let first = e[0];
        if first == 0x00 {
            break;
        }
        let attr = e[11];
        if attr == ATTR_LFN {
            if first == 0xE5 {
                gone_lfn.push((e[13], lfn_units(e)));
            } else {
                lfn.push((first & 0x1F, e[13], lfn_units(e)));
                gone_lfn.clear();
            }
            continue;
        }
        if attr & ATTR_VOLUME_ID != 0 {
            if dir == "/" && first != 0xE5 && attr & ATTR_DIRECTORY == 0 {
                let l: String = e[0..11].iter().map(|&c| c as char).collect::<String>().trim_end().to_string();
                if !l.is_empty() {
                    out.label = Some(l);
                }
            }
            lfn.clear();
            gone_lfn.clear();
            continue;
        }
        let is_dir = attr & ATTR_DIRECTORY != 0;
        let first_cluster = if fs.ty == FatType::Fat32 { (u32::from(u16_at(e, 20)) << 16) | u32::from(u16_at(e, 26)) } else { u32::from(u16_at(e, 26)) };
        let size = if is_dir { 0 } else { u64::from(u32_at(e, 28)) };
        let times = Timestamps {
            created: fat_time(u16_at(e, 16), u16_at(e, 14), e[13]),
            modified: fat_time(u16_at(e, 24), u16_at(e, 22), 0),
            accessed: fat_time(u16_at(e, 18), 0, 0),
            changed: None,
        };
        let kind = if is_dir { EntryKind::Dir } else { EntryKind::File };
        if first == 0xE5 {
            // Deleted: the long name's entries are in reverse order on disk, and their first
            // byte (the sequence number) is lost too, so they are taken in disk order reversed.
            let parts: Vec<Vec<u16>> = gone_lfn.drain(..).rev().map(|(_, u)| u).collect();
            let long = lfn_text(&parts);
            // The short name lost its first character; the long name, when it survived, did not.
            let name = if long.is_empty() { format!("_{}", short_name(e).chars().skip(1).collect::<String>()) } else { long };
            if name == "_" || name.starts_with("_.") && name.len() <= 2 {
                continue;
            }
            let original = join(dir, &name);
            let id = if dir_first == 0 { format!("root.{slot}") } else { format!("c{dir_first}.{slot}") };
            let mut en = Entry::new(&deleted_path(&id, &original), kind);
            en.size = size;
            en.times = times;
            en.id = u64::from(first_cluster);
            en.deleted = true;
            en.recoverable = !is_dir && fs.contiguous_free(first_cluster, size);
            if !is_dir && !en.recoverable && size > 0 {
                diag::info(code::FAT_DELETED_REUSED, format!("{}: {original}", fs.label_for_logs));
            }
            out.gone.push(Gone { entry: en, first: first_cluster });
            continue;
        }
        gone_lfn.clear();
        let short = short_name(e);
        if short == "." || short == ".." {
            lfn.clear();
            continue;
        }
        let mut name = short.clone();
        if !lfn.is_empty() {
            let sum = lfn_checksum(&e[0..11]);
            if lfn.iter().all(|(_, s, _)| *s == sum) {
                let mut parts = lfn.clone();
                parts.sort_by_key(|(seq, _, _)| *seq);
                let long = lfn_text(&parts.into_iter().map(|(_, _, u)| u).collect::<Vec<_>>());
                if !long.is_empty() {
                    name = long;
                }
            } else {
                diag::info(code::FAT_LFN_MISMATCH, format!("{}: {}", fs.label_for_logs, join(dir, &short)));
            }
            lfn.clear();
        }
        let mut en = Entry::new(&join(dir, &name), kind);
        en.size = size;
        en.times = times;
        en.id = u64::from(first_cluster);
        out.live.push(Item { entry: en, first: first_cluster });
    }
    out
}

impl FileSystem for FatFs {
    fn kind(&self) -> FsKind {
        FsKind::Fat
    }

    fn label(&self) -> Option<String> {
        self.label.clone()
    }

    fn size(&self) -> Option<u64> {
        Some(self.size)
    }

    fn supports_deleted(&self) -> bool {
        true
    }

    fn deleted(&self, progress: Option<Progress<'_>>) -> Result<Vec<Entry>> {
        let list = self.gone_list()?;
        if let Some(p) = progress {
            p(1, 1);
        }
        Ok(list.iter().map(|g| g.entry.clone()).collect())
    }

    fn metadata(&self, path: &str) -> Result<Entry> {
        if is_deleted_root(path) {
            return Ok(self.deleted_root_entry());
        }
        if parse_deleted(path).is_some() {
            return Ok(self.find_gone(path)?.entry);
        }
        Ok(self.find(path)?.entry)
    }

    fn read_dir(&self, path: &str) -> Result<Vec<Entry>> {
        if is_deleted_root(path) {
            return Ok(self.gone_list()?.iter().map(|g| g.entry.clone()).collect());
        }
        if parse_deleted(path).is_some() {
            let g = self.find_gone(path)?;
            return Err(Error::new(if g.entry.kind == EntryKind::Dir { fscode::FS_DELETED_UNRECOVERABLE } else { fscode::FS_NOT_A_DIR }, path.to_string()));
        }
        let it = self.find(path)?;
        if it.entry.kind != EntryKind::Dir {
            return Err(Error::new(fscode::FS_NOT_A_DIR, path.to_string()));
        }
        Ok(self.list(path)?.iter().map(|i| i.entry.clone()).collect())
    }

    fn copy_to(&self, path: &str, stream: Option<&str>, sink: Sink<'_>, progress: Option<Progress<'_>>) -> Result<u64> {
        if let Some(s) = stream.filter(|s| !s.is_empty()) {
            return Err(Error::new(fscode::FS_STREAM_NOT_FOUND, format!("{path}:{s}")));
        }
        if parse_deleted(path).is_some() {
            let g = self.find_gone(path)?;
            if g.entry.kind == EntryKind::Dir {
                return Err(Error::new(fscode::FS_NOT_A_FILE, path.to_string()));
            }
            if !g.entry.recoverable {
                return Err(Error::new(fscode::FS_DELETED_UNRECOVERABLE, format!("{path}: clusters allocated again")));
            }
            let n = g.entry.size.div_ceil(self.cluster) as u32;
            let clusters: Vec<u32> = (g.first..g.first + n).collect();
            return self.stream(&clusters, g.entry.size, sink, progress);
        }
        let it = self.find(path)?;
        if it.entry.kind != EntryKind::File {
            return Err(Error::new(fscode::FS_NOT_A_FILE, path.to_string()));
        }
        let want = it.entry.size.div_ceil(self.cluster);
        let clusters = self.chain(it.first, Some(want), &it.entry.path);
        if (clusters.len() as u64) < want {
            diag::warn(code::FAT_CHAIN, format!("{}: {path}: {} of {want} clusters", self.label_for_logs, clusters.len()));
        }
        self.stream(&clusters, it.entry.size, sink, progress)
    }
}

#[cfg(test)]
pub mod testutil {
    //! A tiny FAT formatter for tests.

    /// One file or folder to put on a test volume: path (`/`-separated, no leading slash),
    /// content (None for a folder).
    pub struct Node<'a> {
        pub path: &'a str,
        pub data: Option<&'a [u8]>,
    }

    fn lfn_entries(long: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
        let sum = super::lfn_checksum(short);
        let mut units: Vec<u16> = long.encode_utf16().collect();
        units.push(0);
        while !units.len().is_multiple_of(13) {
            units.push(0xFFFF);
        }
        let n = units.len() / 13;
        let mut out = Vec::new();
        for seq in (1..=n).rev() {
            let mut e = [0u8; 32];
            e[0] = seq as u8 | if seq == n { 0x40 } else { 0 };
            e[11] = 0x0F;
            e[13] = sum;
            let part = &units[(seq - 1) * 13..seq * 13];
            let mut k = 0;
            for range in [1..11, 14..26, 28..32] {
                for i in range.step_by(2) {
                    e[i..i + 2].copy_from_slice(&part[k].to_le_bytes());
                    k += 1;
                }
            }
            out.push(e);
        }
        out
    }

    /// A FAT volume of `sectors` 512-byte sectors, `spc` sectors per cluster, FAT32 when
    /// `fat32`. Every name gets a long-name entry and an upper-case 8.3 alias `Fn~1`-style.
    /// Times: created 2026-11-11 10:20:30.50, modified 2026-11-11 10:21:32, accessed 2026-11-11.
    /// `deleted` names a file (by path) whose entry is then marked deleted (0xE5) and its
    /// clusters freed.
    pub fn volume(sectors: u32, spc: u8, fat32: bool, nodes: &[Node<'_>], deleted: Option<&str>) -> Vec<u8> {
        let bps = 512usize;
        let reserved = if fat32 { 32 } else { 1 };
        let root_entries: usize = if fat32 { 0 } else { 512 };
        let nfats = 2;
        let total = sectors as usize;
        // Size the FAT for the worst case.
        let clusters_guess = total / spc as usize;
        let fat_bytes = if fat32 { (clusters_guess + 2) * 4 } else if clusters_guess < 4085 { (clusters_guess + 2) * 3 / 2 + 1 } else { (clusters_guess + 2) * 2 };
        let fatsz = fat_bytes.div_ceil(bps);
        let root_sectors = (root_entries * 32).div_ceil(bps);
        let data_start = (reserved + nfats * fatsz + root_sectors) * bps;
        let clusters = (total - reserved - nfats * fatsz - root_sectors) / spc as usize;
        let ty = if clusters < 4085 { 12 } else if clusters < 65525 { 16 } else { 32 };
        assert_eq!(ty == 32, fat32, "{clusters} clusters");
        let cs = spc as usize * bps;
        let mut img = vec![0u8; total * bps];
        img[0] = 0xEB;
        img[11..13].copy_from_slice(&(bps as u16).to_le_bytes());
        img[13] = spc;
        img[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
        img[16] = nfats as u8;
        img[17..19].copy_from_slice(&(root_entries as u16).to_le_bytes());
        if total < 65536 && !fat32 {
            img[19..21].copy_from_slice(&(total as u16).to_le_bytes());
        } else {
            img[32..36].copy_from_slice(&(total as u32).to_le_bytes());
        }
        if fat32 {
            img[36..40].copy_from_slice(&(fatsz as u32).to_le_bytes());
            img[44..48].copy_from_slice(&2u32.to_le_bytes());
            img[71..82].copy_from_slice(b"EFI        ");
            img[82..90].copy_from_slice(b"FAT32   ");
        } else {
            img[22..24].copy_from_slice(&(fatsz as u16).to_le_bytes());
            img[43..54].copy_from_slice(b"TESTVOL    ");
            img[54..62].copy_from_slice(if ty == 12 { b"FAT12   " } else { b"FAT16   " });
        }
        img[510] = 0x55;
        img[511] = 0xAA;
        let mut fat = vec![0u32; clusters + 2];
        fat[0] = 0x0FFF_FFF8;
        fat[1] = 0x0FFF_FFFF;
        let eoc = 0x0FFF_FFFF;
        let mut next_free = 2usize;
        let mut alloc = |n: usize, fat: &mut Vec<u32>| -> u32 {
            let first = next_free;
            for i in 0..n {
                fat[first + i] = if i + 1 == n { eoc } else { (first + i + 1) as u32 };
            }
            next_free += n;
            first as u32
        };
        // Directories: path -> (first cluster, entries).
        let mut dirs: Vec<(String, u32, Vec<[u8; 32]>)> = vec![(String::new(), if fat32 { alloc(1, &mut fat) } else { 0 }, Vec::new())];
        let mut counter = 0u32;
        let mut deleted_clusters: Option<(u32, usize)> = None;
        for node in nodes {
            let (parent, name) = node.path.rsplit_once('/').unwrap_or(("", node.path));
            counter += 1;
            let mut short = [b' '; 11];
            let alias = format!("F{counter}~1");
            short[..alias.len()].copy_from_slice(alias.as_bytes());
            if let Some(dot) = name.rfind('.') {
                let ext = name[dot + 1..].to_ascii_uppercase();
                for (i, b) in ext.bytes().take(3).enumerate() {
                    short[8 + i] = b;
                }
            }
            let (first, size, attr) = match node.data {
                Some(d) => {
                    let n = d.len().div_ceil(cs);
                    let first = if n == 0 { 0 } else { alloc(n, &mut fat) };
                    if n > 0 {
                        let at = data_start + (first as usize - 2) * cs;
                        img[at..at + d.len()].copy_from_slice(d);
                    }
                    if deleted == Some(node.path) {
                        deleted_clusters = Some((first, n));
                    }
                    (first, d.len() as u32, 0x20u8)
                }
                None => {
                    let first = alloc(1, &mut fat);
                    dirs.push((node.path.to_string(), first, Vec::new()));
                    (first, 0, 0x10u8)
                }
            };
            let mut e = [0u8; 32];
            e[..11].copy_from_slice(&short);
            e[11] = attr;
            e[13] = 150; // created .50 s and +1 s
            let date: u16 = ((2026 - 1980) << 9) | (11 << 5) | 11;
            let ctime: u16 = (10 << 11) | (20 << 5) | 15;
            let mtime: u16 = (10 << 11) | (21 << 5) | 16;
            e[14..16].copy_from_slice(&ctime.to_le_bytes());
            e[16..18].copy_from_slice(&date.to_le_bytes());
            e[18..20].copy_from_slice(&date.to_le_bytes());
            e[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
            e[22..24].copy_from_slice(&mtime.to_le_bytes());
            e[24..26].copy_from_slice(&date.to_le_bytes());
            e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
            e[28..32].copy_from_slice(&size.to_le_bytes());
            let mut group = lfn_entries(name, &short);
            group.push(e);
            if deleted == Some(node.path) {
                for g in group.iter_mut() {
                    g[0] = 0xE5;
                }
            }
            let d = dirs.iter_mut().find(|(p, _, _)| p == parent).expect("parent folder listed first");
            d.2.extend(group);
        }
        if let Some((first, n)) = deleted_clusters {
            for i in 0..n {
                fat[first as usize + i] = 0;
            }
        }
        // Write the directories.
        for (path, first, entries) in &dirs {
            let mut bytes: Vec<u8> = Vec::new();
            if !path.is_empty() {
                let mut dot = [b' '; 32];
                dot[..11].copy_from_slice(b".          ");
                dot[11] = 0x10;
                dot[12..].fill(0);
                bytes.extend_from_slice(&dot);
                let mut dotdot = dot;
                dotdot[1] = b'.';
                bytes.extend_from_slice(&dotdot);
            }
            for e in entries {
                bytes.extend_from_slice(e);
            }
            let at = if path.is_empty() && !fat32 { (reserved + nfats * fatsz) * bps } else { data_start + (*first as usize - 2) * cs };
            let room = if path.is_empty() && !fat32 { root_sectors * bps } else { cs };
            assert!(bytes.len() <= room, "test folder {path:?} too big for one cluster");
            img[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        // Write the FATs.
        for copy in 0..nfats {
            let base = (reserved + copy * fatsz) * bps;
            for (i, v) in fat.iter().enumerate() {
                match ty {
                    12 => {
                        let at = base + i + i / 2;
                        let cur = u16::from_le_bytes([img[at], img[at + 1]]);
                        let v12 = (*v & 0x0FFF) as u16;
                        let new = if i % 2 == 0 { (cur & 0xF000) | v12 } else { (cur & 0x000F) | (v12 << 4) };
                        img[at..at + 2].copy_from_slice(&new.to_le_bytes());
                    }
                    16 => img[base + i * 2..base + i * 2 + 2].copy_from_slice(&((*v & 0xFFFF) as u16).to_le_bytes()),
                    _ => img[base + i * 4..base + i * 4 + 4].copy_from_slice(&v.to_le_bytes()),
                }
            }
        }
        img
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{volume, Node};
    use super::*;

    fn quiet() {
        crate::diag::set_quiet(true);
    }

    fn open(img: Vec<u8>) -> FatFs {
        FatFs::open(SharedReader::from_bytes(img), "test").expect("opens")
    }

    fn tree() -> Vec<Node<'static>> {
        vec![
            Node { path: "EFI", data: None },
            Node { path: "EFI/Microsoft", data: None },
            Node { path: "EFI/Microsoft/Boot", data: None },
            Node { path: "EFI/Microsoft/Boot/bootmgfw.efi", data: Some(b"MZ\x90\x00 a boot manager") },
            Node { path: "EFI/Boot", data: None },
            Node { path: "EFI/Boot/bootx64.efi", data: Some(&[0x42; 5000]) },
            Node { path: "A long file name with spaces.txt", data: Some(b"long name content") },
            Node { path: "gone.txt", data: Some(b"deleted but still here") },
            Node { path: "empty.dat", data: Some(b"") },
        ]
    }

    fn check(fs: &FatFs) {
        let root = fs.read_dir("/").unwrap();
        let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["A long file name with spaces.txt", "EFI", "empty.dat"], "deleted gone.txt is not in the live listing");
        let e = fs.metadata("/efi/microsoft/BOOT/BootMgfw.EFI").expect("lookup ignores case");
        assert_eq!(e.path, "/EFI/Microsoft/Boot/bootmgfw.efi");
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(fs.read(&e.path, None, 1 << 20).unwrap(), b"MZ\x90\x00 a boot manager");
        let big = fs.read("/EFI/Boot/bootx64.efi", None, 1 << 20).unwrap();
        assert_eq!(big.len(), 5000, "across several clusters");
        assert!(big.iter().all(|&b| b == 0x42));
        assert_eq!(fs.read("/empty.dat", None, 10).unwrap(), b"");
        let t = e.times;
        assert_eq!(t.created.unwrap().to_rfc3339_micros(), "2026-11-11T10:20:31.500000Z");
        assert_eq!(t.modified.unwrap().to_rfc3339_micros(), "2026-11-11T10:21:32.000000Z");
        assert_eq!(t.accessed.unwrap().to_rfc3339_micros(), "2026-11-11T00:00:00.000000Z");
        assert!(matches!(fs.read_dir("/EFI/Boot/bootx64.efi"), Err(e) if e.code == fscode::FS_NOT_A_DIR));
        assert!(matches!(fs.metadata("/nope"), Err(e) if e.code == fscode::FS_NOT_FOUND));
        assert!(matches!(fs.copy_to("/EFI", None, &mut Vec::new(), None), Err(e) if e.code == fscode::FS_NOT_A_FILE));
        assert!(fs.supports_deleted());
        let gone = fs.deleted(None).unwrap();
        assert_eq!(gone.len(), 1, "{gone:?}");
        let g = &gone[0];
        assert!(g.deleted && g.recoverable);
        assert!(g.path.starts_with("/$DELETED/root."), "{}", g.path);
        assert!(g.path.ends_with("/gone.txt"), "the long name survives deletion: {}", g.path);
        assert_eq!(fs.read(&g.path, None, 100).unwrap(), b"deleted but still here");
        assert_eq!(fs.metadata(&g.path).unwrap().size, 22);
        assert_eq!(fs.read_dir("/$DELETED").unwrap().len(), 1);
        let mut walked = Vec::new();
        crate::fs::walk(fs, "/", &crate::fs::WalkOptions::default(), &mut |e: &Entry| {
            walked.push(e.path.clone());
            crate::fs::WalkStep::Continue
        });
        assert!(walked.contains(&"/EFI/Microsoft/Boot/bootmgfw.efi".to_string()), "{walked:?}");
    }

    #[test]
    fn fat12_volume() {
        quiet();
        let fs = open(volume(2880, 1, false, &tree(), Some("gone.txt")));
        assert_eq!(fs.fat_type(), FatType::Fat12);
        assert_eq!(fs.label().as_deref(), Some("TESTVOL"));
        assert_eq!(fs.kind(), FsKind::Fat);
        check(&fs);
    }

    #[test]
    fn fat16_volume() {
        quiet();
        let fs = open(volume(40_000, 1, false, &tree(), Some("gone.txt")));
        assert_eq!(fs.fat_type(), FatType::Fat16);
        check(&fs);
    }

    #[test]
    fn fat32_volume() {
        quiet();
        let fs = open(volume(140_000, 1, true, &tree(), Some("gone.txt")));
        assert_eq!(fs.fat_type(), FatType::Fat32);
        assert_eq!(fs.label().as_deref(), Some("EFI"));
        check(&fs);
    }

    #[test]
    fn deleted_file_whose_clusters_were_reused_is_listed_not_read() {
        quiet();
        let mut img = volume(2880, 1, false, &tree(), Some("gone.txt"));
        let fs = open(img.clone());
        let g = fs.deleted(None).unwrap()[0].clone();
        // Allocate the freed cluster again in both FATs.
        let first = g.id as usize;
        let bps = 512;
        let fatsz = u16::from_le_bytes([img[22], img[23]]) as usize;
        for copy in 0..2 {
            let at = bps + copy * fatsz * bps + first + first / 2;
            let cur = u16::from_le_bytes([img[at], img[at + 1]]);
            let new = if first.is_multiple_of(2) { (cur & 0xF000) | 0x0FFF } else { (cur & 0x000F) | 0xFFF0 };
            img[at..at + 2].copy_from_slice(&new.to_le_bytes());
        }
        let fs = open(img);
        let g = fs.deleted(None).unwrap()[0].clone();
        assert!(g.deleted && !g.recoverable);
        assert!(matches!(fs.read(&g.path, None, 100), Err(e) if e.code == fscode::FS_DELETED_UNRECOVERABLE));
        assert!(crate::diag::has(code::FAT_DELETED_REUSED));
    }

    #[test]
    fn bad_boot_sectors_are_refused_with_codes() {
        quiet();
        assert!(matches!(FatFs::open(SharedReader::from_bytes(vec![0u8; 4096]), "zero"), Err(e) if e.code == code::FAT_OPEN));
        let mut img = volume(2880, 1, false, &tree(), None);
        img[13] = 3;
        assert!(matches!(FatFs::open(SharedReader::from_bytes(img), "spc"), Err(e) if e.code == code::FAT_OPEN));
        assert!(matches!(FatFs::open(SharedReader::from_bytes(vec![0u8; 100]), "short"), Err(e) if e.code == code::FAT_OPEN));
    }

    #[test]
    fn broken_chain_keeps_what_was_read() {
        quiet();
        let mut img = volume(2880, 1, false, &tree(), None);
        let fs = open(img.clone());
        let first = fs.find("/EFI/Boot/bootx64.efi").unwrap().first as usize;
        // Mark the file's first cluster free: the chain stops after it.
        let bps = 512;
        let next = first + 1;
        let at = bps + next + next / 2;
        let cur = u16::from_le_bytes([img[at], img[at + 1]]);
        let new = if next.is_multiple_of(2) { cur & 0xF000 } else { cur & 0x000F };
        img[at..at + 2].copy_from_slice(&new.to_le_bytes());
        let fs = open(img);
        let got = fs.read("/EFI/Boot/bootx64.efi", None, 1 << 20).unwrap();
        assert!(got.len() < 5000 && !got.is_empty(), "{}", got.len());
        assert!(crate::diag::has(code::FAT_CHAIN));
    }

    #[test]
    fn names_and_times() {
        let mut e = [b' '; 32];
        e[..11].copy_from_slice(b"README  TXT");
        e[12] = 0x18;
        assert_eq!(short_name(&e), "readme.txt", "NT lower-case flags");
        e[12] = 0;
        e[0] = 0x05;
        assert_eq!(short_name(&e).chars().next(), Some('\u{e5}'), "0x05 stands for a leading 0xE5");
        assert_eq!(fat_time(0, 0, 0), None);
        let t = fat_time(((2001 - 1980) << 9) | (2 << 5) | 3, (4 << 11) | (5 << 5) | 3, 0).unwrap();
        assert_eq!(t.to_rfc3339_micros(), "2001-02-03T04:05:06.000000Z");
        assert_eq!(lfn_checksum(b"F1~1    TXT"), lfn_checksum(b"F1~1    TXT"));
    }
}
