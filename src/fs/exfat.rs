//! exFAT volumes, read-only: SDXC cards (every SD card over 32 GB), USB sticks and external
//! disks formatted by Windows or macOS, camera and phone storage.
//!
//! The boot sector gives the cluster size, where the file allocation table and the cluster
//! heap start, and the root directory's first cluster. A directory is a run of 32-byte
//! entries; a file is an entry set: a File entry (attributes and times), a Stream Extension
//! (first cluster, valid data length, size, and whether the clusters are contiguous and
//! need no FAT chain) and one File Name entry per 15 UTF-16 characters, protected by a
//! checksum. The root also holds the allocation bitmap (which clusters are in use) and the
//! volume label.
//!
//! Times have 10 ms precision for created and modified, 2 s for accessed, and usually a UTC
//! offset: they are returned in UTC when it is there, and as if UTC (with a code) when it
//! is not. A deleted file keeps its entry set with the in-use bit cleared; it is listed
//! under [`DELETED_DIR`], and its content is read back when every cluster it would occupy
//! is still free in the allocation bitmap. Bytes past a file's valid data length read as
//! zeros, as Windows returns them.
//!
//! Reference: Microsoft, *exFAT file system specification* (2019).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::diag;
use crate::error::{Error, Result};
use crate::fs::{code as fscode, deleted_path, is_deleted_root, join, normalize, parse_deleted, Entry, EntryKind, FileSystem, FsKind, Progress, Sink, DELETED_DIR};
use crate::source::SharedReader;
use crate::time::{Timestamp, Timestamps};

pub mod code {
    crate::codes! {
        EXFAT_OPEN = 820, "the volume's boot sector could not be parsed as exFAT: the sector or cluster size, the FAT or cluster heap position or the cluster count is impossible; the partition offset is wrong or the boot sector is damaged (exFAT keeps a backup boot region at sector 12)";
        EXFAT_OPENED = 821, "an exFAT volume was opened: cluster size, clusters, size, label and whether the allocation bitmap was found";
        EXFAT_FAT_READ = 822, "a block of the file allocation table could not be read (the image is truncated inside it): the chains through it end there";
        EXFAT_BITMAP = 823, "the allocation bitmap is missing, larger than 512 MB or unreadable: every cluster is taken as in use, so no deleted file is read back";
        EXFAT_CHAIN = 824, "a cluster chain ends early (a free, bad or out-of-range cluster) or loops: the content read up to there is kept, a directory lists what was read";
        EXFAT_SET_CHECKSUM = 825, "an entry set's checksum does not match its entries (a damaged directory, or a tool that does not update it): the file is still listed";
        EXFAT_SET_BROKEN = 826, "a File entry is not followed by its Stream Extension and File Name entries (a damaged or half-written directory): skipped";
        EXFAT_DELETED = 827, "deleted entry sets (in-use bit cleared) were found and listed under $DELETED: how many, and how many can still be read back";
        EXFAT_DELETED_REUSED = 828, "a deleted file's clusters are in use again: its name, size and times are listed, its content is not read back";
        EXFAT_DIR_LOOP = 829, "a directory's first cluster is one of its ancestors' (damage or a crafted volume): it was not descended into";
        EXFAT_NO_UTC_OFFSET = 830, "entries whose times carry no UTC offset (written by a system that does not set it, as older Linux drivers and some cameras): those times are local time, shown as if UTC";
        EXFAT_READ = 831, "reading clusters failed: the image is truncated or the medium is failing there";
        EXFAT_VALID_LENGTH = 832, "a file's valid data length is shorter than its size (space allocated, not yet written): the bytes past it read as zeros";
    }
}

/// Bytes of the FAT read at a time.
const FAT_BLOCK: u64 = 64 * 1024;
/// Largest allocation bitmap loaded.
const MAX_BITMAP: u64 = 512 << 20;
const ATTR_DIRECTORY: u16 = 0x10;
/// Entry types.
const T_END: u8 = 0x00;
const T_BITMAP: u8 = 0x81;
const T_LABEL: u8 = 0x83;
const T_FILE: u8 = 0x85;
const T_STREAM: u8 = 0xC0;
const T_NAME: u8 = 0xC1;
const IN_USE: u8 = 0x80;
/// Stream Extension flags.
const NO_FAT_CHAIN: u8 = 0x02;

/// Where a file's clusters are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Extent {
    first: u32,
    /// The clusters follow one another from `first`; the FAT is not used.
    contiguous: bool,
    /// Bytes allocated (DataLength).
    size: u64,
    /// Bytes written (ValidDataLength).
    valid: u64,
}

#[derive(Clone, Debug)]
struct Item {
    entry: Entry,
    ext: Extent,
}

#[derive(Default)]
struct Parsed {
    live: Vec<Item>,
    gone: Vec<Item>,
    label: Option<String>,
    bitmap: Option<(u32, u64)>,
    no_offset: usize,
}

/// An exFAT volume.
pub struct ExFatFs {
    r: SharedReader,
    cluster: u64,
    fat_start: u64,
    heap_start: u64,
    clusters: u32,
    root: u32,
    /// One bit per cluster from cluster 2: set when in use. None when not found.
    bitmap: Option<Vec<u8>>,
    label: Option<String>,
    size: u64,
    fat_cache: Mutex<HashMap<u64, Arc<Vec<u8>>>>,
    dirs: Mutex<HashMap<String, Arc<Vec<Item>>>>,
    gone: Mutex<Option<Arc<Vec<Item>>>>,
    told_no_offset: std::sync::atomic::AtomicBool,
    label_for_logs: String,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3], b[at + 4], b[at + 5], b[at + 6], b[at + 7]])
}

/// An exFAT timestamp: the packed date and time, the 10 ms increment (0-199) and the UTC
/// offset byte (bit 7 set when valid, then a signed count of 15 minutes). Returns the time
/// and whether it carried an offset.
pub fn exfat_time(ts: u32, ms10: u8, offset: u8) -> (Option<Timestamp>, bool) {
    if ts == 0 {
        return (None, true);
    }
    let year = 1980 + (ts >> 25) as i32;
    let month = (ts >> 21) & 0x0F;
    let day = (ts >> 16) & 0x1F;
    let hour = (ts >> 11) & 0x1F;
    let minute = (ts >> 5) & 0x3F;
    let second = (ts & 0x1F) * 2 + u32::from(ms10.min(199)) / 100;
    let Some(local) = Timestamp::from_civil(year, month, day, hour, minute, second.min(59)) else { return (None, true) };
    let nanos = (u32::from(ms10.min(199)) % 100) * 10_000_000;
    if offset & 0x80 == 0 {
        return (Some(Timestamp::from_unix(local.secs, nanos)), false);
    }
    // Seven-bit two's complement, in 15-minute steps: local = UTC + offset.
    let steps = i64::from(((offset << 1) as i8) >> 1);
    (Some(Timestamp::from_unix(local.secs - steps * 15 * 60, nanos)), true)
}

/// The checksum of an entry set, skipping the checksum field itself (bytes 2 and 3).
fn set_checksum(set: &[u8]) -> u16 {
    let mut sum: u16 = 0;
    for (i, &b) in set.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        sum = (if sum & 1 != 0 { 0x8000u16 } else { 0 }).wrapping_add(sum >> 1).wrapping_add(u16::from(b));
    }
    sum
}

impl ExFatFs {
    /// Opens the volume whose first byte is the boot sector.
    pub fn open(volume: SharedReader, label_for_logs: &str) -> Result<Self> {
        let bad = |why: &str| Error::recorded(code::EXFAT_OPEN, format!("{label_for_logs}: {why}"));
        let bs = volume.bytes_at(0, 512).ok_or_else(|| bad("boot sector unreadable"))?;
        if &bs[3..11] != b"EXFAT   " {
            return Err(bad("no EXFAT signature"));
        }
        let bps_shift = u32::from(bs[108]);
        let spc_shift = u32::from(bs[109]);
        if !(9..=12).contains(&bps_shift) || spc_shift > 25 - bps_shift {
            return Err(bad(&format!("sector shift {bps_shift}, cluster shift {spc_shift}")));
        }
        let bps = 1u64 << bps_shift;
        let cluster = bps << spc_shift;
        let length = u64_at(&bs, 72);
        let fat_offset = u64::from(u32_at(&bs, 80));
        let fat_length = u64::from(u32_at(&bs, 84));
        let heap = u64::from(u32_at(&bs, 88));
        let clusters = u32_at(&bs, 92);
        let root = u32_at(&bs, 96);
        if fat_offset < 24 || fat_length == 0 || heap < fat_offset + fat_length || clusters == 0 || clusters > 0xFFFF_FFF5 {
            return Err(bad(&format!("FAT at sector {fat_offset} ({fat_length} sectors), heap at {heap}, {clusters} clusters")));
        }
        if fat_length * bps < (u64::from(clusters) + 2) * 4 {
            return Err(bad(&format!("a FAT of {fat_length} sectors for {clusters} clusters")));
        }
        if root < 2 || root >= clusters + 2 {
            return Err(bad(&format!("root directory at cluster {root} of {clusters}")));
        }
        let mut fs = ExFatFs {
            cluster,
            fat_start: fat_offset * bps,
            heap_start: heap * bps,
            clusters,
            root,
            bitmap: None,
            label: None,
            size: length.saturating_mul(bps),
            fat_cache: Mutex::new(HashMap::new()),
            dirs: Mutex::new(HashMap::new()),
            gone: Mutex::new(None),
            told_no_offset: std::sync::atomic::AtomicBool::new(false),
            label_for_logs: label_for_logs.to_string(),
            r: volume,
        };
        let root_bytes = fs.dir_bytes(&Extent { first: root, contiguous: false, size: 0, valid: 0 }, "/")?;
        let parsed = parse(&root_bytes, "/", 0, &fs);
        fs.label = parsed.label;
        match parsed.bitmap {
            Some((first, len)) if len <= MAX_BITMAP && len * 8 >= u64::from(clusters) => {
                // Its chain is in the FAT; formatters also lay it out contiguously.
                let read = |contiguous: bool| {
                    let mut buf = Vec::with_capacity(len as usize);
                    let n = fs.stream(&Extent { first, contiguous, size: len, valid: len }, &mut buf, None).ok()?;
                    (n == len && fs.clusters_of(&Extent { first, contiguous, size: len, valid: len }, Some(len.div_ceil(fs.cluster)), "bitmap").len() as u64 == len.div_ceil(fs.cluster)).then_some(buf)
                };
                match read(false).or_else(|| read(true)) {
                    Some(buf) => fs.bitmap = Some(buf),
                    _ => {
                        diag::warn(code::EXFAT_BITMAP, format!("{label_for_logs}: the bitmap at cluster {first} could not be read"));
                    }
                };
            }
            Some((first, len)) => {
                diag::warn(code::EXFAT_BITMAP, format!("{label_for_logs}: a bitmap of {len} bytes at cluster {first} for {clusters} clusters"));
            }
            None => {
                diag::warn(code::EXFAT_BITMAP, format!("{label_for_logs}: no allocation bitmap entry in the root"));
            }
        }
        diag::info(
            code::EXFAT_OPENED,
            format!(
                "{label_for_logs}: cluster {cluster} bytes, {clusters} clusters, {}{}{}",
                crate::volume::human_size(fs.size),
                fs.label.as_deref().map(|l| format!(", label {l}")).unwrap_or_default(),
                if fs.bitmap.is_some() { "" } else { ", no allocation bitmap" }
            ),
        );
        Ok(fs)
    }

    #[cfg(test)]
    fn bitmap_first(&self) -> u32 {
        let root = self.dir_bytes(&Extent { first: self.root, contiguous: false, size: 0, valid: 0 }, "/").unwrap();
        parse(&root, "/", 0, self).bitmap.unwrap().0
    }

    fn valid_cluster(&self, c: u32) -> bool {
        c >= 2 && c < self.clusters + 2
    }

    fn offset(&self, c: u32) -> u64 {
        self.heap_start + u64::from(c - 2) * self.cluster
    }

    /// Whether the bitmap says a cluster is in use (true when there is no bitmap).
    fn in_use(&self, c: u32) -> bool {
        let Some(b) = &self.bitmap else { return true };
        let i = (c - 2) as usize;
        b.get(i / 8).is_none_or(|byte| byte & (1 << (i % 8)) != 0)
    }

    /// The FAT entry of cluster `c`, read a block at a time; None when unreadable.
    fn fat_entry(&self, c: u32) -> Option<u32> {
        let at = self.fat_start + u64::from(c) * 4;
        let block = at / FAT_BLOCK;
        let cached = self.fat_cache.lock().ok()?.get(&block).cloned();
        let data = match cached {
            Some(d) => d,
            None => {
                let start = block * FAT_BLOCK;
                let end = (self.fat_start + (u64::from(self.clusters) + 2) * 4).min(start + FAT_BLOCK);
                let Some(raw) = self.r.bytes_at(start, (end - start) as usize) else {
                    diag::warn(code::EXFAT_FAT_READ, format!("{}: {} bytes at {start}", self.label_for_logs, end - start));
                    return None;
                };
                let d = Arc::new(raw);
                self.fat_cache.lock().ok()?.insert(block, Arc::clone(&d));
                d
            }
        };
        let i = (at - block * FAT_BLOCK) as usize;
        data.get(i..i + 4).map(|b| u32_at(b, 0))
    }

    /// The clusters of an extent, in order: `count` from `first` when contiguous, else the
    /// FAT chain (up to `count` when given).
    fn clusters_of(&self, ext: &Extent, count: Option<u64>, what: &str) -> Vec<u32> {
        if ext.contiguous {
            let n = count.unwrap_or(0);
            if !self.valid_cluster(ext.first) || u64::from(ext.first) + n > u64::from(self.clusters) + 2 {
                diag::warn(code::EXFAT_CHAIN, format!("{}: {what}: {n} contiguous clusters from {} pass the end of the heap", self.label_for_logs, ext.first));
                let last = u64::from(self.clusters) + 2;
                return (u64::from(ext.first.max(2))..last.min(u64::from(ext.first) + n)).map(|c| c as u32).collect();
            }
            return (ext.first..ext.first + n as u32).collect();
        }
        let mut out = Vec::new();
        let mut c = ext.first;
        while self.valid_cluster(c) {
            out.push(c);
            if count.is_some_and(|w| out.len() as u64 >= w) {
                return out;
            }
            if out.len() > self.clusters as usize {
                diag::warn(code::EXFAT_CHAIN, format!("{}: {what}: loop at cluster {c}", self.label_for_logs));
                return out;
            }
            let Some(next) = self.fat_entry(c) else { return out };
            if next == 0xFFFF_FFFF {
                return out;
            }
            if !self.valid_cluster(next) {
                diag::warn(code::EXFAT_CHAIN, format!("{}: {what}: cluster {c} points to {next:#x}", self.label_for_logs));
                return out;
            }
            c = next;
        }
        if ext.first != 0 && out.is_empty() {
            diag::warn(code::EXFAT_CHAIN, format!("{}: {what}: first cluster {:#x} out of range", self.label_for_logs, ext.first));
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
            self.r.read_at(self.offset(clusters[i]), &mut buf).map_err(|e| Error::recorded(code::EXFAT_READ, format!("{}: cluster {}: {e}", self.label_for_logs, clusters[i])))?;
            if !each(&buf)? {
                return Ok(());
            }
            i = j;
        }
        Ok(())
    }

    /// The raw entries of a directory.
    fn dir_bytes(&self, ext: &Extent, what: &str) -> Result<Vec<u8>> {
        let count = (ext.size > 0).then(|| ext.size.div_ceil(self.cluster));
        let clusters = self.clusters_of(ext, if ext.contiguous { count } else { None }, what);
        let mut out = Vec::new();
        self.read_clusters(&clusters, |b| {
            out.extend_from_slice(b);
            Ok(out.len() < 256 << 20)
        })?;
        if ext.size > 0 {
            out.truncate(ext.size as usize);
        }
        Ok(out)
    }

    /// Streams `ext.size` bytes: what is valid from the clusters, zeros after.
    fn stream(&self, ext: &Extent, sink: Sink<'_>, mut progress: Option<Progress<'_>>) -> Result<u64> {
        let size = ext.size;
        let valid = ext.valid.min(size);
        let want = valid.div_ceil(self.cluster);
        let clusters = self.clusters_of(ext, Some(want), "file");
        if (clusters.len() as u64) < want {
            diag::warn(code::EXFAT_CHAIN, format!("{}: {} of {want} clusters", self.label_for_logs, clusters.len()));
        }
        let mut left = valid;
        let mut done = 0u64;
        self.read_clusters(&clusters, |b| {
            let take = (b.len() as u64).min(left) as usize;
            sink.write_all(&b[..take]).map_err(|e| Error::new(fscode::FS_READ, e.to_string()))?;
            left -= take as u64;
            done += take as u64;
            if let Some(p) = progress.as_mut() {
                p(done, size);
            }
            Ok(left > 0)
        })?;
        if done == valid && valid < size {
            diag::info(code::EXFAT_VALID_LENGTH, format!("{}: {valid} of {size} bytes written", self.label_for_logs));
            let zeros = vec![0u8; 64 * 1024];
            let mut rest = size - valid;
            while rest > 0 {
                let n = rest.min(zeros.len() as u64) as usize;
                sink.write_all(&zeros[..n]).map_err(|e| Error::new(fscode::FS_READ, e.to_string()))?;
                rest -= n as u64;
                done += n as u64;
            }
            if let Some(p) = progress.as_mut() {
                p(done, size);
            }
        }
        Ok(done)
    }

    /// Whether every cluster a deleted file would occupy is free.
    fn recoverable(&self, ext: &Extent) -> bool {
        if self.bitmap.is_none() {
            return false;
        }
        let n = ext.valid.min(ext.size).div_ceil(self.cluster);
        if n == 0 {
            return true;
        }
        let clusters = self.clusters_of(ext, Some(n), "deleted file");
        clusters.len() as u64 == n && clusters.iter().all(|&c| !self.in_use(c))
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
        if let Some(v) = self.dirs.lock().map_err(|_| Error::new(fscode::FS_READ, "exFAT directory cache"))?.get(&key) {
            return Ok(Arc::clone(v));
        }
        let (ext, first, canonical) = if norm == "/" {
            (Extent { first: self.root, contiguous: false, size: 0, valid: 0 }, 0, norm.clone())
        } else {
            let it = self.find(&norm)?;
            if it.entry.kind != EntryKind::Dir {
                return Err(Error::new(fscode::FS_NOT_A_DIR, path.to_string()));
            }
            (it.ext, it.ext.first, it.entry.path.clone())
        };
        let bytes = self.dir_bytes(&ext, &canonical)?;
        let mut parsed = parse(&bytes, &canonical, first, self);
        if parsed.no_offset > 0 && !self.told_no_offset.swap(true, std::sync::atomic::Ordering::Relaxed) {
            diag::info(code::EXFAT_NO_UTC_OFFSET, format!("{}: {canonical}: {} entr{} (and maybe others)", self.label_for_logs, parsed.no_offset, if parsed.no_offset == 1 { "y" } else { "ies" }));
        }
        parsed.live.sort_by(|a, b| a.entry.name.cmp(&b.entry.name));
        let v = Arc::new(parsed.live);
        self.dirs.lock().map_err(|_| Error::new(fscode::FS_READ, "exFAT directory cache"))?.insert(key, Arc::clone(&v));
        Ok(v)
    }

    fn find(&self, path: &str) -> Result<Item> {
        let norm = normalize(path);
        if norm == "/" {
            return Ok(Item { entry: Entry::new("/", EntryKind::Dir), ext: Extent { first: self.root, contiguous: false, size: 0, valid: 0 } });
        }
        let (parent, name) = norm.rsplit_once('/').map(|(p, n)| (if p.is_empty() { "/" } else { p }, n)).unwrap_or(("/", norm.as_str()));
        let siblings = self.list(parent)?;
        let lower = name.to_lowercase();
        siblings.iter().find(|i| i.entry.name.to_lowercase() == lower).cloned().ok_or_else(|| Error::new(fscode::FS_NOT_FOUND, path.to_string()))
    }

    /// Every deleted entry set of the volume: a walk of the live tree, done once.
    fn gone_list(&self) -> Result<Arc<Vec<Item>>> {
        if let Some(g) = self.gone.lock().map_err(|_| Error::new(fscode::FS_READ, "exFAT deleted cache"))?.as_ref() {
            return Ok(Arc::clone(g));
        }
        let mut all = Vec::new();
        let mut no_offset = 0usize;
        let root = Extent { first: self.root, contiguous: false, size: 0, valid: 0 };
        let mut stack: Vec<(String, Extent, u32, Vec<u32>)> = vec![("/".to_string(), root, 0, Vec::new())];
        while let Some((path, ext, first, ancestors)) = stack.pop() {
            let Ok(bytes) = self.dir_bytes(&ext, &path) else { continue };
            let parsed = parse(&bytes, &path, first, self);
            no_offset += parsed.no_offset;
            all.extend(parsed.gone);
            for it in parsed.live {
                if it.entry.kind == EntryKind::Dir && it.ext.first != 0 {
                    let here = if first == 0 { self.root } else { first };
                    if it.ext.first == here || ancestors.contains(&it.ext.first) {
                        diag::warn(code::EXFAT_DIR_LOOP, format!("{}: {}", self.label_for_logs, it.entry.path));
                        continue;
                    }
                    let mut a = ancestors.clone();
                    a.push(here);
                    stack.push((it.entry.path.clone(), it.ext, it.ext.first, a));
                }
            }
        }
        all.sort_by(|a, b| a.entry.path.cmp(&b.entry.path));
        let readable = all.iter().filter(|g| g.entry.recoverable).count();
        if !all.is_empty() {
            diag::info(code::EXFAT_DELETED, format!("{}: {} deleted entr{}, {readable} readable", self.label_for_logs, all.len(), if all.len() == 1 { "y" } else { "ies" }));
        }
        if no_offset > 0 {
            diag::info(code::EXFAT_NO_UTC_OFFSET, format!("{}: {no_offset} entr{} in the whole volume", self.label_for_logs, if no_offset == 1 { "y" } else { "ies" }));
        }
        let v = Arc::new(all);
        *self.gone.lock().map_err(|_| Error::new(fscode::FS_READ, "exFAT deleted cache"))? = Some(Arc::clone(&v));
        Ok(v)
    }

    fn find_gone(&self, path: &str) -> Result<Item> {
        let norm = normalize(path);
        self.gone_list()?.iter().find(|g| g.entry.path.eq_ignore_ascii_case(&norm)).cloned().ok_or_else(|| Error::new(fscode::FS_NOT_FOUND, path.to_string()))
    }
}

/// Parses a directory's entries; `dir_first` is its first cluster (0 for the root).
fn parse(bytes: &[u8], dir: &str, dir_first: u32, fs: &ExFatFs) -> Parsed {
    let mut out = Parsed::default();
    let n = bytes.len() / 32;
    let entry = |i: usize| &bytes[i * 32..i * 32 + 32];
    let mut i = 0;
    while i < n {
        let e = entry(i);
        let t = e[0];
        match t {
            T_END => break,
            T_BITMAP if dir == "/" && e[1] & 1 == 0 => {
                out.bitmap = Some((u32_at(e, 20), u64_at(e, 24)));
            }
            T_LABEL if dir == "/" => {
                let count = usize::from(e[1].min(11));
                let units: Vec<u16> = (0..count).map(|k| u16_at(e, 2 + 2 * k)).collect();
                let l = String::from_utf16_lossy(&units).trim_end().to_string();
                if !l.is_empty() {
                    out.label = Some(l);
                }
            }
            _ if t & 0x7F == T_FILE & 0x7F => {
                let live = t & IN_USE != 0;
                let secondaries = usize::from(e[1]);
                if secondaries < 2 || i + secondaries >= n {
                    if live {
                        diag::warn(code::EXFAT_SET_BROKEN, format!("{}: {dir}: entry {i}: {secondaries} secondary entries", fs.label_for_logs));
                    }
                    i += 1;
                    continue;
                }
                let set = &bytes[i * 32..(i + 1 + secondaries) * 32];
                let stream = &set[32..64];
                // The secondaries carry the same in-use state as their File entry.
                let want = |ty: u8| if live { ty } else { ty & 0x7F };
                let names_ok = (2..=secondaries).all(|k| set[k * 32] == want(T_NAME) || set[k * 32] & 0x7F > T_NAME & 0x7F);
                if stream[0] != want(T_STREAM) || set[64] != want(T_NAME) || !names_ok {
                    if live {
                        diag::warn(code::EXFAT_SET_BROKEN, format!("{}: {dir}: entry {i}: no stream extension or name after the file entry", fs.label_for_logs));
                    }
                    i += 1;
                    continue;
                }
                if live && set_checksum(set) != u16_at(e, 2) {
                    diag::info(code::EXFAT_SET_CHECKSUM, format!("{}: {dir}: entry {i}", fs.label_for_logs));
                }
                let name_len = usize::from(stream[3]);
                let mut units: Vec<u16> = Vec::with_capacity(name_len);
                for k in 2..=secondaries {
                    let ne = &set[k * 32..k * 32 + 32];
                    if ne[0] & 0x7F != T_NAME & 0x7F {
                        break;
                    }
                    for c in 0..15 {
                        if units.len() < name_len {
                            units.push(u16_at(ne, 2 + 2 * c));
                        }
                    }
                }
                let name = String::from_utf16_lossy(&units);
                let attrs = u16_at(e, 4);
                let is_dir = attrs & ATTR_DIRECTORY != 0;
                let (created, c_ok) = exfat_time(u32_at(e, 8), e[20], e[22]);
                let (modified, m_ok) = exfat_time(u32_at(e, 12), e[21], e[23]);
                let (accessed, a_ok) = exfat_time(u32_at(e, 16), 0, e[24]);
                if !(c_ok && m_ok && a_ok) {
                    out.no_offset += 1;
                }
                let ext = Extent { first: u32_at(stream, 20), contiguous: stream[1] & NO_FAT_CHAIN != 0, size: u64_at(stream, 24), valid: u64_at(stream, 8) };
                if name.is_empty() || name == "." || name == ".." {
                    i += 1 + secondaries;
                    continue;
                }
                // A '/' cannot be in a name; a damaged entry could hold one.
                let name = name.replace('/', "_");
                let kind = if is_dir { EntryKind::Dir } else { EntryKind::File };
                let times = Timestamps { created, modified, accessed, changed: None };
                if live {
                    let mut en = Entry::new(&join(dir, &name), kind);
                    en.size = if is_dir { 0 } else { ext.size };
                    en.times = times;
                    en.id = u64::from(ext.first);
                    out.live.push(Item { entry: en, ext });
                } else {
                    let original = join(dir, &name);
                    let id = if dir_first == 0 { format!("root.{i}") } else { format!("c{dir_first}.{i}") };
                    let mut en = Entry::new(&deleted_path(&id, &original), kind);
                    en.size = if is_dir { 0 } else { ext.size };
                    en.times = times;
                    en.id = u64::from(ext.first);
                    en.deleted = true;
                    en.recoverable = !is_dir && fs.recoverable(&ext);
                    if !is_dir && !en.recoverable && ext.size > 0 {
                        diag::info(code::EXFAT_DELETED_REUSED, format!("{}: {original}", fs.label_for_logs));
                    }
                    out.gone.push(Item { entry: en, ext });
                }
                i += 1 + secondaries;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

impl FileSystem for ExFatFs {
    fn kind(&self) -> FsKind {
        FsKind::ExFat
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
                return Err(Error::new(fscode::FS_DELETED_UNRECOVERABLE, format!("{path}: clusters in use again")));
            }
            return self.stream(&g.ext, sink, progress);
        }
        let it = self.find(path)?;
        if it.entry.kind != EntryKind::File {
            return Err(Error::new(fscode::FS_NOT_A_FILE, path.to_string()));
        }
        self.stream(&it.ext, sink, progress)
    }
}

#[cfg(test)]
pub mod testutil {
    //! A tiny exFAT formatter for tests.

    /// One file or folder: path (`/`-separated, no leading slash), content (None for a
    /// folder), and whether its clusters are contiguous (no FAT chain) or chained through
    /// the FAT in reverse order (so a reader that ignores the FAT reads them wrongly).
    pub struct Node<'a> {
        pub path: &'a str,
        pub data: Option<&'a [u8]>,
        pub contiguous: bool,
    }

    /// 2026-11-11 10:20:30 + `sec2` two-second steps, local.
    fn ts(min: u32, sec2: u32) -> u32 {
        ((2026 - 1980) << 25) | (11 << 21) | (11 << 16) | (10 << 11) | (min << 5) | sec2
    }

    struct Alloc {
        next: u32,
        fat: Vec<u32>,
        used: Vec<u32>,
    }

    impl Alloc {
        /// `n` clusters one after the other, chained in that order too (as mkfs lays out
        /// the bitmap).
        fn take_forward(&mut self, n: u32) -> Vec<u32> {
            let v: Vec<u32> = (self.next..self.next + n).collect();
            self.next += n;
            self.used.extend(&v);
            for w in v.windows(2) {
                self.fat[w[0] as usize] = w[1];
            }
            if let Some(l) = v.last() {
                self.fat[*l as usize] = 0xFFFF_FFFF;
            }
            v
        }

        /// `n` clusters; chained in reverse order unless contiguous.
        fn take(&mut self, n: u32, contiguous: bool) -> Vec<u32> {
            let mut v: Vec<u32> = (self.next..self.next + n).collect();
            self.next += n;
            self.used.extend(&v);
            if !contiguous {
                v.reverse();
                for w in v.windows(2) {
                    self.fat[w[0] as usize] = w[1];
                }
                if let Some(l) = v.last() {
                    self.fat[*l as usize] = 0xFFFF_FFFF;
                }
            }
            v
        }
    }

    /// The entry set of a file or folder.
    fn set(name: &str, dir: bool, first: u32, size: u64, valid: u64, contiguous: bool, offset: Option<i8>) -> Vec<[u8; 32]> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let names = units.len().div_ceil(15).max(1);
        let mut out = vec![[0u8; 32]; 2 + names];
        let f = &mut out[0];
        f[0] = super::T_FILE;
        f[1] = (1 + names) as u8;
        f[4..6].copy_from_slice(&(if dir { 0x10u16 } else { 0x20 }).to_le_bytes());
        f[8..12].copy_from_slice(&ts(20, 15).to_le_bytes());
        f[12..16].copy_from_slice(&ts(21, 16).to_le_bytes());
        f[16..20].copy_from_slice(&ts(22, 0).to_le_bytes());
        f[20] = 150;
        f[21] = 0;
        let off = offset.map_or(0u8, |o| 0x80 | ((o as u8) & 0x7F));
        f[22] = off;
        f[23] = off;
        f[24] = off;
        let st = &mut out[1];
        st[0] = super::T_STREAM;
        st[1] = 0x01 | if contiguous { super::NO_FAT_CHAIN } else { 0 };
        st[3] = units.len() as u8;
        st[8..16].copy_from_slice(&valid.to_le_bytes());
        st[20..24].copy_from_slice(&first.to_le_bytes());
        st[24..32].copy_from_slice(&size.to_le_bytes());
        for k in 0..names {
            let e = &mut out[2 + k];
            e[0] = super::T_NAME;
            for (c, u) in units.iter().skip(k * 15).take(15).enumerate() {
                e[2 + 2 * c..4 + 2 * c].copy_from_slice(&u.to_le_bytes());
            }
        }
        let flat: Vec<u8> = out.iter().flatten().copied().collect();
        let sum = super::set_checksum(&flat);
        out[0][2..4].copy_from_slice(&sum.to_le_bytes());
        out
    }

    /// An exFAT volume of `sectors` 512-byte sectors, 2^`spc_shift` sectors per cluster.
    /// Times: created 2026-11-11 10:20:31.50, modified 10:21:32, accessed 10:22:00, local
    /// time at `offset` quarter hours from UTC (None: no offset recorded). `deleted` names
    /// a file whose entry set is then marked not in use and its clusters freed in the
    /// bitmap (the FAT chain is left as it was). The volume label is TESTCARD.
    pub fn volume(sectors: u32, spc_shift: u8, nodes: &[Node<'_>], deleted: Option<&str>, offset: Option<i8>) -> Vec<u8> {
        let bps = 512usize;
        let spc = 1usize << spc_shift;
        let cs = bps * spc;
        let fat_offset = 24usize;
        let clusters_guess = sectors as usize / spc;
        let fat_len = ((clusters_guess + 2) * 4).div_ceil(bps);
        let heap = (fat_offset + fat_len).div_ceil(spc) * spc;
        let clusters = (sectors as usize - heap) / spc;
        let mut img = vec![0u8; sectors as usize * bps];
        img[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        img[3..11].copy_from_slice(b"EXFAT   ");
        img[72..80].copy_from_slice(&u64::from(sectors).to_le_bytes());
        img[80..84].copy_from_slice(&(fat_offset as u32).to_le_bytes());
        img[84..88].copy_from_slice(&(fat_len as u32).to_le_bytes());
        img[88..92].copy_from_slice(&(heap as u32).to_le_bytes());
        img[92..96].copy_from_slice(&(clusters as u32).to_le_bytes());
        img[104..106].copy_from_slice(&0x0100u16.to_le_bytes());
        img[108] = 9;
        img[109] = spc_shift;
        img[110] = 1;
        img[510] = 0x55;
        img[511] = 0xAA;
        let mut a = Alloc { next: 2, fat: vec![0u32; clusters + 2], used: Vec::new() };
        a.fat[0] = 0xFFFF_FFF8;
        a.fat[1] = 0xFFFF_FFFF;
        let bitmap_len = clusters.div_ceil(8);
        let bitmap = a.take_forward(bitmap_len.div_ceil(cs) as u32);
        let upcase = a.take(1, false);
        // Folders first (each one cluster, contiguous), then files.
        let mut dirs: Vec<(String, u32)> = vec![(String::new(), 0)];
        let root = a.take(4, false);
        img[96..100].copy_from_slice(&root[0].to_le_bytes());
        dirs[0].1 = root[0];
        let mut entries: std::collections::BTreeMap<String, Vec<[u8; 32]>> = std::collections::BTreeMap::new();
        let mut gone_clusters = Vec::new();
        for n in nodes.iter().filter(|n| n.data.is_none()) {
            let c = a.take(1, true)[0];
            dirs.push((n.path.to_string(), c));
        }
        for n in nodes {
            let (parent, name) = n.path.rsplit_once('/').unwrap_or(("", n.path));
            let mut es = match n.data {
                None => {
                    let c = dirs.iter().find(|d| d.0 == n.path).unwrap().1;
                    set(name, true, c, cs as u64, cs as u64, true, offset)
                }
                Some(data) => {
                    let k = data.len().div_ceil(cs) as u32;
                    let cl = a.take(k, n.contiguous);
                    for (i, c) in cl.iter().enumerate() {
                        let at = (heap + (*c as usize - 2) * spc) * bps;
                        let chunk = &data[i * cs..data.len().min((i + 1) * cs)];
                        img[at..at + chunk.len()].copy_from_slice(chunk);
                    }
                    if deleted == Some(n.path) {
                        gone_clusters.extend(cl.iter().copied());
                    }
                    set(name, false, cl.first().copied().unwrap_or(0), data.len() as u64, data.len() as u64, n.contiguous, offset)
                }
            };
            if deleted == Some(n.path) {
                for e in &mut es {
                    e[0] &= 0x7F;
                }
            }
            entries.entry(parent.to_string()).or_default().extend(es);
        }
        // Root: bitmap, up-case table, label, then the entries.
        let mut root_entries = Vec::new();
        let mut b = [0u8; 32];
        b[0] = super::T_BITMAP;
        b[20..24].copy_from_slice(&bitmap[0].to_le_bytes());
        b[24..32].copy_from_slice(&(bitmap_len as u64).to_le_bytes());
        root_entries.push(b);
        let mut u = [0u8; 32];
        u[0] = 0x82;
        u[20..24].copy_from_slice(&upcase[0].to_le_bytes());
        u[24..32].copy_from_slice(&128u64.to_le_bytes());
        root_entries.push(u);
        let mut l = [0u8; 32];
        l[0] = super::T_LABEL;
        let label: Vec<u16> = "TESTCARD".encode_utf16().collect();
        l[1] = label.len() as u8;
        for (i, c) in label.iter().enumerate() {
            l[2 + 2 * i..4 + 2 * i].copy_from_slice(&c.to_le_bytes());
        }
        root_entries.push(l);
        root_entries.extend(entries.remove("").unwrap_or_default());
        let write_dir = |img: &mut Vec<u8>, clusters: &[u32], es: &[[u8; 32]]| {
            let flat: Vec<u8> = es.iter().flatten().copied().collect();
            assert!(flat.len() <= clusters.len() * cs, "the test directory is too big");
            for (i, c) in clusters.iter().enumerate() {
                let at = (heap + (*c as usize - 2) * spc) * bps;
                let start = i * cs;
                if start >= flat.len() {
                    break;
                }
                let end = flat.len().min(start + cs);
                img[at..at + end - start].copy_from_slice(&flat[start..end]);
            }
        };
        // The root's clusters in chain order.
        let mut root_chain = vec![root[0]];
        while a.fat[*root_chain.last().unwrap() as usize] != 0xFFFF_FFFF {
            let n = a.fat[*root_chain.last().unwrap() as usize];
            root_chain.push(n);
        }
        write_dir(&mut img, &root_chain, &root_entries);
        for (path, c) in dirs.iter().skip(1) {
            write_dir(&mut img, &[*c], &entries.remove(path).unwrap_or_default());
        }
        // FAT and bitmap.
        for (i, v) in a.fat.iter().enumerate() {
            let at = fat_offset * bps + i * 4;
            img[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        let bm_at = (heap + (bitmap[0] as usize - 2) * spc) * bps;
        let mut bm = vec![0u8; bitmap_len];
        for c in a.used.iter().filter(|c| !gone_clusters.contains(c)) {
            let i = (*c - 2) as usize;
            bm[i / 8] |= 1 << (i % 8);
        }
        img[bm_at..bm_at + bitmap_len].copy_from_slice(&bm);
        img
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{volume, Node};
    use super::*;

    fn quiet() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
    }

    fn open(img: Vec<u8>) -> ExFatFs {
        ExFatFs::open(SharedReader::from_bytes(img), "test").unwrap()
    }

    fn big() -> Vec<u8> {
        (0..20_000u32).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn tree(big: &[u8]) -> Vec<Node<'_>> {
        vec![
            Node { path: "DCIM", data: None, contiguous: true },
            Node { path: "DCIM/100CANON", data: None, contiguous: true },
            Node { path: "DCIM/100CANON/IMG_0001.JPG", data: Some(b"\xff\xd8\xff\xe0 a photo"), contiguous: true },
            Node { path: "DCIM/100CANON/a long name with \u{f1} and more than fifteen characters.mov", data: Some(big), contiguous: false },
            Node { path: "notes.txt", data: Some(b"meeting at nine"), contiguous: true },
            Node { path: "chained.bin", data: Some(big), contiguous: false },
            Node { path: "gone.txt", data: Some(b"deleted but still here"), contiguous: true },
            Node { path: "empty.txt", data: Some(b""), contiguous: true },
        ]
    }

    #[test]
    fn reads_folders_files_chains_and_times() {
        quiet();
        let b = big();
        for shift in [0u8, 3] {
            let fs = open(volume(8192, shift, &tree(&b), Some("gone.txt"), Some(4)));
            assert_eq!(fs.kind(), FsKind::ExFat);
            assert_eq!(fs.label().as_deref(), Some("TESTCARD"));
            assert!(fs.bitmap.is_some());
            let root: Vec<String> = fs.read_dir("/").unwrap().iter().map(|e| e.name.clone()).collect();
            assert_eq!(root, vec!["DCIM", "chained.bin", "empty.txt", "notes.txt"], "sorted, the deleted one not among them");
            assert_eq!(fs.read("/notes.txt", None, 100).unwrap(), b"meeting at nine");
            assert_eq!(fs.read("/NOTES.TXT", None, 100).unwrap(), b"meeting at nine", "names ignore case");
            assert_eq!(fs.read("/chained.bin", None, 1 << 20).unwrap(), b, "a FAT chain in reverse order");
            assert_eq!(fs.read("/empty.txt", None, 100).unwrap(), b"");
            let long = "/DCIM/100CANON/a long name with \u{f1} and more than fifteen characters.mov";
            assert_eq!(fs.read(long, None, 1 << 20).unwrap(), b, "a name over several entries");
            assert_eq!(fs.read("/dcim/100canon/img_0001.jpg", None, 100).unwrap(), b"\xff\xd8\xff\xe0 a photo");
            let m = fs.metadata("/notes.txt").unwrap();
            assert_eq!(m.size, 15);
            assert_eq!(m.path, "/notes.txt");
            // Local 10:20:31.50 at UTC+1 is 09:20:31.50 UTC.
            assert_eq!(m.times.created.unwrap().to_rfc3339_micros(), "2026-11-11T09:20:31.500000Z");
            assert_eq!(m.times.modified.unwrap().to_rfc3339_micros(), "2026-11-11T09:21:32.000000Z");
            assert_eq!(m.times.accessed.unwrap().to_rfc3339_micros(), "2026-11-11T09:22:00.000000Z");
            assert_eq!(fs.metadata("/DCIM").unwrap().kind, EntryKind::Dir);
            assert!(matches!(fs.read_dir("/notes.txt"), Err(e) if e.code == fscode::FS_NOT_A_DIR));
            assert!(matches!(fs.metadata("/nope"), Err(e) if e.code == fscode::FS_NOT_FOUND));
            assert!(matches!(fs.read("/DCIM", None, 10), Err(e) if e.code == fscode::FS_NOT_A_FILE));
            let gone = fs.deleted(None).unwrap();
            assert_eq!(gone.len(), 1, "{gone:?}");
            assert!(gone[0].path.starts_with("/$DELETED/root.") && gone[0].path.ends_with("/gone.txt"), "{}", gone[0].path);
            assert!(gone[0].deleted && gone[0].recoverable);
            assert_eq!(fs.read(&gone[0].path, None, 100).unwrap(), b"deleted but still here");
            assert_eq!(fs.read_dir("/$DELETED").unwrap().len(), 1);
            let mut walked = Vec::new();
            crate::fs::walk(&fs, "/", &crate::fs::WalkOptions::default(), &mut |e: &Entry| {
                walked.push(e.path.clone());
                crate::fs::WalkStep::Continue
            });
            assert!(walked.contains(&long.to_string()), "{walked:?}");
            assert!(!crate::diag::has(code::EXFAT_SET_CHECKSUM));
            assert!(crate::diag::has(code::EXFAT_OPENED));
            crate::diag::drain();
        }
    }

    #[test]
    fn times_without_an_offset_are_said_to_be_local() {
        quiet();
        let b = big();
        let fs = open(volume(8192, 0, &tree(&b), None, None));
        let m = fs.metadata("/notes.txt").unwrap();
        assert_eq!(m.times.created.unwrap().to_rfc3339_micros(), "2026-11-11T10:20:31.500000Z");
        assert!(crate::diag::has(code::EXFAT_NO_UTC_OFFSET));
        let fs = open(volume(8192, 0, &tree(&b), None, Some(-20)));
        let m = fs.metadata("/notes.txt").unwrap();
        assert_eq!(m.times.modified.unwrap().to_rfc3339_micros(), "2026-11-11T15:21:32.000000Z", "UTC-5 local 10:21:32");
        assert_eq!(exfat_time(0, 0, 0x80), (None, true));
    }

    #[test]
    fn deleted_file_whose_clusters_are_in_use_again_is_listed_not_read() {
        quiet();
        let b = big();
        let mut img = volume(8192, 0, &tree(&b), Some("gone.txt"), Some(0));
        let fs = open(img.clone());
        let g = fs.deleted(None).unwrap()[0].clone();
        let c = g.id as usize;
        let bm_at = fs.offset(fs.bitmap_first());
        drop(fs);
        let i = c - 2;
        img[bm_at as usize + i / 8] |= 1 << (i % 8);
        let fs = open(img);
        let g = fs.deleted(None).unwrap()[0].clone();
        assert!(g.deleted && !g.recoverable);
        assert!(matches!(fs.read(&g.path, None, 100), Err(e) if e.code == fscode::FS_DELETED_UNRECOVERABLE));
        assert!(crate::diag::has(code::EXFAT_DELETED_REUSED));
    }

    #[test]
    fn checksums_broken_sets_and_valid_length() {
        quiet();
        let b = big();
        let img = volume(8192, 0, &tree(&b), None, Some(0));
        let fs = open(img.clone());
        let root_at = fs.offset(fs.root) as usize;
        drop(fs);
        // The first file set in the root follows the bitmap, up-case and label entries.
        let set_at = root_at + 3 * 32;
        assert_eq!(img[set_at], T_FILE);
        // A flipped byte in a name: listed, with the checksum code.
        let mut bad = img.clone();
        bad[set_at + 2 * 32 + 2] ^= 0x01;
        let fs = open(bad);
        assert_eq!(fs.read_dir("/").unwrap().len(), 5);
        assert!(crate::diag::has(code::EXFAT_SET_CHECKSUM));
        crate::diag::drain();
        // No stream extension after the file entry: skipped.
        let mut bad = img.clone();
        bad[set_at + 32] = 0xA0;
        let fs = open(bad);
        assert_eq!(fs.read_dir("/").unwrap().len(), 4);
        assert!(crate::diag::has(code::EXFAT_SET_BROKEN));
        crate::diag::drain();
        // notes.txt with only 4 of its 15 bytes valid: the rest reads as zeros. The sets are
        // written in tree order, not sorted: find its set by its name.
        let mut short = img.clone();
        let mut at = set_at;
        loop {
            let name: Vec<u16> = (0..9).map(|k| u16::from_le_bytes([short[at + 66 + 2 * k], short[at + 67 + 2 * k]])).collect();
            if String::from_utf16_lossy(&name) == "notes.txt" {
                break;
            }
            at += 32 * (1 + usize::from(short[at + 1]));
        }
        short[at + 32 + 8..at + 32 + 16].copy_from_slice(&4u64.to_le_bytes());
        let fs = open(short);
        assert_eq!(fs.read("/notes.txt", None, 100).unwrap(), b"meet\0\0\0\0\0\0\0\0\0\0\0");
        assert!(crate::diag::has(code::EXFAT_VALID_LENGTH));
    }

    #[test]
    fn bad_boot_sectors_are_refused_with_codes() {
        quiet();
        let b = big();
        let good = volume(8192, 0, &tree(&b), None, Some(0));
        assert!(matches!(ExFatFs::open(SharedReader::from_bytes(vec![0u8; 4096]), "zero"), Err(e) if e.code == code::EXFAT_OPEN));
        assert!(matches!(ExFatFs::open(SharedReader::from_bytes(vec![0u8; 100]), "short"), Err(e) if e.code == code::EXFAT_OPEN));
        for (at, v) in [(108usize, 8u8), (108, 13), (109, 20)] {
            let mut img = good.clone();
            img[at] = v;
            assert!(matches!(ExFatFs::open(SharedReader::from_bytes(img), "shift"), Err(e) if e.code == code::EXFAT_OPEN), "byte {at} = {v}");
        }
        let mut img = good.clone();
        img[96..100].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(ExFatFs::open(SharedReader::from_bytes(img), "root"), Err(e) if e.code == code::EXFAT_OPEN));
        let mut img = good.clone();
        img[84..88].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(ExFatFs::open(SharedReader::from_bytes(img), "fat"), Err(e) if e.code == code::EXFAT_OPEN));
        // No bitmap entry: opens, deleted files are not read back.
        let mut img = volume(8192, 0, &tree(&b), Some("gone.txt"), Some(0));
        let fs = open(img.clone());
        let root_at = fs.offset(fs.root) as usize;
        drop(fs);
        img[root_at] = 0xA0;
        let fs = open(img);
        assert!(fs.bitmap.is_none());
        assert!(crate::diag::has(code::EXFAT_BITMAP));
        assert!(!fs.deleted(None).unwrap()[0].recoverable);
    }

    #[test]
    fn damaged_volumes_do_not_panic() {
        quiet();
        let b = big();
        let good = volume(8192, 0, &tree(&b), Some("gone.txt"), Some(0));
        let mut seed: u64 = 0xe8fa7;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let fs = open(good.clone());
        let heap = fs.heap_start as usize;
        drop(fs);
        for _ in 0..200 {
            let mut img = good.clone();
            // The FAT, the root and the first folders, where the structure is.
            for _ in 0..(1 + rnd() % 40) {
                let span = heap + 40 * 512;
                let at = 24 * 512 + (rnd() as usize % (span - 24 * 512));
                img[at] = rnd() as u8;
            }
            if let Ok(fs) = ExFatFs::open(SharedReader::from_bytes(img), "noise") {
                let mut paths = Vec::new();
                crate::fs::walk(&fs, "/", &crate::fs::WalkOptions::default(), &mut |e: &Entry| {
                    paths.push(e.path.clone());
                    crate::fs::WalkStep::Continue
                });
                for p in paths.iter().take(20) {
                    let _ = fs.read(p, None, 1 << 20);
                }
                for g in fs.deleted(None).unwrap_or_default() {
                    let _ = fs.read(&g.path, None, 1 << 20);
                }
            }
        }
        crate::diag::drain();
    }

    #[test]
    fn a_folder_that_contains_itself_is_not_walked_forever() {
        quiet();
        let b = big();
        let img = volume(8192, 0, &tree(&b), None, Some(0));
        let fs = open(img.clone());
        let dcim = fs.find("/DCIM").unwrap().ext.first;
        let sub_at = fs.offset(dcim) as usize;
        let root = fs.root;
        drop(fs);
        // DCIM's only child, 100CANON, now points at the root.
        let mut bad = img;
        assert_eq!(bad[sub_at], T_FILE);
        bad[sub_at + 32 + 20..sub_at + 32 + 24].copy_from_slice(&root.to_le_bytes());
        bad[sub_at + 32 + 1] &= !NO_FAT_CHAIN;
        let fs = open(bad);
        let _ = fs.deleted(None).unwrap();
        assert!(crate::diag::has(code::EXFAT_DIR_LOOP));
    }

    #[test]
    fn checksum_and_time_helpers() {
        assert_eq!(set_checksum(&[0u8; 64]), 0);
        let mut a = [0u8; 64];
        a[2] = 0xFF;
        a[3] = 0xFF;
        assert_eq!(set_checksum(&a), 0, "bytes 2 and 3 are skipped");
        a[10] = 1;
        assert_ne!(set_checksum(&a), 0);
        let t = ((2001 - 1980) << 25) | (2 << 21) | (3 << 16) | (4 << 11) | (5 << 5) | 3;
        assert_eq!(exfat_time(t, 199, 0x80).0.unwrap().to_rfc3339_micros(), "2001-02-03T04:05:07.990000Z");
        assert_eq!(exfat_time(t, 0, 0x80 | 0x7F).0.unwrap().to_rfc3339_micros(), "2001-02-03T04:20:06.000000Z", "UTC-0:15");
        assert!(crate::diag::catalog().iter().any(|c| c.id == 800) && crate::diag::catalog().iter().any(|c| c.id == 820), "FAT and exFAT codes are catalogued");
    }
}
