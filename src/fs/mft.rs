//! The `$MFT` read record by record, without the live directory indexes: every record,
//! in use or not, with its names, times, sizes and data runs. This is how deleted files
//! come back on NTFS: a record whose `IN_USE` flag is off still carries `$FILE_NAME`,
//! `$STANDARD_INFORMATION` and the `$DATA` runs until it is reused, so the file's path,
//! times, size and (when the clusters have not been written again) content are all there.
//!
//! The parser works on a stream of records, so it serves both a mounted volume (the
//! `$MFT` data stream of record 0) and a bare `$MFT` file copied out by a triage tool;
//! with the latter, resident content is recoverable and non-resident content is not
//! (the clusters are not in the file).

use std::collections::HashMap;
use std::io::Read;

use crate::diag;
use crate::time::{Timestamp, Timestamps};

pub mod code {
    crate::codes! {
        MFT_RECORD_SIZE = 430, "the $MFT record size is not 1024 or 4096 bytes; the volume's boot sector is unusual or the file given is not an $MFT, nothing was parsed";
        MFT_BAD_FIXUP = 431, "a FILE record's update sequence does not match its sectors; the record is torn (half-written) and was skipped";
        MFT_BAD_HEADER = 432, "a record has no FILE signature or an impossible header; it is unused space or damage and was skipped";
        MFT_ATTRIBUTE_TRUNCATED = 433, "an attribute runs past the end of its record; the attributes before it were kept";
        MFT_NAME_TOO_LONG = 434, "a $FILE_NAME attribute claims more than 255 characters; the name was ignored";
        MFT_RUNLIST_BAD = 435, "a data run list is malformed (a run points before cluster 0 or past the end); the runs decoded so far were kept and the file is marked not recoverable";
        MFT_ATTRIBUTE_LIST = 436, "a deleted record has an $ATTRIBUTE_LIST: its attributes live in other records this reader does not chase, so its content may be incomplete and is marked not recoverable";
        MFT_SCANNED = 437, "the $MFT was scanned: records, in use, deleted with a name, bytes";
        MFT_PARENT_REUSED = 438, "the parent directory of a deleted file has been reused since (its sequence number moved on); the path is rebuilt under $OrphanFiles";
        MFT_READ = 439, "reading the $MFT stream failed part-way; the records read so far were kept";
        MFT_COMPRESSED = 440, "a deleted file's data is compressed, encrypted or sparse in a way this reader does not decode; its metadata is listed, its content is not recoverable";
        MFT_EXTENSION_RECORD = 441, "a record is an extension of another (its base reference is set); it carries no name of its own and was folded into the count";
        MFT_TOO_MANY = 442, "more deleted records than the limit were found; the list was cut";
    }
}

/// Records the scan never returns beyond.
pub const MAX_DELETED: usize = 2_000_000;
/// Longest run list decoded (runs), a guard against garbage.
pub const MAX_RUNS: usize = 1 << 20;

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFF_FFFF;

const FLAG_IN_USE: u16 = 0x0001;
const FLAG_DIRECTORY: u16 = 0x0002;

/// Attribute flag: compressed.
pub const ATTR_FLAG_COMPRESSED: u16 = 0x0001;
/// Attribute flag: encrypted.
pub const ATTR_FLAG_ENCRYPTED: u16 = 0x4000;
/// Attribute flag: sparse.
pub const ATTR_FLAG_SPARSE: u16 = 0x8000;

/// Folder deleted files are listed under when their parent is gone or reused.
pub const ORPHAN_DIR: &str = "$OrphanFiles";

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// One run of clusters: `lcn` is `None` for a sparse run (zeros).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    pub lcn: Option<u64>,
    pub clusters: u64,
}

/// A `$FILE_NAME` attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileName {
    /// Record number of the parent directory.
    pub parent: u64,
    /// Sequence number the parent had when this name was written.
    pub parent_seq: u16,
    /// 0 POSIX, 1 Win32, 2 DOS, 3 Win32+DOS.
    pub namespace: u8,
    pub name: String,
    pub size: u64,
    pub times: Timestamps,
    pub is_dir: bool,
}

/// A `$DATA` attribute (the unnamed one or an alternate stream).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataAttr {
    pub name: String,
    /// Real size in bytes.
    pub size: u64,
    /// Content of a resident attribute.
    pub resident: Option<Vec<u8>>,
    /// Runs of a non-resident attribute, in order.
    pub runs: Vec<Run>,
    /// Attribute flags (compressed, encrypted, sparse).
    pub flags: u16,
    /// The run list was damaged; `runs` is a prefix.
    pub runs_damaged: bool,
}

impl DataAttr {
    /// Can the bytes be read back from the volume as plain data?
    pub fn is_plain(&self) -> bool {
        self.flags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_ENCRYPTED) == 0 && !self.runs_damaged
    }
}

/// One `FILE` record, parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub number: u64,
    pub sequence: u16,
    pub in_use: bool,
    pub is_dir: bool,
    /// Non-zero when the record extends another one.
    pub base_record: u64,
    pub hard_links: u16,
    /// `$STANDARD_INFORMATION` times.
    pub si_times: Option<Timestamps>,
    pub names: Vec<FileName>,
    pub data: Vec<DataAttr>,
    pub has_attribute_list: bool,
}

impl Record {
    /// The name to show: Win32 or POSIX before DOS, the first one otherwise.
    pub fn best_name(&self) -> Option<&FileName> {
        self.names.iter().find(|n| n.namespace != 2).or_else(|| self.names.first())
    }

    /// The unnamed `$DATA` attribute.
    pub fn main_data(&self) -> Option<&DataAttr> {
        self.data.iter().find(|d| d.name.is_empty())
    }
}

/// Applies the update sequence array to a copy of the record. `None` when the sectors do
/// not carry the expected sequence (a torn record).
pub fn apply_fixups(record: &[u8]) -> Option<Vec<u8>> {
    if record.len() < 48 || &record[..4] != b"FILE" {
        return None;
    }
    let usa_off = u16le(record, 4) as usize;
    let usa_count = u16le(record, 6) as usize;
    if usa_count < 2 || usa_off + usa_count * 2 > record.len() || (usa_count - 1) * 512 > record.len() {
        return None;
    }
    let mut out = record.to_vec();
    let usn = [record[usa_off], record[usa_off + 1]];
    for i in 1..usa_count {
        let end = i * 512;
        if end > out.len() {
            return None;
        }
        if out[end - 2..end] != usn {
            return None;
        }
        out[end - 2] = record[usa_off + i * 2];
        out[end - 1] = record[usa_off + i * 2 + 1];
    }
    Some(out)
}

/// Decodes a run list. `(runs, damaged)`: `damaged` says the list ended in an impossible
/// run and `runs` is what came before.
pub fn decode_runs(bytes: &[u8]) -> (Vec<Run>, bool) {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut lcn: i64 = 0;
    while pos < bytes.len() {
        let h = bytes[pos];
        if h == 0 {
            return (runs, false);
        }
        let len_size = (h & 0x0F) as usize;
        let off_size = (h >> 4) as usize;
        if len_size == 0 || len_size > 8 || off_size > 8 || pos + 1 + len_size + off_size > bytes.len() {
            return (runs, true);
        }
        let mut len: u64 = 0;
        for i in 0..len_size {
            len |= (bytes[pos + 1 + i] as u64) << (8 * i);
        }
        if len == 0 {
            return (runs, true);
        }
        if off_size == 0 {
            runs.push(Run { lcn: None, clusters: len });
        } else {
            let mut off: i64 = 0;
            for i in 0..off_size {
                off |= (bytes[pos + 1 + len_size + i] as i64) << (8 * i);
            }
            // Sign-extend.
            let shift = 64 - 8 * off_size;
            off = (off << shift) >> shift;
            lcn += off;
            if lcn < 0 {
                return (runs, true);
            }
            runs.push(Run { lcn: Some(lcn as u64), clusters: len });
        }
        pos += 1 + len_size + off_size;
        if runs.len() > MAX_RUNS {
            return (runs, true);
        }
    }
    (runs, false)
}

fn nt(ticks: u64) -> Option<Timestamp> {
    Timestamp::from_nt(ticks)
}

fn times_at(b: &[u8], o: usize) -> Timestamps {
    Timestamps { created: nt(u64le(b, o)), modified: nt(u64le(b, o + 8)), changed: nt(u64le(b, o + 16)), accessed: nt(u64le(b, o + 24)) }
}

/// Parses one record (fixups applied here). `number` is the record's position in the
/// `$MFT`; the header's own number is used when the header is the long form and agrees.
/// Returns `None` for unused space and torn records; records that are not in use and
/// carry nothing are returned with empty `names`.
pub fn parse_record(raw: &[u8], number: u64) -> Option<Record> {
    let b = apply_fixups(raw)?;
    let flags = u16le(&b, 22);
    let first_attr = u16le(&b, 20) as usize;
    let used = u32le(&b, 24) as usize;
    if first_attr < 0x30 || first_attr >= b.len() || used > b.len() {
        return None;
    }
    let mut rec = Record {
        number,
        sequence: u16le(&b, 16),
        in_use: flags & FLAG_IN_USE != 0,
        is_dir: flags & FLAG_DIRECTORY != 0,
        base_record: u64le(&b, 32) & 0x0000_FFFF_FFFF_FFFF,
        hard_links: u16le(&b, 18),
        si_times: None,
        names: Vec::new(),
        data: Vec::new(),
        has_attribute_list: false,
    };
    let mut pos = first_attr;
    while pos + 8 <= b.len() {
        let ty = u32le(&b, pos);
        if ty == ATTR_END {
            break;
        }
        let len = u32le(&b, pos + 4) as usize;
        if len < 24 || !len.is_multiple_of(8) || pos + len > b.len() {
            diag::info(code::MFT_ATTRIBUTE_TRUNCATED, format!("record {number}: attribute {ty:#x} at {pos}"));
            break;
        }
        let a = &b[pos..pos + len];
        let non_resident = a[8] != 0;
        let name_len = a[9] as usize;
        let name_off = u16le(a, 10) as usize;
        let aflags = u16le(a, 12);
        let name = if name_len > 0 && name_off + name_len * 2 <= a.len() {
            let units: Vec<u16> = a[name_off..name_off + name_len * 2].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units)
        } else {
            String::new()
        };
        let value: Option<&[u8]> = if non_resident {
            None
        } else if a.len() >= 24 {
            let vlen = u32le(a, 16) as usize;
            let voff = u16le(a, 20) as usize;
            if voff + vlen <= a.len() {
                Some(&a[voff..voff + vlen])
            } else {
                None
            }
        } else {
            None
        };
        match ty {
            ATTR_STANDARD_INFORMATION => {
                if let Some(v) = value {
                    if v.len() >= 32 {
                        rec.si_times = Some(times_at(v, 0));
                    }
                }
            }
            ATTR_ATTRIBUTE_LIST => rec.has_attribute_list = true,
            ATTR_FILE_NAME => {
                if let Some(v) = value {
                    if v.len() >= 66 {
                        let nlen = v[64] as usize;
                        if nlen > 255 || 66 + nlen * 2 > v.len() {
                            diag::info(code::MFT_NAME_TOO_LONG, format!("record {number}: {nlen} chars"));
                        } else {
                            let units: Vec<u16> = v[66..66 + nlen * 2].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                            let parent_ref = u64le(v, 0);
                            let fn_flags = u32le(v, 56);
                            rec.names.push(FileName {
                                parent: parent_ref & 0x0000_FFFF_FFFF_FFFF,
                                parent_seq: (parent_ref >> 48) as u16,
                                namespace: v[65],
                                name: String::from_utf16_lossy(&units),
                                size: u64le(v, 48),
                                times: times_at(v, 8),
                                is_dir: fn_flags & 0x1000_0000 != 0,
                            });
                        }
                    }
                }
            }
            ATTR_DATA => {
                if non_resident {
                    if a.len() >= 64 {
                        let runs_off = u16le(a, 32) as usize;
                        let real = u64le(a, 48);
                        let (runs, damaged) = if runs_off < a.len() { decode_runs(&a[runs_off..]) } else { (Vec::new(), true) };
                        if damaged {
                            diag::info(code::MFT_RUNLIST_BAD, format!("record {number}: stream '{name}'"));
                        }
                        rec.data.push(DataAttr { name, size: real, resident: None, runs, flags: aflags, runs_damaged: damaged });
                    }
                } else if let Some(v) = value {
                    rec.data.push(DataAttr { name, size: v.len() as u64, resident: Some(v.to_vec()), runs: Vec::new(), flags: aflags, runs_damaged: false });
                }
            }
            _ => {}
        }
        pos += len;
    }
    Some(rec)
}

/// What a record contributes to path building.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameInfo {
    pub parent: u64,
    pub parent_seq: u16,
    pub sequence: u16,
    pub name: String,
    pub is_dir: bool,
    pub in_use: bool,
}

/// A deleted file or directory found in the `$MFT`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deleted {
    pub record: Record,
    /// The path rebuilt from the parent chain, `/`-separated with a leading `/`;
    /// `/$OrphanFiles/...` when the chain breaks.
    pub path: String,
    /// The chain reached the root with every sequence number matching.
    pub path_complete: bool,
}

impl Deleted {
    /// The shown name.
    pub fn name(&self) -> &str {
        self.record.best_name().map(|n| n.name.as_str()).unwrap_or("")
    }

    /// The times: `$STANDARD_INFORMATION` first, `$FILE_NAME` otherwise.
    pub fn times(&self) -> Timestamps {
        self.record.si_times.or_else(|| self.record.best_name().map(|n| n.times)).unwrap_or_default()
    }

    /// Size of the unnamed data stream (the `$FILE_NAME` size when no `$DATA` remains).
    pub fn size(&self) -> u64 {
        self.record.main_data().map(|d| d.size).or_else(|| self.record.best_name().map(|n| n.size)).unwrap_or(0)
    }

    /// Can the content be read back? `with_volume` says whether the clusters are reachable
    /// (false for a bare `$MFT` file, where only resident data is).
    pub fn recoverable(&self, with_volume: bool) -> bool {
        if self.record.is_dir || self.record.has_attribute_list {
            return false;
        }
        match self.record.main_data() {
            Some(d) if d.resident.is_some() => true,
            Some(d) => with_volume && d.is_plain() && (!d.runs.is_empty() || d.size == 0),
            None => false,
        }
    }
}

/// What one worker thread hands back: names, deleted records, in-use count.
type Part = (Vec<(u64, NameInfo)>, Vec<Record>, u64);

/// The result of a scan.
#[derive(Clone, Debug, Default)]
pub struct Scan {
    /// Records read (slots, used or not).
    pub records: u64,
    pub in_use: u64,
    /// Every record with a name, by number: the live tree plus the deleted names, for
    /// path building.
    pub names: HashMap<u64, NameInfo>,
    /// Deleted records with a name, by record number.
    pub deleted: Vec<Deleted>,
    pub bytes: u64,
    pub truncated: bool,
}

/// Parses every record of a stream of `record_size`-byte records, several threads at a
/// time, and rebuilds the paths of the deleted ones. `progress` gets `(bytes read, total)`.
pub fn scan<R: Read>(mut reader: R, record_size: usize, total: u64, mut progress: Option<&mut dyn FnMut(u64, u64)>) -> Scan {
    let mut out = Scan::default();
    if record_size != 1024 && record_size != 4096 {
        diag::error(code::MFT_RECORD_SIZE, format!("{record_size} bytes"));
        return out;
    }
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(1, 8);
    let chunk_bytes = 32usize << 20;
    let mut buf = vec![0u8; chunk_bytes];
    let mut filled = 0usize;
    let mut number: u64 = 0;
    let mut raw_deleted: Vec<Record> = Vec::new();
    let mut eof = false;
    while !eof || filled >= record_size {
        // Fill the buffer with whole records.
        while filled < chunk_bytes && !eof {
            match reader.read(&mut buf[filled..]) {
                Ok(0) => eof = true,
                Ok(n) => filled += n,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    diag::warn(code::MFT_READ, format!("after {} bytes: {e}", out.bytes + filled as u64));
                    out.truncated = true;
                    eof = true;
                }
            }
        }
        let whole = filled / record_size * record_size;
        if whole == 0 {
            break;
        }
        let data = &buf[..whole];
        let count = whole / record_size;
        let per = count.div_ceil(threads).max(1);
        let base = number;
        let parts: Vec<Part> = std::thread::scope(|s| {
            let handles: Vec<_> = data
                .chunks(per * record_size)
                .enumerate()
                .map(|(i, slice)| {
                    let first = base + (i * per) as u64;
                    s.spawn(move || {
                        let mut names = Vec::new();
                        let mut deleted = Vec::new();
                        let mut in_use = 0u64;
                        for (j, raw) in slice.chunks_exact(record_size).enumerate() {
                            let n = first + j as u64;
                            let Some(rec) = parse_record(raw, n) else { continue };
                            if rec.base_record != 0 {
                                continue;
                            }
                            if rec.in_use {
                                in_use += 1;
                            }
                            if let Some(fname) = rec.best_name() {
                                names.push((n, NameInfo { parent: fname.parent, parent_seq: fname.parent_seq, sequence: rec.sequence, name: fname.name.clone(), is_dir: rec.is_dir || fname.is_dir, in_use: rec.in_use }));
                                if !rec.in_use {
                                    deleted.push(rec);
                                }
                            }
                        }
                        // Diagnostics recorded on the worker belong to the caller.
                        (names, deleted, in_use, diag::drain())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    let (names, deleted, in_use, diags) = h.join().unwrap_or_else(|_| (Vec::new(), Vec::new(), 0, Vec::new()));
                    diag::absorb(diags);
                    (names, deleted, in_use)
                })
                .collect()
        });
        for (names, deleted, in_use) in parts {
            out.in_use += in_use;
            for (n, info) in names {
                out.names.insert(n, info);
            }
            raw_deleted.extend(deleted);
        }
        number += count as u64;
        out.records = number;
        out.bytes += whole as u64;
        if let Some(p) = progress.as_deref_mut() {
            p(out.bytes, total);
        }
        if raw_deleted.len() > MAX_DELETED {
            diag::warn(code::MFT_TOO_MANY, format!("{} deleted records", raw_deleted.len()));
            raw_deleted.truncate(MAX_DELETED);
            out.truncated = true;
            break;
        }
        // Keep the tail that is not a whole record.
        let rest = filled - whole;
        buf.copy_within(whole..filled, 0);
        filled = rest;
    }
    raw_deleted.sort_by_key(|r| r.number);
    let mut orphans = 0usize;
    for rec in raw_deleted {
        let (path, complete) = resolve_path(&out.names, &rec);
        if !complete {
            orphans += 1;
        }
        out.deleted.push(Deleted { record: rec, path, path_complete: complete });
    }
    if orphans > 0 {
        diag::info(code::MFT_PARENT_REUSED, format!("{orphans} deleted entries under {ORPHAN_DIR}"));
    }
    diag::info(code::MFT_SCANNED, format!("{} records, {} in use, {} deleted with a name, {} bytes", out.records, out.in_use, out.deleted.len(), out.bytes));
    out
}

/// Rebuilds the path of a record through its parent chain. The chain stops at the root
/// (record 5); a parent that is missing or whose sequence number has moved on breaks it,
/// and the path goes under [`ORPHAN_DIR`].
pub fn resolve_path(names: &HashMap<u64, NameInfo>, rec: &Record) -> (String, bool) {
    let Some(fname) = rec.best_name() else { return (format!("/{ORPHAN_DIR}/record_{}", rec.number), false) };
    let mut parts: Vec<&str> = vec![fname.name.as_str()];
    let mut parent = fname.parent;
    let mut parent_seq = fname.parent_seq;
    let mut complete = true;
    let mut hops = 0;
    loop {
        if parent == 5 {
            break;
        }
        hops += 1;
        if hops > 256 {
            complete = false;
            break;
        }
        match names.get(&parent) {
            Some(info) if info.sequence == parent_seq || (!info.in_use && info.sequence == parent_seq.wrapping_add(1)) => {
                parts.push(info.name.as_str());
                parent = info.parent;
                parent_seq = info.parent_seq;
            }
            _ => {
                complete = false;
                break;
            }
        }
    }
    if !complete {
        parts.push(ORPHAN_DIR);
    }
    parts.reverse();
    (format!("/{}", parts.join("/")), complete)
}

/// Streams the content of a data attribute: resident bytes, or the runs read from
/// `read_cluster(lcn, count) -> bytes`. Sparse runs are zeros. Returns the bytes written,
/// cut to the attribute's real size.
pub fn stream_data(data: &DataAttr, cluster_size: u64, read_clusters: &mut dyn FnMut(u64, u64) -> std::io::Result<Vec<u8>>, sink: &mut dyn std::io::Write, mut progress: Option<&mut dyn FnMut(u64, u64)>) -> std::io::Result<u64> {
    if let Some(v) = &data.resident {
        sink.write_all(v)?;
        if let Some(p) = progress.as_deref_mut() {
            p(v.len() as u64, v.len() as u64);
        }
        return Ok(v.len() as u64);
    }
    let total = data.size;
    let mut done = 0u64;
    let step_clusters = ((4u64 << 20) / cluster_size.max(1)).max(1);
    for run in &data.runs {
        if done >= total {
            break;
        }
        let mut left = run.clusters;
        let mut lcn = run.lcn;
        while left > 0 && done < total {
            let n = left.min(step_clusters);
            let want = (n * cluster_size).min(total - done);
            match lcn {
                None => {
                    let zeros = vec![0u8; want as usize];
                    sink.write_all(&zeros)?;
                }
                Some(l) => {
                    let bytes = read_clusters(l, n)?;
                    let take = (want as usize).min(bytes.len());
                    sink.write_all(&bytes[..take])?;
                    if (take as u64) < want {
                        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, format!("cluster {l}: {take} of {want} bytes")));
                    }
                    lcn = Some(l + n);
                }
            }
            done += want;
            left -= n;
            if let Some(p) = progress.as_deref_mut() {
                p(done, total);
            }
        }
    }
    Ok(done)
}

/// Builds a synthetic `FILE` record for tests and demos: one `$STANDARD_INFORMATION`,
/// one Win32 `$FILE_NAME` under `parent`, and a `$DATA` that is resident (`content`) or
/// non-resident over `runs` with `size` bytes.
#[allow(clippy::too_many_arguments)]
pub fn synthetic_record(number: u64, seq: u16, in_use: bool, is_dir: bool, parent: (u64, u16), name: &str, content: Option<&[u8]>, runs: &[Run], size: u64) -> Vec<u8> {
    let mut r = vec![0u8; 1024];
    r[..4].copy_from_slice(b"FILE");
    r[4..6].copy_from_slice(&48u16.to_le_bytes()); // usa offset
    r[6..8].copy_from_slice(&3u16.to_le_bytes()); // usa count (1 + 2 sectors)
    r[16..18].copy_from_slice(&seq.to_le_bytes());
    r[18..20].copy_from_slice(&1u16.to_le_bytes());
    r[20..22].copy_from_slice(&56u16.to_le_bytes()); // first attribute
    let flags: u16 = (if in_use { FLAG_IN_USE } else { 0 }) | (if is_dir { FLAG_DIRECTORY } else { 0 });
    r[22..24].copy_from_slice(&flags.to_le_bytes());
    r[28..32].copy_from_slice(&1024u32.to_le_bytes());
    r[44..48].copy_from_slice(&(number as u32).to_le_bytes());
    // USA: sequence 0x0101, then the two original sector tails (zero).
    r[48..50].copy_from_slice(&[1, 1]);
    let mut pos = 56usize;
    let t: u64 = 132_000_000_000_000_000; // 2019-03-28
    // $STANDARD_INFORMATION, resident, 48 bytes of value.
    {
        let vlen = 48u32;
        let alen = 24 + vlen as usize;
        r[pos..pos + 4].copy_from_slice(&ATTR_STANDARD_INFORMATION.to_le_bytes());
        r[pos + 4..pos + 8].copy_from_slice(&(alen as u32).to_le_bytes());
        r[pos + 16..pos + 20].copy_from_slice(&vlen.to_le_bytes());
        r[pos + 20..pos + 22].copy_from_slice(&24u16.to_le_bytes());
        for i in 0..4 {
            r[pos + 24 + i * 8..pos + 32 + i * 8].copy_from_slice(&(t + i as u64 * 10_000_000).to_le_bytes());
        }
        pos += alen;
    }
    // $FILE_NAME.
    {
        let units: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let vlen = 66 + units.len();
        let alen = (24 + vlen).div_ceil(8) * 8;
        r[pos..pos + 4].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        r[pos + 4..pos + 8].copy_from_slice(&(alen as u32).to_le_bytes());
        r[pos + 16..pos + 20].copy_from_slice(&(vlen as u32).to_le_bytes());
        r[pos + 20..pos + 22].copy_from_slice(&24u16.to_le_bytes());
        let v = pos + 24;
        let pref = parent.0 | ((parent.1 as u64) << 48);
        r[v..v + 8].copy_from_slice(&pref.to_le_bytes());
        for i in 0..4 {
            r[v + 8 + i * 8..v + 16 + i * 8].copy_from_slice(&t.to_le_bytes());
        }
        r[v + 40..v + 48].copy_from_slice(&size.div_ceil(4096).saturating_mul(4096).to_le_bytes());
        r[v + 48..v + 56].copy_from_slice(&size.to_le_bytes());
        if is_dir {
            r[v + 56..v + 60].copy_from_slice(&0x1000_0000u32.to_le_bytes());
        }
        r[v + 64] = name.encode_utf16().count() as u8;
        r[v + 65] = 1;
        r[v + 66..v + 66 + units.len()].copy_from_slice(&units);
        pos += alen;
    }
    // $DATA.
    if !is_dir {
        r[pos..pos + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        if let Some(c) = content {
            let alen = (24 + c.len()).div_ceil(8) * 8;
            r[pos + 4..pos + 8].copy_from_slice(&(alen as u32).to_le_bytes());
            r[pos + 16..pos + 20].copy_from_slice(&(c.len() as u32).to_le_bytes());
            r[pos + 20..pos + 22].copy_from_slice(&24u16.to_le_bytes());
            r[pos + 24..pos + 24 + c.len()].copy_from_slice(c);
            pos += alen;
        } else {
            let mut rl = Vec::new();
            let mut prev: i64 = 0;
            for run in runs {
                match run.lcn {
                    None => {
                        rl.push(0x01);
                        rl.push(run.clusters as u8);
                    }
                    Some(l) => {
                        let delta = l as i64 - prev;
                        rl.push(0x41);
                        rl.push(run.clusters as u8);
                        rl.extend_from_slice(&(delta as i32).to_le_bytes());
                        prev = l as i64;
                    }
                }
            }
            rl.push(0);
            let alen = (64 + rl.len()).div_ceil(8) * 8;
            r[pos + 4..pos + 8].copy_from_slice(&(alen as u32).to_le_bytes());
            r[pos + 8] = 1;
            r[pos + 32..pos + 34].copy_from_slice(&64u16.to_le_bytes());
            r[pos + 40..pos + 48].copy_from_slice(&size.div_ceil(4096).saturating_mul(4096).to_le_bytes());
            r[pos + 48..pos + 56].copy_from_slice(&size.to_le_bytes());
            r[pos + 56..pos + 64].copy_from_slice(&size.to_le_bytes());
            r[pos + 64..pos + 64 + rl.len()].copy_from_slice(&rl);
            pos += alen;
        }
    }
    r[pos..pos + 4].copy_from_slice(&ATTR_END.to_le_bytes());
    pos += 8;
    r[24..28].copy_from_slice(&(pos as u32).to_le_bytes());
    // Fixups: the last two bytes of each sector carry the USN; the originals go to the USA.
    for i in 1..3usize {
        let end = i * 512;
        r[48 + i * 2] = r[end - 2];
        r[48 + i * 2 + 1] = r[end - 1];
        r[end - 2] = 1;
        r[end - 1] = 1;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() {
        diag::set_quiet(true);
        diag::drain();
    }

    #[test]
    fn synthetic_record_round_trips() {
        quiet();
        let raw = synthetic_record(64, 3, false, false, (5, 5), "secret.txt", Some(b"top secret"), &[], 10);
        let rec = parse_record(&raw, 64).expect("parses");
        assert_eq!(rec.number, 64);
        assert_eq!(rec.sequence, 3);
        assert!(!rec.in_use && !rec.is_dir);
        assert_eq!(rec.names.len(), 1);
        assert_eq!(rec.names[0].name, "secret.txt");
        assert_eq!(rec.names[0].parent, 5);
        assert_eq!(rec.names[0].parent_seq, 5);
        assert_eq!(rec.names[0].size, 10);
        assert!(rec.si_times.unwrap().created.is_some());
        let d = rec.main_data().unwrap();
        assert_eq!(d.resident.as_deref(), Some(&b"top secret"[..]));
        assert_eq!(d.size, 10);
    }

    #[test]
    fn non_resident_runs_decode_and_stream() {
        quiet();
        let runs = [Run { lcn: Some(100), clusters: 2 }, Run { lcn: None, clusters: 1 }, Run { lcn: Some(50), clusters: 1 }];
        let raw = synthetic_record(70, 1, false, false, (5, 5), "big.bin", None, &runs, 4096 * 4 - 100);
        let rec = parse_record(&raw, 70).unwrap();
        let d = rec.main_data().unwrap();
        assert_eq!(d.runs, runs.to_vec());
        assert!(!d.runs_damaged && d.is_plain());
        let mut out = Vec::new();
        let mut reads = Vec::new();
        let n = stream_data(
            d,
            4096,
            &mut |lcn, count| {
                reads.push((lcn, count));
                Ok(vec![lcn as u8; (count * 4096) as usize])
            },
            &mut out,
            None,
        )
        .unwrap();
        assert_eq!(n, 4096 * 4 - 100);
        assert_eq!(out.len() as u64, n);
        assert!(out[..8192].iter().all(|&b| b == 100));
        assert!(out[8192..12288].iter().all(|&b| b == 0), "sparse run is zeros");
        assert!(out[12288..].iter().all(|&b| b == 50));
        assert_eq!(reads, vec![(100, 2), (50, 1)]);
    }

    #[test]
    fn runlist_edge_cases() {
        // Negative delta, then a damaged header.
        let (runs, damaged) = decode_runs(&[0x21, 0x04, 0x00, 0x10, 0x11, 0x02, 0xF0, 0x00]);
        assert_eq!(runs, vec![Run { lcn: Some(0x1000), clusters: 4 }, Run { lcn: Some(0x1000 - 16), clusters: 2 }]);
        assert!(!damaged);
        let (runs, damaged) = decode_runs(&[0x11, 0x02, 0x80]);
        assert!(runs.is_empty() && damaged, "a run before cluster 0 is damage");
        let (runs, damaged) = decode_runs(&[0x19, 0x01]);
        assert!(runs.is_empty() && damaged, "a 9-byte length is impossible");
        let (runs, damaged) = decode_runs(&[]);
        assert!(runs.is_empty() && !damaged);
    }

    #[test]
    fn torn_record_is_rejected_and_junk_too() {
        quiet();
        let mut raw = synthetic_record(1, 1, true, false, (5, 5), "a", Some(b"x"), &[], 1);
        raw[510] = 9; // break the fixup of the first sector
        assert!(parse_record(&raw, 1).is_none());
        assert!(parse_record(&[0u8; 1024], 2).is_none());
        assert!(parse_record(b"FILE", 3).is_none());
    }

    #[test]
    fn scan_rebuilds_paths_and_marks_orphans() {
        quiet();
        let mut mft = Vec::new();
        for n in 0..5u64 {
            mft.extend(synthetic_record(n, 1, true, n == 5, (5, 5), &format!("$meta{n}"), Some(b""), &[], 0));
        }
        mft.extend(synthetic_record(5, 5, true, true, (5, 5), ".", None, &[], 0)); // root
        mft.extend(synthetic_record(6, 1, true, true, (5, 5), "Users", None, &[], 0));
        mft.extend(synthetic_record(7, 2, true, true, (6, 1), "mallory", None, &[], 0));
        mft.extend(synthetic_record(8, 4, false, false, (7, 2), "plan.txt", Some(b"the plan"), &[], 8));
        mft.extend(synthetic_record(9, 1, false, false, (77, 1), "lost.txt", Some(b"lost"), &[], 4));
        mft.extend(synthetic_record(10, 9, false, true, (6, 1), "Temp", None, &[], 0));
        mft.extend(synthetic_record(11, 2, false, false, (10, 8), "inside.bin", None, &[Run { lcn: Some(3), clusters: 1 }], 100));
        mft.extend(vec![0u8; 1024 * 3]); // unused slots
        let total = mft.len() as u64;
        let mut progress = Vec::new();
        let scan = scan(std::io::Cursor::new(mft.clone()), 1024, total, Some(&mut |a, b| progress.push((a, b))));
        assert_eq!(scan.records, 15);
        assert_eq!(scan.in_use, 8);
        assert_eq!(scan.deleted.len(), 4);
        assert_eq!(progress.last(), Some(&(total, total)));
        let by_name = |n: &str| scan.deleted.iter().find(|d| d.name() == n).unwrap();
        let plan = by_name("plan.txt");
        assert_eq!(plan.path, "/Users/mallory/plan.txt");
        assert!(plan.path_complete);
        assert!(plan.recoverable(false), "resident data comes back even from a bare $MFT");
        assert_eq!(plan.size(), 8);
        let lost = by_name("lost.txt");
        assert_eq!(lost.path, "/$OrphanFiles/lost.txt");
        assert!(!lost.path_complete);
        let temp = by_name("Temp");
        assert_eq!(temp.path, "/Users/Temp");
        assert!(!temp.recoverable(true), "directories have no content");
        let inside = by_name("inside.bin");
        assert_eq!(inside.path, "/Users/Temp/inside.bin", "a deleted parent one sequence later still matches");
        assert!(inside.recoverable(true) && !inside.recoverable(false));
        assert!(diag::has(code::MFT_SCANNED) && diag::has(code::MFT_PARENT_REUSED));
        // Deterministic.
        let again = super::scan(std::io::Cursor::new(mft), 1024, total, None);
        assert_eq!(again.deleted, scan.deleted);
    }

    #[test]
    fn wrong_record_size_is_an_error() {
        quiet();
        let s = scan(std::io::Cursor::new(vec![0u8; 2048]), 512, 2048, None);
        assert_eq!(s.records, 0);
        assert!(diag::has(code::MFT_RECORD_SIZE));
    }
}
