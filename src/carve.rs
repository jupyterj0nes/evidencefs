//! Carving: files found by their signature in bytes that no file system entry points at
//! any more (unallocated clusters, slack, a memory dump, a bare partition). Built on
//! [blockcarve](https://github.com/jupyterj0nes/blockcarve): the scanner reads the source in
//! 4 MB blocks, every sector-aligned signature is validated by a parser that walks the
//! structure to its real end, and only structures that prove themselves are kept.
//!
//! Kinds: registry hives (`regf`), event log chunks (`ElfChnk`, runs of consecutive chunks
//! rebuilt into a readable `.evtx`), Prefetch (`SCCA` and the compressed `MAM`), shell
//! links, SQLite databases, PE executables, PDF, zip (docx, xlsx, jar...), JPEG and PNG.
//! Each carved item has a stable id, `<kind>_<offset in hex>`, and a size; [`read`] streams
//! its bytes. The scan splits the source in ranges and runs one thread per range; the
//! results are merged in offset order, so two scans of the same bytes give the same list.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use blockcarve::scan::{scan_many, HitAction, ScanConfig};
use blockcarve::source::{BlockError, BlockSource};

use crate::diag;
use crate::error::{Error, Result};
use crate::source::SharedReader;

pub mod code {
    crate::codes! {
        CARVE_EMPTY = 850, "the source has no bytes to scan";
        CARVE_NO_KINDS = 851, "no carve kind was selected; pick at least one of hive, evtx, prefetch, lnk, sqlite, pe, pdf, zip, jpeg, png";
        CARVE_STARTED = 852, "a carve scan started: source size, kinds, threads";
        CARVE_FOUND = 853, "a carve scan finished: items per kind, bytes read, read errors";
        CARVE_CANCELLED = 854, "the carve scan was cancelled by the caller; the items found so far are kept";
        CARVE_READ_ERROR = 855, "a block of the source could not be read during the scan; the window was skipped and the scan went on";
        CARVE_LIMIT = 856, "the scan found more items than the limit and stopped listing new ones";
        CARVE_OVERSIZE = 857, "a structure declares a size above the per-item limit; it was cut to the limit and marked incomplete";
        CARVE_HIVE_TRUNCATED = 858, "a carved hive's bins end before its declared size (overwritten or fragmented); the verified prefix is what reads back";
        CARVE_EVTX_RUN = 859, "a run of consecutive event log chunks was carved as one .evtx with a rebuilt file header";
        CARVE_INVALID_ID = 860, "a $CARVED id is not <kind>_<offset in hex>; use the id shown in the listing";
        CARVE_NOT_FOUND = 861, "no carved item has that id in this scan's results; run the scan again with the kind included";
        CARVE_UNSUPPORTED_SOURCE = 862, "carving needs an image, a volume or a single file; a folder or an archive has no unallocated space to scan";
        CARVE_KIND_UNKNOWN = 863, "a carve kind name was not recognised; the known kinds are hive, evtx, prefetch, lnk, sqlite, pe, pdf, zip, jpeg, png";
        CARVE_READ = 864, "reading a carved item back failed part-way; the bytes read so far are kept";
    }
}

/// Per-item size cap by default (256 MB).
pub const DEFAULT_MAX_SIZE: u64 = 256 << 20;
/// Items listed by default before the scan stops adding.
pub const DEFAULT_MAX_ITEMS: usize = 200_000;
/// Bytes read forward when a structure has no size field (PDF, zip, JPEG).
const FORWARD_STEP: usize = 1 << 20;

/// What to look for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CarveKind {
    Hive,
    Evtx,
    Prefetch,
    Lnk,
    Sqlite,
    Pe,
    Pdf,
    Zip,
    Jpeg,
    Png,
}

impl CarveKind {
    /// Every kind, in a stable order.
    pub const ALL: [CarveKind; 10] = [CarveKind::Hive, CarveKind::Evtx, CarveKind::Prefetch, CarveKind::Lnk, CarveKind::Sqlite, CarveKind::Pe, CarveKind::Pdf, CarveKind::Zip, CarveKind::Jpeg, CarveKind::Png];

    /// The name used in ids and on the command line.
    pub fn name(&self) -> &'static str {
        match self {
            CarveKind::Hive => "hive",
            CarveKind::Evtx => "evtx",
            CarveKind::Prefetch => "prefetch",
            CarveKind::Lnk => "lnk",
            CarveKind::Sqlite => "sqlite",
            CarveKind::Pe => "pe",
            CarveKind::Pdf => "pdf",
            CarveKind::Zip => "zip",
            CarveKind::Jpeg => "jpeg",
            CarveKind::Png => "png",
        }
    }

    /// What it is, for a list.
    pub fn describe(&self) -> &'static str {
        match self {
            CarveKind::Hive => "registry hives (regf): SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat and their shadow copies",
            CarveKind::Evtx => "Windows event log chunks (ElfChnk), consecutive chunks rebuilt into one .evtx",
            CarveKind::Prefetch => "Prefetch files (SCCA, and the Windows 10 compressed MAM form)",
            CarveKind::Lnk => "shell links (.lnk), the header walked to its exact end",
            CarveKind::Sqlite => "SQLite databases (browser history, cookies, mail stores), size from the header",
            CarveKind::Pe => "PE executables and DLLs, size from the section table",
            CarveKind::Pdf => "PDF documents, from %PDF- to the last %%EOF",
            CarveKind::Zip => "zip archives and Office documents (docx, xlsx, pptx), jars and apks, verified by the end-of-central-directory record",
            CarveKind::Jpeg => "JPEG images, markers walked to the end of the scan data",
            CarveKind::Png => "PNG images, chunks walked to IEND",
        }
    }

    /// File extension of a carved copy.
    pub fn extension(&self) -> &'static str {
        match self {
            CarveKind::Hive => "hive",
            CarveKind::Evtx => "evtx",
            CarveKind::Prefetch => "pf",
            CarveKind::Lnk => "lnk",
            CarveKind::Sqlite => "sqlite",
            CarveKind::Pe => "exe",
            CarveKind::Pdf => "pdf",
            CarveKind::Zip => "zip",
            CarveKind::Jpeg => "jpg",
            CarveKind::Png => "png",
        }
    }

    /// By name (case-insensitive; `all` is not a kind, see [`parse_kinds`]).
    pub fn parse(s: &str) -> Option<CarveKind> {
        let l = s.trim().to_ascii_lowercase();
        CarveKind::ALL.iter().copied().find(|k| k.name() == l || k.extension() == l || (l == "registry" && *k == CarveKind::Hive) || (l == "exe" || l == "dll") && *k == CarveKind::Pe || (l == "jpg" && *k == CarveKind::Jpeg))
    }

    /// The byte signatures the scanner looks for.
    pub fn signatures(&self) -> Vec<&'static [u8]> {
        match self {
            CarveKind::Hive => vec![b"regf"],
            CarveKind::Evtx => vec![blockcarve::evtx::CHUNK_MAGIC],
            CarveKind::Prefetch => {
                let mut v: Vec<&'static [u8]> = blockcarve::prefetch::SCCA_SIGNATURES.to_vec();
                v.push(blockcarve::prefetch::MAM_MAGIC);
                v
            }
            CarveKind::Lnk => vec![b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"],
            CarveKind::Sqlite => vec![b"SQLite format 3\x00"],
            CarveKind::Pe => vec![b"MZ"],
            CarveKind::Pdf => vec![b"%PDF-"],
            CarveKind::Zip => vec![b"PK\x03\x04"],
            CarveKind::Jpeg => vec![b"\xff\xd8\xff"],
            CarveKind::Png => vec![b"\x89PNG\r\n\x1a\n"],
        }
    }
}

/// Parses a comma-separated list of kinds; `all` means every kind.
pub fn parse_kinds(list: &str) -> Result<Vec<CarveKind>> {
    let mut out = Vec::new();
    for part in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if part.eq_ignore_ascii_case("all") {
            for k in CarveKind::ALL {
                if !out.contains(&k) {
                    out.push(k);
                }
            }
            continue;
        }
        let k = CarveKind::parse(part).ok_or_else(|| Error::recorded(code::CARVE_KIND_UNKNOWN, part.to_string()))?;
        if !out.contains(&k) {
            out.push(k);
        }
    }
    if out.is_empty() {
        return Err(Error::recorded(code::CARVE_NO_KINDS, list.to_string()));
    }
    out.sort();
    Ok(out)
}

/// How to scan.
#[derive(Clone, Debug)]
pub struct CarveOptions {
    pub kinds: Vec<CarveKind>,
    /// Threads (0: one per core, at most 8).
    pub threads: usize,
    /// Largest item kept whole.
    pub max_size: u64,
    /// Items listed before the scan stops adding.
    pub max_items: usize,
    /// Alignment of candidate signatures (512 for disks; 1 scans every byte).
    pub step: usize,
}

impl Default for CarveOptions {
    fn default() -> Self {
        CarveOptions { kinds: CarveKind::ALL.to_vec(), threads: 0, max_size: DEFAULT_MAX_SIZE, max_items: DEFAULT_MAX_ITEMS, step: 512 }
    }
}

/// One structure found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carved {
    pub kind: CarveKind,
    /// Absolute offset of the signature in the source.
    pub offset: u64,
    /// Bytes [`read`] gives back.
    pub size: u64,
    /// What the structure says about itself: hive name, image dimensions, first zip
    /// member, chunk count...
    pub label: String,
    /// The structure ends where its header says; false when it was cut or its end was
    /// not found.
    pub complete: bool,
}

impl Carved {
    /// `<kind>_<offset in hex>`.
    pub fn id(&self) -> String {
        format!("{}_{:x}", self.kind.name(), self.offset)
    }

    /// `<kind>_<offset in hex>.<ext>`, or with the label's name when it has one.
    pub fn file_name(&self) -> String {
        let hint = match self.kind {
            CarveKind::Hive | CarveKind::Prefetch => self.label.split_whitespace().next().unwrap_or(""),
            _ => "",
        };
        let hint: String = hint.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')).take(40).collect();
        if hint.is_empty() {
            format!("{}.{}", self.id(), self.kind.extension())
        } else {
            format!("{}_{hint}.{}", self.id(), self.kind.extension())
        }
    }

    /// Parses an id back into kind and offset.
    pub fn parse_id(id: &str) -> Result<(CarveKind, u64)> {
        let (k, off) = id.trim().rsplit_once('_').ok_or_else(|| Error::new(code::CARVE_INVALID_ID, id.to_string()))?;
        let kind = CarveKind::parse(k).ok_or_else(|| Error::new(code::CARVE_INVALID_ID, id.to_string()))?;
        let offset = u64::from_str_radix(off.trim_start_matches("0x"), 16).map_err(|_| Error::new(code::CARVE_INVALID_ID, id.to_string()))?;
        Ok((kind, offset))
    }

    /// One line.
    pub fn describe(&self) -> String {
        format!("{} @ {:#x} {} bytes{}{}", self.kind.name(), self.offset, self.size, if self.label.is_empty() { String::new() } else { format!(" [{}]", self.label) }, if self.complete { "" } else { " (incomplete)" })
    }
}

/// What a scan did, besides the items.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CarveStats {
    pub bytes_read: u64,
    pub signatures: usize,
    pub read_errors: usize,
    pub cancelled: bool,
    pub truncated: bool,
}

/// A range of the shared reader as a block source (the carry window past the end
/// included, so a structure cut by the range end is still seen whole).
struct RangeSource {
    reader: SharedReader,
    start: u64,
    len: u64,
    label: String,
    cancel: Option<Arc<AtomicBool>>,
    done: Arc<AtomicU64>,
}

impl BlockSource for RangeSource {
    fn size(&self) -> u64 {
        self.len
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn read_block(&mut self, offset: u64, len: usize) -> std::result::Result<Vec<u8>, BlockError> {
        if self.cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(BlockError::Unavailable("cancelled".into()));
        }
        if offset >= self.len {
            return Ok(Vec::new());
        }
        let want = len.min((self.len - offset) as usize);
        let mut buf = vec![0u8; want];
        match self.reader.read_at(self.start + offset, &mut buf) {
            Ok(()) => {
                self.done.fetch_add(want as u64, Ordering::Relaxed);
                Ok(buf)
            }
            Err(e) => Err(BlockError::Io(e.to_string())),
        }
    }
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Reads `n` bytes at `offset`, shorter at the end of the source.
fn bytes_at(reader: &SharedReader, offset: u64, n: usize) -> Vec<u8> {
    let len = reader.len();
    if offset >= len {
        return Vec::new();
    }
    let n = n.min((len - offset) as usize);
    reader.bytes_at(offset, n).unwrap_or_default()
}

/// Walks forward from `start` in steps looking for `needle`, up to `max` bytes; returns
/// the absolute offset of the match. `stop` may end the search early when it sees a
/// block (it gets the absolute offset of the block and the bytes).
/// Early-stop callback of the forward search: absolute offset of a block and its bytes.
type StopFn<'a> = &'a mut dyn FnMut(u64, &[u8]) -> bool;

fn find_forward(reader: &SharedReader, start: u64, needle: &[u8], max: u64, mut stop: Option<StopFn<'_>>) -> Option<u64> {
    let mut pos = start;
    let end = start.saturating_add(max).min(reader.len());
    let mut carry: Vec<u8> = Vec::new();
    while pos < end {
        let want = FORWARD_STEP.min((end - pos) as usize);
        let block = bytes_at(reader, pos, want);
        if block.is_empty() {
            break;
        }
        let base = pos - carry.len() as u64;
        let mut buf = std::mem::take(&mut carry);
        buf.extend_from_slice(&block);
        if let Some(i) = buf.windows(needle.len()).position(|w| w == needle) {
            return Some(base + i as u64);
        }
        if let Some(s) = stop.as_deref_mut() {
            if s(pos, &block) {
                return None;
            }
        }
        let keep = needle.len().saturating_sub(1).min(buf.len());
        carry = buf[buf.len() - keep..].to_vec();
        pos += block.len() as u64;
    }
    None
}

/// Validates the structure at `offset` for one kind; `window` is what the scanner saw.
pub fn validate(reader: &SharedReader, kind: CarveKind, offset: u64, window: &[u8], max_size: u64) -> Option<Carved> {
    match kind {
        CarveKind::Hive => {
            let h = blockcarve::hive::validate_base_block(window).ok()?;
            let declared = blockcarve::hive::BASE_BLOCK_SIZE as u64 + h.data_size as u64;
            let (size, complete) = cap(declared, max_size);
            Some(Carved { kind, offset, size, label: format!("{} seq {}/{}", h.file_name(), h.primary_sequence, h.secondary_sequence), complete })
        }
        CarveKind::Evtx => {
            let chunk = bytes_at(reader, offset, blockcarve::evtx::CHUNK_SIZE);
            if !blockcarve::evtx::chunk_checksums_ok(&chunk) {
                return None;
            }
            let h = blockcarve::evtx::ChunkHeader::parse(&chunk)?;
            Some(Carved { kind, offset, size: blockcarve::evtx::CHUNK_SIZE as u64, label: format!("records {}-{}", h.first_record_id, h.last_record_id), complete: true })
        }
        CarveKind::Prefetch => {
            let c = blockcarve::prefetch::candidate(window)?;
            let name = if c.version.is_some() && window.len() >= 76 {
                let units: Vec<u16> = window[16..76].chunks_exact(2).map(|x| u16::from_le_bytes([x[0], x[1]])).take_while(|&u| u != 0).collect();
                String::from_utf16_lossy(&units)
            } else {
                String::new()
            };
            let (size, complete) = match c.stored_size {
                Some(s) => cap(s as u64, max_size),
                None => (cap(c.decompressed_size as u64, max_size).0, false),
            };
            let label = if name.is_empty() { format!("MAM compressed, {} bytes decompressed", c.decompressed_size) } else { format!("{name} v{}", c.version.unwrap_or(0)) };
            Some(Carved { kind, offset, size, label, complete })
        }
        CarveKind::Lnk => {
            let size = lnk_size(reader, offset, window)?;
            let (size, complete) = cap(size, max_size.min(1 << 20));
            Some(Carved { kind, offset, size, label: String::new(), complete })
        }
        CarveKind::Sqlite => {
            if window.len() < 100 {
                return None;
            }
            let ps = u16::from_be_bytes([window[16], window[17]]) as u64;
            let page_size = if ps == 1 { 65536 } else { ps };
            if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() || window[21] != 64 || window[22] != 32 || window[23] != 32 {
                return None;
            }
            let pages = be32(window, 28) as u64;
            let change_counter = be32(window, 24);
            let valid_for = be32(window, 92);
            if pages == 0 || change_counter != valid_for {
                return None;
            }
            let (size, complete) = cap(page_size * pages, max_size);
            Some(Carved { kind, offset, size, label: format!("{pages} pages of {page_size}"), complete })
        }
        CarveKind::Pe => {
            let (raw_size, info) = pe_size(reader, offset, window)?;
            let (size, complete) = cap(raw_size, max_size);
            Some(Carved { kind, offset, size, label: size_label_pe(info), complete })
        }
        CarveKind::Pdf => {
            if window.len() < 8 || !window[5].is_ascii_digit() {
                return None;
            }
            let version = String::from_utf8_lossy(&window[5..window.len().min(8)]).trim_end_matches(|c: char| !c.is_ascii_digit() && c != '.').to_string();
            // The last %%EOF before another header or a run of zeros.
            let limit = max_size.min(64 << 20);
            let mut last_eof: Option<u64> = None;
            let mut pos = offset;
            let end = offset.saturating_add(limit).min(reader.len());
            let needle = b"%%EOF";
            while pos < end {
                let hit = find_forward(reader, pos, needle, end - pos, Some(&mut |abs, block: &[u8]| abs > offset && (block.windows(5).any(|w| w == b"%PDF-") || block.iter().take(4096).all(|&b| b == 0))))?;
                last_eof = Some(hit + needle.len() as u64);
                // Past this %%EOF: a newline or two, then either more PDF or something else.
                let tail = bytes_at(reader, hit + 5, 512);
                let trimmed = tail.iter().position(|&b| b != b'\r' && b != b'\n' && b != b' ');
                match trimmed {
                    Some(i) if tail[i..].starts_with(b"%PDF-") || tail[i] == 0 => break,
                    None => break,
                    Some(_) => pos = hit + 5,
                }
                if last_eof.is_some() && pos >= end {
                    break;
                }
            }
            let mut eof = last_eof?;
            // The end-of-line after %%EOF belongs to the file.
            let tail = bytes_at(reader, eof, 2);
            for b in tail {
                if b == 13 || b == 10 {
                    eof += 1;
                } else {
                    break;
                }
            }
            Some(Carved { kind, offset, size: eof - offset, label: format!("PDF {version}"), complete: true })
        }
        CarveKind::Zip => {
            if window.len() < 30 {
                return None;
            }
            let name_len = le16(window, 26) as usize;
            let extra_len = le16(window, 28) as usize;
            let version = le16(window, 4);
            if version > 100 || name_len > 1024 || 30 + name_len > window.len() {
                return None;
            }
            let first = String::from_utf8_lossy(&window[30..30 + name_len]).to_string();
            if first.chars().any(|c| (c as u32) < 32) {
                return None;
            }
            let _ = extra_len;
            let limit = max_size.min(256 << 20);
            let mut pos = offset + 30;
            let end = offset.saturating_add(limit).min(reader.len());
            let mut result = None;
            while pos < end {
                let hit = find_forward(reader, pos, b"PK\x05\x06", end - pos, None)?;
                let eocd = bytes_at(reader, hit, 22 + 65535);
                if eocd.len() < 22 {
                    break;
                }
                let cd_size = le32(&eocd, 12) as u64;
                let cd_off = le32(&eocd, 16) as u64;
                let comment = le16(&eocd, 20) as u64;
                if cd_off != 0xFFFF_FFFF && offset + cd_off + cd_size == hit {
                    result = Some(hit + 22 + comment - offset);
                    break;
                }
                // An end record of another archive (this hit was an inner member): stop.
                if offset + cd_off + cd_size < hit {
                    break;
                }
                pos = hit + 4;
            }
            let size = result?;
            Some(Carved { kind, offset, size, label: first, complete: true })
        }
        CarveKind::Jpeg => {
            let (size, dims) = jpeg_size(reader, offset, max_size.min(64 << 20))?;
            Some(Carved { kind, offset, size, label: dims, complete: true })
        }
        CarveKind::Png => {
            let (size, dims, complete) = png_size(reader, offset, max_size.min(64 << 20))?;
            Some(Carved { kind, offset, size, label: dims, complete })
        }
    }
}

fn cap(size: u64, max: u64) -> (u64, bool) {
    if size > max {
        (max, false)
    } else {
        (size, true)
    }
}

fn size_label_pe((machine, sections, dll): (u16, u16, bool)) -> String {
    let m = match machine {
        0x14c => "x86",
        0x8664 => "x64",
        0x1c0 | 0x1c4 => "ARM",
        0xaa64 => "ARM64",
        _ => "PE",
    };
    format!("{m} {} {sections} sections", if dll { "DLL" } else { "EXE" })
}

/// `(size, (machine, sections, is_dll))` from the PE headers and section table.
fn pe_size(reader: &SharedReader, offset: u64, window: &[u8]) -> Option<(u64, (u16, u16, bool))> {
    if window.len() < 64 {
        return None;
    }
    let e_lfanew = le32(window, 60) as u64;
    if !(64..=4096).contains(&e_lfanew) {
        return None;
    }
    let hdr = bytes_at(reader, offset + e_lfanew, 24 + 240 + 40 * 96);
    if hdr.len() < 24 + 20 || &hdr[..4] != b"PE\0\0" {
        return None;
    }
    let machine = le16(&hdr, 4);
    let sections = le16(&hdr, 6);
    let opt_size = le16(&hdr, 20) as usize;
    let chars = le16(&hdr, 22);
    if sections == 0 || sections > 96 || opt_size < 2 {
        return None;
    }
    let magic = le16(&hdr, 24);
    let (cert_off, cert_size) = match magic {
        0x10b if opt_size >= 128 + 8 => (le32(&hdr, 24 + 128) as u64, le32(&hdr, 24 + 132) as u64),
        0x20b if opt_size >= 144 + 8 => (le32(&hdr, 24 + 144) as u64, le32(&hdr, 24 + 148) as u64),
        0x10b | 0x20b => (0, 0),
        _ => return None,
    };
    let headers_size = match magic {
        0x10b => le32(&hdr, 24 + 60) as u64,
        _ => le32(&hdr, 24 + 60) as u64,
    };
    let table = 24 + opt_size;
    let mut end = headers_size;
    for i in 0..sections as usize {
        let s = table + i * 40;
        if s + 40 > hdr.len() {
            return None;
        }
        let raw_ptr = le32(&hdr, s + 20) as u64;
        let raw_size = le32(&hdr, s + 16) as u64;
        end = end.max(raw_ptr + raw_size);
    }
    if cert_off != 0 && cert_size != 0 {
        end = end.max(cert_off + cert_size);
    }
    if end < e_lfanew + 24 || end > 4 << 30 {
        return None;
    }
    Some((end, (machine, sections, chars & 0x2000 != 0)))
}

/// Walks a shell link's structures to its end.
fn lnk_size(reader: &SharedReader, offset: u64, window: &[u8]) -> Option<u64> {
    if window.len() < 76 {
        return None;
    }
    let flags = le32(window, 20);
    let data = bytes_at(reader, offset, 1 << 20);
    let mut pos = 76usize;
    let need = |pos: usize, n: usize| if pos + n <= data.len() { Some(()) } else { None };
    if flags & 0x01 != 0 {
        need(pos, 2)?;
        pos += 2 + le16(&data, pos) as usize;
    }
    if flags & 0x02 != 0 {
        need(pos, 4)?;
        let n = le32(&data, pos) as usize;
        if n < 28 {
            return None;
        }
        pos += n;
    }
    let unicode = flags & 0x80 != 0;
    for bit in [0x04u32, 0x08, 0x10, 0x20, 0x40] {
        if flags & bit != 0 {
            need(pos, 2)?;
            let count = le16(&data, pos) as usize;
            pos += 2 + if unicode { count * 2 } else { count };
        }
    }
    loop {
        need(pos, 4)?;
        let n = le32(&data, pos) as usize;
        if n < 4 {
            pos += 4;
            break;
        }
        pos += n;
    }
    need(pos, 0)?;
    Some(pos as u64)
}

/// JPEG: skips the marker segments to the scan data, then finds the end of image.
fn jpeg_size(reader: &SharedReader, offset: u64, max: u64) -> Option<(u64, String)> {
    let head = bytes_at(reader, offset, 1 << 20);
    if head.len() < 4 || head[0] != 0xFF || head[1] != 0xD8 {
        return None;
    }
    let mut pos = 2usize;
    let mut dims = String::new();
    loop {
        if pos + 4 > head.len() {
            return None;
        }
        if head[pos] != 0xFF {
            return None;
        }
        let marker = head[pos + 1];
        if marker == 0xD8 || (0xD0..=0xD7).contains(&marker) || marker == 0x01 || marker == 0xFF {
            pos += if marker == 0xFF { 1 } else { 2 };
            continue;
        }
        let len = u16::from_be_bytes([head[pos + 2], head[pos + 3]]) as usize;
        if len < 2 {
            return None;
        }
        if matches!(marker, 0xC0 | 0xC1 | 0xC2 | 0xC3 | 0xC5 | 0xC6 | 0xC7 | 0xC9 | 0xCA | 0xCB | 0xCD | 0xCE | 0xCF) && pos + 9 <= head.len() {
            let h = u16::from_be_bytes([head[pos + 5], head[pos + 6]]);
            let w = u16::from_be_bytes([head[pos + 7], head[pos + 8]]);
            dims = format!("{w}x{h}");
        }
        if marker == 0xDA {
            pos += 2 + len;
            break;
        }
        pos += 2 + len;
    }
    // Entropy-coded data: FF 00 is a stuffed byte, FF D0-D7 a restart, FF D9 the end.
    let mut abs = offset + pos as u64;
    let end = offset.saturating_add(max).min(reader.len());
    let mut prev_ff = false;
    while abs < end {
        let block = bytes_at(reader, abs, FORWARD_STEP.min((end - abs) as usize));
        if block.is_empty() {
            break;
        }
        for (i, &b) in block.iter().enumerate() {
            if prev_ff {
                prev_ff = false;
                if b == 0xD9 {
                    return Some((abs + i as u64 + 1 - offset, dims));
                }
                if b == 0xFF {
                    prev_ff = true;
                }
            } else if b == 0xFF {
                prev_ff = true;
            }
        }
        abs += block.len() as u64;
    }
    None
}

/// PNG: walks the chunks to IEND. `(size, dims, complete)`.
fn png_size(reader: &SharedReader, offset: u64, max: u64) -> Option<(u64, String, bool)> {
    let mut pos = offset + 8;
    let end = offset.saturating_add(max).min(reader.len());
    let mut dims = String::new();
    let mut chunks = 0;
    while pos + 12 <= end {
        let h = bytes_at(reader, pos, 8);
        if h.len() < 8 {
            return None;
        }
        let len = be32(&h, 0) as u64;
        let ty = &h[4..8];
        if !ty.iter().all(|c| c.is_ascii_alphabetic()) || len > 1 << 31 {
            // The chunks stop before IEND: the image was cut or overwritten here.
            return (chunks > 1).then_some((pos - offset, dims, false));
        }
        if ty == b"IHDR" {
            let d = bytes_at(reader, pos + 8, 8);
            if d.len() == 8 {
                dims = format!("{}x{}", be32(&d, 0), be32(&d, 4));
            }
        }
        chunks += 1;
        pos += 12 + len;
        if ty == b"IEND" {
            return Some((pos - offset, dims, true));
        }
        if chunks > 100_000 {
            return None;
        }
    }
    (chunks > 1).then_some((end - offset, dims, false))
}

/// Scans the reader for the kinds in `opts`. Items come back sorted by offset; the same
/// bytes always give the same list.
pub fn scan(reader: &SharedReader, opts: &CarveOptions, mut progress: Option<&mut dyn FnMut(u64, u64)>, cancel: Option<Arc<AtomicBool>>) -> Result<(Vec<Carved>, CarveStats)> {
    let total = reader.len();
    if total == 0 {
        return Err(Error::recorded(code::CARVE_EMPTY, "0 bytes"));
    }
    if opts.kinds.is_empty() {
        return Err(Error::recorded(code::CARVE_NO_KINDS, "none selected"));
    }
    let mut kinds = opts.kinds.clone();
    kinds.sort();
    kinds.dedup();
    // One signature table: (bytes, kind).
    let mut table: Vec<(&'static [u8], CarveKind)> = Vec::new();
    for k in &kinds {
        for s in k.signatures() {
            table.push((s, *k));
        }
    }
    let sigs: Vec<&[u8]> = table.iter().map(|(s, _)| *s).collect();
    let threads = if opts.threads == 0 { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(1, 8) } else { opts.threads.clamp(1, 64) };
    // Ranges of at least 64 MB, aligned to the step.
    let min_range = 64u64 << 20;
    let ranges = ((total / min_range).max(1) as usize).min(threads).max(1);
    let step = opts.step.max(1) as u64;
    let range_len = total.div_ceil(ranges as u64).div_ceil(step) * step;
    let window = 8192usize;
    diag::info(code::CARVE_STARTED, format!("{} bytes, kinds {}, {ranges} range(s) on {threads} thread(s)", total, kinds.iter().map(|k| k.name()).collect::<Vec<_>>().join(",")));
    let done = Arc::new(AtomicU64::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let max_items = opts.max_items;
    let max_size = opts.max_size;
    let results: Vec<(Vec<Carved>, CarveStats, Vec<diag::Diagnostic>)> = std::thread::scope(|s| {
        let mut handles = Vec::new();
        for i in 0..ranges {
            let start = i as u64 * range_len;
            if start >= total {
                break;
            }
            let own = range_len.min(total - start);
            let visible = (own + window as u64).min(total - start);
            let reader = reader.clone();
            let sigs = sigs.clone();
            let table = table.clone();
            let cancel = cancel.clone();
            let done = done.clone();
            let finished = finished.clone();
            handles.push(s.spawn(move || {
                diag::set_quiet(diag::is_quiet());
                let mut src = RangeSource { reader: reader.clone(), start, len: visible, label: format!("range {i}"), cancel: cancel.clone(), done };
                let cfg = ScanConfig { block_size: blockcarve::scan::BLOCK_SIZE, window, step: step as usize };
                let mut items: Vec<Carved> = Vec::new();
                let mut stats = CarveStats::default();
                let mut on_hit = |_s: &mut dyn BlockSource, rel: u64, bytes: &[u8], which: usize| -> HitAction {
                    if rel >= own {
                        return HitAction::SkipTo(u64::MAX);
                    }
                    if items.len() >= max_items {
                        stats.truncated = true;
                        return HitAction::SkipTo(u64::MAX);
                    }
                    let kind = table[which].1;
                    if let Some(c) = validate(&reader, kind, start + rel, bytes, max_size) {
                        let skip = c.size;
                        items.push(c);
                        // Jump past the structure (its inner signatures are not new files),
                        // except for chunk-sized kinds where consecutive items matter.
                        if kind != CarveKind::Evtx && skip > step {
                            return HitAction::SkipTo(rel + skip);
                        }
                    }
                    HitAction::Continue
                };
                let mut on_progress = |_o: u64, _t: u64| {};
                let st = scan_many(&mut src, &cfg, &sigs, &mut on_hit, &mut on_progress, None);
                stats.bytes_read = st.bytes_read;
                stats.signatures = st.signatures;
                stats.read_errors = st.read_errors;
                stats.cancelled = st.aborted && cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed));
                for n in st.notes.iter().take(5) {
                    diag::info(code::CARVE_READ_ERROR, n.clone());
                }
                finished.fetch_add(1, Ordering::Relaxed);
                (items, stats, diag::drain())
            }));
        }
        let spawned = handles.len();
        // Poll for progress while the workers run.
        if progress.is_some() {
            while finished.load(Ordering::Relaxed) < spawned {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Some(p) = progress.as_deref_mut() {
                    p(done.load(Ordering::Relaxed).min(total), total);
                }
            }
        }
        handles.into_iter().map(|h| h.join().unwrap_or_else(|_| (Vec::new(), CarveStats::default(), Vec::new()))).collect()
    });
    let mut items: Vec<Carved> = Vec::new();
    let mut stats = CarveStats::default();
    for (list, st, diags) in results {
        diag::absorb(diags);
        items.extend(list);
        stats.bytes_read += st.bytes_read;
        stats.signatures += st.signatures;
        stats.read_errors += st.read_errors;
        stats.cancelled |= st.cancelled;
        stats.truncated |= st.truncated;
    }
    items.sort_by_key(|c| (c.offset, c.kind));
    items.dedup_by(|a, b| a.offset == b.offset && a.kind == b.kind);
    // Consecutive event log chunks become one .evtx.
    items = merge_evtx_runs(items);
    if items.len() > max_items {
        diag::warn(code::CARVE_LIMIT, format!("{} items, limit {max_items}", items.len()));
        items.truncate(max_items);
        stats.truncated = true;
    }
    if stats.cancelled {
        diag::warn(code::CARVE_CANCELLED, format!("{} items so far", items.len()));
    }
    let mut per_kind: Vec<String> = Vec::new();
    for k in &kinds {
        let n = items.iter().filter(|c| c.kind == *k).count();
        if n > 0 {
            per_kind.push(format!("{} {}", n, k.name()));
        }
    }
    diag::info(code::CARVE_FOUND, format!("{} item(s): {}; {} bytes read, {} read error(s)", items.len(), if per_kind.is_empty() { "none".to_string() } else { per_kind.join(", ") }, stats.bytes_read, stats.read_errors));
    if let Some(p) = progress {
        p(total, total);
    }
    Ok((items, stats))
}

/// Chunks that follow each other become one item of `n` chunks; its `size` is the size of
/// the rebuilt file (a 4 KB header plus the chunks).
fn merge_evtx_runs(items: Vec<Carved>) -> Vec<Carved> {
    let chunk = blockcarve::evtx::CHUNK_SIZE as u64;
    let mut out: Vec<Carved> = Vec::with_capacity(items.len());
    let mut run: Option<(u64, u64, String, String)> = None; // start, chunks, first label, last label
    let flush = |run: &mut Option<(u64, u64, String, String)>, out: &mut Vec<Carved>| {
        if let Some((start, n, first, last)) = run.take() {
            let first_id = first.strip_prefix("records ").and_then(|s| s.split('-').next()).unwrap_or("?");
            let last_id = last.strip_prefix("records ").and_then(|s| s.rsplit('-').next()).unwrap_or("?");
            if n > 1 {
                diag::info(code::CARVE_EVTX_RUN, format!("{n} chunks at {start:#x}"));
            }
            out.push(Carved { kind: CarveKind::Evtx, offset: start, size: 4096 + n * chunk, label: format!("{n} chunk(s), records {first_id}-{last_id}"), complete: true });
        }
    };
    for it in items {
        if it.kind != CarveKind::Evtx {
            flush(&mut run, &mut out);
            out.push(it);
            continue;
        }
        match &mut run {
            Some((start, n, _, last)) if *start + *n * chunk == it.offset => {
                *n += 1;
                *last = it.label.clone();
            }
            _ => {
                flush(&mut run, &mut out);
                run = Some((it.offset, 1, it.label.clone(), it.label.clone()));
            }
        }
    }
    flush(&mut run, &mut out);
    out.sort_by_key(|c| (c.offset, c.kind));
    out
}

/// Streams a carved item into `sink`: hives are re-read bin by bin (a truncated copy gets
/// its header patched), event log runs get a rebuilt file header, everything else is the
/// bytes as found. Returns the bytes written.
pub fn read(reader: &SharedReader, item: &Carved, sink: &mut dyn std::io::Write, mut progress: Option<&mut dyn FnMut(u64, u64)>) -> Result<u64> {
    let write = |sink: &mut dyn std::io::Write, b: &[u8]| sink.write_all(b).map_err(|e| Error::recorded(crate::extract::code::EXTRACT_WRITE, format!("{}: {e}", item.id())));
    match item.kind {
        CarveKind::Hive => {
            let window = bytes_at(reader, item.offset, blockcarve::hive::WINDOW);
            let header = blockcarve::hive::validate_base_block(&window).map_err(|e| Error::recorded(code::CARVE_READ, format!("{}: {e}", item.id())))?;
            let mut src = RangeSource { reader: reader.clone(), start: 0, len: reader.len(), label: item.id(), cancel: None, done: Arc::new(AtomicU64::new(0)) };
            let raw = blockcarve::hive::read_hive_raw(&mut src, item.offset, &header).map_err(|e| Error::recorded(code::CARVE_READ, format!("{}: {e}", item.id())))?;
            if !raw.complete {
                diag::info(code::CARVE_HIVE_TRUNCATED, format!("{}: {} of {} bytes", item.id(), raw.recovered_len, raw.declared_len));
            }
            write(sink, &raw.bytes)?;
            if let Some(p) = progress.as_deref_mut() {
                p(raw.bytes.len() as u64, raw.bytes.len() as u64);
            }
            Ok(raw.bytes.len() as u64)
        }
        CarveKind::Evtx => {
            let chunk = blockcarve::evtx::CHUNK_SIZE as u64;
            let n = item.size.saturating_sub(4096) / chunk;
            let mut header = [0u8; 4096];
            header[0..8].copy_from_slice(blockcarve::evtx::FILE_MAGIC);
            header[16..24].copy_from_slice(&n.saturating_sub(1).to_le_bytes());
            header[32..36].copy_from_slice(&128u32.to_le_bytes());
            header[36..38].copy_from_slice(&1u16.to_le_bytes());
            header[38..40].copy_from_slice(&3u16.to_le_bytes());
            header[40..42].copy_from_slice(&4096u16.to_le_bytes());
            header[42..44].copy_from_slice(&(n.min(65535) as u16).to_le_bytes());
            let crc = blockcarve::evtx::crc32_ieee(&header[0..120]);
            header[124..128].copy_from_slice(&crc.to_le_bytes());
            write(sink, &header)?;
            let mut done = 4096u64;
            for i in 0..n {
                let c = bytes_at(reader, item.offset + i * chunk, chunk as usize);
                if c.len() as u64 != chunk {
                    diag::warn(code::CARVE_READ, format!("{}: chunk {i} short", item.id()));
                    break;
                }
                write(sink, &c)?;
                done += chunk;
                if let Some(p) = progress.as_deref_mut() {
                    p(done, item.size);
                }
            }
            Ok(done)
        }
        _ => {
            let mut done = 0u64;
            while done < item.size {
                let want = FORWARD_STEP.min((item.size - done) as usize);
                let b = bytes_at(reader, item.offset + done, want);
                if b.is_empty() {
                    diag::warn(code::CARVE_READ, format!("{}: source ends after {done} of {} bytes", item.id(), item.size));
                    break;
                }
                write(sink, &b)?;
                done += b.len() as u64;
                if let Some(p) = progress.as_deref_mut() {
                    p(done, item.size);
                }
            }
            Ok(done)
        }
    }
}

/// Finds the item with `id` in a list.
pub fn find<'a>(items: &'a [Carved], id: &str) -> Result<&'a Carved> {
    let (kind, offset) = Carved::parse_id(id)?;
    items.iter().find(|c| c.kind == kind && c.offset == offset).ok_or_else(|| Error::new(code::CARVE_NOT_FOUND, id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() {
        diag::set_quiet(true);
        diag::drain();
    }

    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut chunk = |ty: &[u8], data: &[u8]| {
            v.extend_from_slice(&(data.len() as u32).to_be_bytes());
            v.extend_from_slice(ty);
            v.extend_from_slice(data);
            v.extend_from_slice(&[0, 0, 0, 0]);
        };
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&w.to_be_bytes());
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        chunk(b"IHDR", &ihdr);
        chunk(b"IDAT", &[7u8; 100]);
        chunk(b"IEND", &[]);
        v
    }

    fn jpeg() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        // APP0 with a fake embedded FFD9 that must not end the image.
        v.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x08, 0xFF, 0xD9, 0x00, 0x00, 0x00, 0x00]);
        // SOF0: len 17, precision 8, height 480, width 640, 3 components.
        v.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08, 0x01, 0xE0, 0x02, 0x80, 0x03, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
        // SOS: len 12.
        v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 3, 1, 0, 2, 0x11, 3, 0x11, 0, 0x3F, 0]);
        v.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    fn pdf() -> Vec<u8> {
        let mut v = b"%PDF-1.7\n1 0 obj<<>>endobj\nstartxref\n9\n%%EOF\n".to_vec();
        // An incremental update.
        v.extend_from_slice(b"2 0 obj<<>>endobj\nstartxref\n40\n%%EOF\n");
        v
    }

    fn zip() -> Vec<u8> {
        let name = b"word/document.xml";
        let mut v = Vec::new();
        v.extend_from_slice(b"PK\x03\x04");
        v.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&[0; 12]); // crc, sizes (stored, empty)
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(name);
        let cd_off = v.len() as u32;
        // Central directory header.
        v.extend_from_slice(b"PK\x01\x02");
        v.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&[0; 12]);
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&[0; 12]);
        v.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        v.extend_from_slice(name);
        let cd_size = v.len() as u32 - cd_off;
        v.extend_from_slice(b"PK\x05\x06");
        v.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        v.extend_from_slice(&cd_size.to_le_bytes());
        v.extend_from_slice(&cd_off.to_le_bytes());
        v.extend_from_slice(&3u16.to_le_bytes());
        v.extend_from_slice(b"abc");
        v
    }

    fn sqlite() -> Vec<u8> {
        let mut v = vec![0u8; 4096 * 3];
        v[..16].copy_from_slice(b"SQLite format 3\x00");
        v[16..18].copy_from_slice(&4096u16.to_be_bytes());
        v[18] = 1;
        v[19] = 1;
        v[21] = 64;
        v[22] = 32;
        v[23] = 32;
        v[24..28].copy_from_slice(&5u32.to_be_bytes());
        v[28..32].copy_from_slice(&3u32.to_be_bytes());
        v[92..96].copy_from_slice(&5u32.to_be_bytes());
        v
    }

    fn pe() -> Vec<u8> {
        let mut v = vec![0u8; 1024];
        v[0] = b'M';
        v[1] = b'Z';
        v[60..64].copy_from_slice(&128u32.to_le_bytes());
        let p = 128;
        v[p..p + 4].copy_from_slice(b"PE\0\0");
        v[p + 4..p + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        v[p + 6..p + 8].copy_from_slice(&2u16.to_le_bytes());
        v[p + 20..p + 22].copy_from_slice(&240u16.to_le_bytes());
        v[p + 22..p + 24].copy_from_slice(&0x2002u16.to_le_bytes()); // executable, DLL
        v[p + 24..p + 26].copy_from_slice(&0x20bu16.to_le_bytes());
        v[p + 24 + 60..p + 24 + 64].copy_from_slice(&512u32.to_le_bytes()); // size of headers
        let t = p + 24 + 240;
        // Section 1: raw 512..1024; section 2: raw 1024..3072.
        v[t + 16..t + 20].copy_from_slice(&512u32.to_le_bytes());
        v[t + 20..t + 24].copy_from_slice(&512u32.to_le_bytes());
        v[t + 40 + 16..t + 40 + 20].copy_from_slice(&2048u32.to_le_bytes());
        v[t + 40 + 20..t + 40 + 24].copy_from_slice(&1024u32.to_le_bytes());
        v.resize(3072, 0xAB);
        v
    }

    fn lnk() -> Vec<u8> {
        let mut v = vec![0u8; 76];
        v[0] = 0x4C;
        v[4..20].copy_from_slice(&[0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]);
        v[20..24].copy_from_slice(&(0x01u32 | 0x04 | 0x80).to_le_bytes()); // id list, name string, unicode
        v.extend_from_slice(&4u16.to_le_bytes()); // id list size
        v.extend_from_slice(&[1, 2, 3, 4]);
        v.extend_from_slice(&3u16.to_le_bytes()); // name: 3 UTF-16 units
        v.extend_from_slice(&[b'a', 0, b'b', 0, b'c', 0]);
        v.extend_from_slice(&12u32.to_le_bytes()); // one extra block of 12
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&0u32.to_le_bytes()); // terminal
        v
    }

    fn place(image: &mut Vec<u8>, at: usize, bytes: &[u8]) {
        if image.len() < at + bytes.len() {
            image.resize(at + bytes.len(), 0);
        }
        image[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn lab_image() -> (Vec<u8>, Vec<(CarveKind, usize, usize)>) {
        let mut img = vec![0u8; 4 << 20];
        let mut truth = Vec::new();
        let hive = blockcarve::hive::synthetic_hive("SYSTEM");
        place(&mut img, 0x1000, &hive);
        truth.push((CarveKind::Hive, 0x1000, hive.len()));
        let chunk = blockcarve::evtx::synthetic_chunk();
        place(&mut img, 0x40000, &chunk);
        place(&mut img, 0x50000, &chunk);
        truth.push((CarveKind::Evtx, 0x40000, 4096 + 2 * 65536));
        let p = png(16, 9);
        place(&mut img, 0x80000, &p);
        truth.push((CarveKind::Png, 0x80000, p.len()));
        let j = jpeg();
        place(&mut img, 0x90000, &j);
        truth.push((CarveKind::Jpeg, 0x90000, j.len()));
        let d = pdf();
        place(&mut img, 0xA0000, &d);
        truth.push((CarveKind::Pdf, 0xA0000, d.len()));
        let z = zip();
        place(&mut img, 0xB0000, &z);
        truth.push((CarveKind::Zip, 0xB0000, z.len()));
        let s = sqlite();
        place(&mut img, 0xC0000, &s);
        truth.push((CarveKind::Sqlite, 0xC0000, s.len()));
        let e = pe();
        place(&mut img, 0xE0000, &e);
        truth.push((CarveKind::Pe, 0xE0000, e.len()));
        let l = lnk();
        place(&mut img, 0xF0000, &l);
        truth.push((CarveKind::Lnk, 0xF0000, l.len()));
        // Decoys: an unaligned signature, a zip local header of an inner member with no
        // matching end record, a regf with an impossible version.
        place(&mut img, 0x100100, b"%PDF-1.4 junk");
        place(&mut img, 0x110000, b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00abc");
        let mut bad = blockcarve::hive::synthetic_hive("SAM");
        bad[0x14..0x18].copy_from_slice(&9u32.to_le_bytes());
        place(&mut img, 0x120000, &bad);
        (img, truth)
    }

    #[test]
    fn every_kind_is_found_once_with_its_exact_size() {
        quiet();
        let (img, truth) = lab_image();
        let reader = SharedReader::from_bytes(img);
        let mut prog = Vec::new();
        let (items, stats) = scan(&reader, &CarveOptions::default(), Some(&mut |a, b| prog.push((a, b))), None).unwrap();
        for it in &items {
            eprintln!("{}", it.describe());
        }
        assert_eq!(items.len(), truth.len(), "{items:?}");
        for (kind, off, size) in &truth {
            let it = items.iter().find(|c| c.kind == *kind && c.offset == *off as u64).unwrap_or_else(|| panic!("{kind:?} at {off:#x} missing"));
            assert_eq!(it.size as usize, *size, "{kind:?} size");
            assert!(it.complete, "{kind:?} complete");
        }
        assert_eq!(items.iter().find(|c| c.kind == CarveKind::Png).unwrap().label, "16x9");
        assert_eq!(items.iter().find(|c| c.kind == CarveKind::Jpeg).unwrap().label, "640x480");
        assert_eq!(items.iter().find(|c| c.kind == CarveKind::Zip).unwrap().label, "word/document.xml");
        assert_eq!(items.iter().find(|c| c.kind == CarveKind::Pe).unwrap().label, "x64 DLL 2 sections");
        assert!(items.iter().find(|c| c.kind == CarveKind::Hive).unwrap().label.starts_with("SYSTEM"));
        assert!(items.iter().find(|c| c.kind == CarveKind::Evtx).unwrap().label.starts_with("2 chunk(s)"));
        assert_eq!(prog.last(), Some(&(reader.len(), reader.len())));
        assert!(stats.bytes_read >= reader.len());
        assert!(diag::has(code::CARVE_FOUND) && diag::has(code::CARVE_STARTED));
        // Deterministic, also with one thread and with many.
        for threads in [1, 3, 8] {
            let (again, _) = scan(&reader, &CarveOptions { threads, ..Default::default() }, None, None).unwrap();
            assert_eq!(again, items, "{threads} threads");
        }
    }

    #[test]
    fn items_read_back_as_the_planted_bytes() {
        quiet();
        let (img, _) = lab_image();
        let reader = SharedReader::from_bytes(img.clone());
        let (items, _) = scan(&reader, &CarveOptions::default(), None, None).unwrap();
        for it in &items {
            let mut out = Vec::new();
            let n = read(&reader, it, &mut out, None).unwrap();
            assert_eq!(n as usize, out.len());
            match it.kind {
                CarveKind::Evtx => {
                    assert!(out.starts_with(b"ElfFile\0"));
                    assert_eq!(out.len(), 4096 + 2 * 65536);
                    assert!(out[4096..].starts_with(blockcarve::evtx::CHUNK_MAGIC));
                }
                CarveKind::Hive => {
                    assert!(out.starts_with(b"regf"));
                    assert_eq!(out.len() as u64, it.size);
                }
                _ => assert_eq!(out, img[it.offset as usize..(it.offset + it.size) as usize].to_vec(), "{}", it.id()),
            }
            let id = it.id();
            assert_eq!(find(&items, &id).unwrap(), it);
            assert!(it.file_name().ends_with(it.kind.extension()));
            let (k, o) = Carved::parse_id(&id).unwrap();
            assert_eq!((k, o), (it.kind, it.offset));
        }
        assert_eq!(find(&items, "pdf_999").unwrap_err().code, code::CARVE_NOT_FOUND);
        assert_eq!(Carved::parse_id("nothing").unwrap_err().code, code::CARVE_INVALID_ID);
        assert_eq!(Carved::parse_id("gif_10").unwrap_err().code, code::CARVE_INVALID_ID);
    }

    #[test]
    fn kinds_filter_and_parse() {
        quiet();
        let (img, _) = lab_image();
        let reader = SharedReader::from_bytes(img);
        let opts = CarveOptions { kinds: vec![CarveKind::Png, CarveKind::Jpeg], ..Default::default() };
        let (items, _) = scan(&reader, &opts, None, None).unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|c| matches!(c.kind, CarveKind::Png | CarveKind::Jpeg)));
        assert_eq!(parse_kinds("png, JPG,hive").unwrap(), vec![CarveKind::Hive, CarveKind::Jpeg, CarveKind::Png]);
        assert_eq!(parse_kinds("all").unwrap().len(), CarveKind::ALL.len());
        assert_eq!(parse_kinds("gif").unwrap_err().code, code::CARVE_KIND_UNKNOWN);
        assert_eq!(parse_kinds(" , ").unwrap_err().code, code::CARVE_NO_KINDS);
        assert_eq!(CarveKind::parse("dll"), Some(CarveKind::Pe));
        assert_eq!(CarveKind::parse("registry"), Some(CarveKind::Hive));
        for k in CarveKind::ALL {
            assert_eq!(CarveKind::parse(k.name()), Some(k));
            assert!(!k.describe().is_empty() && !k.signatures().is_empty());
        }
    }

    #[test]
    fn cancel_stops_the_scan_and_empty_is_refused() {
        quiet();
        let reader = SharedReader::from_bytes(vec![0u8; 8 << 20]);
        let cancel = Arc::new(AtomicBool::new(true));
        let (items, stats) = scan(&reader, &CarveOptions::default(), None, Some(cancel)).unwrap();
        assert!(items.is_empty());
        assert!(stats.cancelled);
        assert!(diag::has(code::CARVE_CANCELLED));
        assert_eq!(scan(&SharedReader::from_bytes(Vec::new()), &CarveOptions::default(), None, None).unwrap_err().code, code::CARVE_EMPTY);
        assert_eq!(scan(&reader, &CarveOptions { kinds: Vec::new(), ..Default::default() }, None, None).unwrap_err().code, code::CARVE_NO_KINDS);
    }

    #[test]
    fn oversize_items_are_cut_and_marked() {
        quiet();
        let mut s = sqlite();
        s[28..32].copy_from_slice(&1_000_000u32.to_be_bytes());
        let mut img = vec![0u8; 1 << 20];
        place(&mut img, 0x2000, &s);
        let reader = SharedReader::from_bytes(img);
        let (items, _) = scan(&reader, &CarveOptions { kinds: vec![CarveKind::Sqlite], max_size: 1 << 16, ..Default::default() }, None, None).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].size, 1 << 16);
        assert!(!items[0].complete);
    }

    #[test]
    fn png_without_iend_is_incomplete_and_truncated_structures_are_dropped() {
        quiet();
        let mut p = png(2, 2);
        p.truncate(p.len() - 12); // no IEND
        let mut img = vec![0u8; 1 << 20];
        place(&mut img, 0x4000, &p);
        place(&mut img, 0x8000, &jpeg()[..20]); // cut before SOS
        let reader = SharedReader::from_bytes(img);
        let (items, _) = scan(&reader, &CarveOptions { kinds: vec![CarveKind::Png, CarveKind::Jpeg], ..Default::default() }, None, None).unwrap();
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(items[0].kind, CarveKind::Png);
        assert!(!items[0].complete);
    }
}
