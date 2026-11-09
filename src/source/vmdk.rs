//! VMDK reader: a VMware virtual disk as `Read + Seek`.
//!
//! Supports monolithic sparse, monolithic flat, split sparse (`-s001.vmdk`...), split flat
//! (`-flat.vmdk`), `ZERO` extents and streamOptimized (compressed grains, grain directory in
//! the footer). Snapshot deltas (a descriptor with `parentFileNameHint`) are refused: the
//! base disk must be given, or the chain merged. Ported from faramir / masstin.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;

use crate::diag;
use crate::error::{Error, Result};

pub mod code {
    crate::codes! {
        VMDK_OPEN = 150, "the VMDK file could not be opened; check the path and permissions";
        VMDK_READ_HEADER = 151, "the first bytes of the VMDK could not be read; the file is empty or unreadable";
        VMDK_EXTENT_MISSING = 152, "the descriptor names an extent file that is not next to it; only the descriptor was collected, the data file (-flat.vmdk, -sNNN.vmdk) is needed";
        VMDK_EXTENT_FILEPART = 153, "the extent file was found only as an incomplete upload (<name>.filepart) and was used as it is; the disk is incomplete past the uploaded bytes";
        VMDK_EXTENT_TYPE = 154, "the descriptor has an extent of a type this reader does not know (not FLAT, VMFS, SPARSE, VMFSSPARSE or ZERO)";
        VMDK_NO_EXTENTS = 155, "the descriptor has no RW/RDONLY/NOACCESS extent lines; it is not a VMDK descriptor or it is truncated";
        VMDK_EXTENT_LINE = 156, "an extent line of the descriptor is malformed (not 'ACCESS SECTORS TYPE \"FILE\" [OFFSET]'); the descriptor is damaged";
        VMDK_SPARSE_MAGIC = 157, "a sparse extent has no KDMV magic; the file named as SPARSE is not one";
        VMDK_SPARSE_DAMAGED = 158, "a sparse extent header has values VMware never writes (grain size, table size or capacity); the header is damaged";
        VMDK_GD_AT_END_UNCOMPRESSED = 159, "the grain directory is marked as 'at end of file' but the extent is not streamOptimized; an unsupported layout";
        VMDK_FOOTER_MISSING = 160, "a streamOptimized VMDK has no valid footer; it was truncated during export or upload, the bytes beyond what was written cannot be read";
        VMDK_GD_DOES_NOT_FIT = 161, "the grain directory would lie beyond the end of the extent file; the extent is truncated or damaged";
        VMDK_GRAIN_READ = 162, "a grain could not be read or decompressed; that grain reads as zeros, the extent is damaged there";
        VMDK_HAS_PARENT = 163, "the VMDK is a snapshot delta (parentFileNameHint / parentCID set); give the base disk or merge the snapshot chain first (vmware-vdiskmanager -r, qemu-img convert)";
        VMDK_RAW_FALLBACK = 164, "the file has neither a sparse header nor a descriptor; it was read as a flat extent of its own size";
    }
}

const SECTOR_SIZE: u64 = 512;
const SPARSE_MAGIC: u32 = 0x564D_444B; // "KDMV"
const GD_AT_END: u64 = 0xFFFF_FFFF_FFFF_FFFF;

#[derive(Debug, Clone)]
struct SparseHeader {
    capacity: u64,
    grain_size: u64,
    num_gte_per_gt: u32,
    gd_offset: u64,
    compressed: bool,
}

enum ExtentData {
    Zero,
    Flat { file: File, file_offset: u64 },
    Sparse { file: File, header: SparseHeader, grain_directory: Vec<u32>, grain_table_cache: HashMap<u32, Vec<u32>>, grain_data_cache: HashMap<u64, Vec<u8>> },
}

struct Extent {
    data: ExtentData,
    size_bytes: u64,
    path: PathBuf,
}

/// A VMDK as `Read + Seek`.
pub struct VmdkReader {
    extents: Vec<Extent>,
    total_size: u64,
    position: u64,
}

/// `ACCESS SECTORS TYPE "FILENAME" [OFFSET]`, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentLine {
    pub sectors: u64,
    pub extent_type: String,
    pub filename: String,
    pub flat_offset: u64,
}

impl VmdkReader {
    /// Opens a VMDK (descriptor, monolithic sparse or flat).
    pub fn open(path: &Path) -> Result<Self> {
        let shown = path.display().to_string();
        let base_dir = path.parent().unwrap_or(Path::new("."));
        let mut file = File::open(path).map_err(|e| Error::recorded(code::VMDK_OPEN, format!("{shown}: {e}")))?;
        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf).map_err(|e| Error::recorded(code::VMDK_READ_HEADER, format!("{shown}: {e}")))?;
        let magic = u32::from_le_bytes(magic_buf);
        if magic == SPARSE_MAGIC {
            drop(file);
            let extent = Self::open_sparse_extent(path)?;
            let size = extent.size_bytes;
            return Ok(VmdkReader { extents: vec![extent], total_size: size, position: 0 });
        }
        file.seek(SeekFrom::Start(0)).map_err(|e| Error::recorded(code::VMDK_READ_HEADER, format!("{shown}: {e}")))?;
        let mut buf = vec![0u8; 65536];
        let n = file.read(&mut buf).map_err(|e| Error::recorded(code::VMDK_READ_HEADER, format!("{shown}: {e}")))?;
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        if text.contains("# Disk DescriptorFile") || text.contains("createType") {
            Self::open_from_descriptor(&text, base_dir, &shown)
        } else {
            drop(file);
            let file = File::open(path).map_err(|e| Error::recorded(code::VMDK_OPEN, format!("{shown}: {e}")))?;
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            diag::info(code::VMDK_RAW_FALLBACK, format!("{shown}: {size} bytes"));
            Ok(VmdkReader { extents: vec![Extent { data: ExtentData::Flat { file, file_offset: 0 }, size_bytes: size, path: path.to_path_buf() }], total_size: size, position: 0 })
        }
    }

    /// Virtual size of the disk.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// The files the extents come from (ZERO extents have none).
    pub fn extent_files(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        for e in &self.extents {
            if !matches!(e.data, ExtentData::Zero) && !out.contains(&e.path) {
                out.push(e.path.clone());
            }
        }
        out
    }

    /// Declared virtual size without opening extents (descriptor files are about 1 KB).
    pub fn probe_size(path: &Path) -> Option<u64> {
        let mut file = File::open(path).ok()?;
        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf).ok()?;
        if u32::from_le_bytes(magic_buf) == SPARSE_MAGIC {
            file.seek(SeekFrom::Start(0)).ok()?;
            let h = Self::read_sparse_header_at_current(&mut file, &path.display().to_string()).ok()?;
            return Some(h.capacity * SECTOR_SIZE);
        }
        file.seek(SeekFrom::Start(0)).ok()?;
        let mut buf = vec![0u8; 65536];
        let n = file.read(&mut buf).ok()?;
        let text = String::from_utf8_lossy(&buf[..n]);
        if !text.contains("# Disk DescriptorFile") && !text.contains("createType") {
            return None;
        }
        let mut total_sectors: u64 = 0;
        for line in text.lines() {
            if let Ok(parts) = parse_extent_line(line.trim()) {
                total_sectors = total_sectors.saturating_add(parts.sectors);
            }
        }
        if total_sectors == 0 {
            None
        } else {
            Some(total_sectors * SECTOR_SIZE)
        }
    }

    fn open_from_descriptor(descriptor: &str, base_dir: &Path, shown: &str) -> Result<Self> {
        if descriptor_has_parent(descriptor) {
            return Err(Error::recorded(code::VMDK_HAS_PARENT, shown.to_string()));
        }
        let mut extents = Vec::new();
        let mut total_size: u64 = 0;
        for line in descriptor.lines() {
            let line = line.trim();
            if !is_extent_line(line) {
                continue;
            }
            let parts = parse_extent_line(line).map_err(|m| Error::recorded(code::VMDK_EXTENT_LINE, format!("{shown}: {m}")))?;
            let extent_path = base_dir.join(&parts.filename);
            let extent = match parts.extent_type.to_uppercase().as_str() {
                "FLAT" | "VMFS" | "VMFSRAW" | "VMFSRDM" => {
                    let f = match File::open(&extent_path) {
                        Ok(f) => f,
                        Err(_) => {
                            // Incomplete SFTP uploads leave the data file as <name>.filepart.
                            let filepart = PathBuf::from(format!("{}.filepart", extent_path.display()));
                            match File::open(&filepart) {
                                Ok(f) => {
                                    diag::warn(code::VMDK_EXTENT_FILEPART, format!("{shown}: {}", filepart.display()));
                                    f
                                }
                                Err(_) => return Err(Error::recorded(code::VMDK_EXTENT_MISSING, format!("{shown}: {}", parts.filename))),
                            }
                        }
                    };
                    Extent { data: ExtentData::Flat { file: f, file_offset: parts.flat_offset * SECTOR_SIZE }, size_bytes: parts.sectors * SECTOR_SIZE, path: extent_path }
                }
                "SPARSE" | "VMFSSPARSE" => Self::open_sparse_extent(&extent_path)?,
                "ZERO" => Extent { data: ExtentData::Zero, size_bytes: parts.sectors * SECTOR_SIZE, path: PathBuf::new() },
                other => return Err(Error::recorded(code::VMDK_EXTENT_TYPE, format!("{shown}: {other}"))),
            };
            total_size += extent.size_bytes;
            extents.push(extent);
        }
        if extents.is_empty() {
            return Err(Error::recorded(code::VMDK_NO_EXTENTS, shown.to_string()));
        }
        Ok(VmdkReader { extents, total_size, position: 0 })
    }

    fn open_sparse_extent(path: &Path) -> Result<Extent> {
        let shown = path.display().to_string();
        let mut file = File::open(path).map_err(|e| Error::recorded(code::VMDK_EXTENT_MISSING, format!("{shown}: {e}")))?;
        file.seek(SeekFrom::Start(0)).map_err(|e| Error::recorded(code::VMDK_READ_HEADER, format!("{shown}: {e}")))?;
        let mut header = Self::read_sparse_header_at_current(&mut file, &shown)?;

        if header.gd_offset == GD_AT_END || header.gd_offset == 0 {
            if !header.compressed && header.capacity > 0 {
                return Err(Error::recorded(code::VMDK_GD_AT_END_UNCOMPRESSED, shown));
            }
            let file_size = file.seek(SeekFrom::End(0)).map_err(|e| Error::recorded(code::VMDK_READ_HEADER, format!("{shown}: {e}")))?;
            let declared_bytes = header.capacity.saturating_mul(SECTOR_SIZE);
            let mut footer_header = None;
            for offset_from_end in &[1024u64, 1536, 2048, 512] {
                let pos = file_size.saturating_sub(*offset_from_end);
                if file.seek(SeekFrom::Start(pos)).is_err() {
                    continue;
                }
                if let Ok(h) = Self::read_sparse_header_at_current(&mut file, &shown) {
                    if h.gd_offset != GD_AT_END && h.gd_offset != 0 && h.capacity > 0 {
                        footer_header = Some(h);
                        break;
                    }
                }
            }
            let footer_header = footer_header.ok_or_else(|| {
                let gb = |b: u64| b as f64 / 1_073_741_824.0;
                Error::recorded(code::VMDK_FOOTER_MISSING, format!("{shown}: declared {:.2} GB, {:.2} GB on disk", gb(declared_bytes), gb(file_size)))
            })?;
            header.gd_offset = footer_header.gd_offset;
        }

        let num_gd_entries = Self::gd_entry_count(&header);
        let gd_byte_offset = header.gd_offset.saturating_mul(SECTOR_SIZE);
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if (num_gd_entries as u64).saturating_mul(4) > file_len || gd_byte_offset >= file_len {
            return Err(Error::recorded(code::VMDK_GD_DOES_NOT_FIT, format!("{shown}: {num_gd_entries} entries at byte {gd_byte_offset} in a {file_len}-byte file")));
        }
        file.seek(SeekFrom::Start(gd_byte_offset)).map_err(|e| Error::recorded(code::VMDK_GD_DOES_NOT_FIT, format!("{shown}: {e}")))?;
        let mut gd_buf = vec![0u8; num_gd_entries * 4];
        file.read_exact(&mut gd_buf).map_err(|e| Error::recorded(code::VMDK_GD_DOES_NOT_FIT, format!("{shown}: {e}")))?;
        let grain_directory: Vec<u32> = gd_buf.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        let size_bytes = header.capacity * SECTOR_SIZE;
        Ok(Extent { data: ExtentData::Sparse { file, header, grain_directory, grain_table_cache: HashMap::new(), grain_data_cache: HashMap::new() }, size_bytes, path: path.to_path_buf() })
    }

    fn read_sparse_header_at_current(file: &mut File, shown: &str) -> Result<SparseHeader> {
        let mut buf = [0u8; 72];
        file.read_exact(&mut buf).map_err(|e| Error::new(code::VMDK_READ_HEADER, format!("{shown}: {e}")))?;
        if u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) != SPARSE_MAGIC {
            return Err(Error::new(code::VMDK_SPARSE_MAGIC, shown.to_string()));
        }
        let flags = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let capacity = u64::from_le_bytes(buf[12..20].try_into().expect("8 bytes"));
        let grain_size = u64::from_le_bytes(buf[20..28].try_into().expect("8 bytes"));
        let num_gte_per_gt = u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]);
        let gd_offset = u64::from_le_bytes(buf[56..64].try_into().expect("8 bytes"));
        let compressed = (flags & 0x10000) != 0;
        // VMware writes grainSize 128 and numGTEsPerGT 512; far-off values are damage.
        if grain_size == 0 || !grain_size.is_power_of_two() || grain_size > 2048 {
            return Err(Error::recorded(code::VMDK_SPARSE_DAMAGED, format!("{shown}: grainSize {grain_size}")));
        }
        if num_gte_per_gt == 0 || num_gte_per_gt > 65536 {
            return Err(Error::recorded(code::VMDK_SPARSE_DAMAGED, format!("{shown}: numGTEsPerGT {num_gte_per_gt}")));
        }
        if capacity.checked_mul(SECTOR_SIZE).is_none() {
            return Err(Error::recorded(code::VMDK_SPARSE_DAMAGED, format!("{shown}: capacity {capacity} sectors")));
        }
        Ok(SparseHeader { capacity, grain_size, num_gte_per_gt, gd_offset, compressed })
    }

    fn gd_entry_count(header: &SparseHeader) -> usize {
        let sectors_per_gt = header.num_gte_per_gt as u64 * header.grain_size;
        if sectors_per_gt == 0 {
            return 0;
        }
        header.capacity.div_ceil(sectors_per_gt) as usize
    }

    fn find_extent(&self, global_offset: u64) -> Option<(usize, u64)> {
        let mut cumulative: u64 = 0;
        for (i, ext) in self.extents.iter().enumerate() {
            if global_offset < cumulative + ext.size_bytes {
                return Some((i, global_offset - cumulative));
            }
            cumulative += ext.size_bytes;
        }
        None
    }

    fn read_flat(file: &mut File, file_offset: u64, local_offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        file.seek(SeekFrom::Start(file_offset + local_offset))?;
        let n = file.read(buf)?;
        if n == 0 && !buf.is_empty() {
            // Shorter than declared: zeros, not EOF.
            buf.fill(0);
            return Ok(buf.len());
        }
        Ok(n)
    }

    #[allow(clippy::too_many_arguments)]
    fn read_sparse(file: &mut File, header: &SparseHeader, grain_directory: &[u32], grain_table_cache: &mut HashMap<u32, Vec<u32>>, grain_data_cache: &mut HashMap<u64, Vec<u8>>, local_offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let grain_bytes = header.grain_size * SECTOR_SIZE;
        let extent_size = header.capacity * SECTOR_SIZE;
        if local_offset >= extent_size {
            return Ok(0);
        }
        let gte_per_gt = header.num_gte_per_gt as u64;
        let grain_index = (local_offset / SECTOR_SIZE) / header.grain_size;
        let gd_index = (grain_index / gte_per_gt) as usize;
        let gt_index = (grain_index % gte_per_gt) as usize;
        let offset_in_grain = local_offset % grain_bytes;
        let max_read = buf.len().min((grain_bytes - offset_in_grain) as usize).min((extent_size - local_offset) as usize);

        if gd_index >= grain_directory.len() {
            buf[..max_read].fill(0);
            return Ok(max_read);
        }
        let gd_entry = grain_directory[gd_index];
        if gd_entry == 0 || gd_entry == 1 {
            buf[..max_read].fill(0);
            return Ok(max_read);
        }
        let gt = Self::load_grain_table(file, grain_table_cache, gd_entry, gte_per_gt as usize)?;
        if gt_index >= gt.len() {
            buf[..max_read].fill(0);
            return Ok(max_read);
        }
        let gt_entry = gt[gt_index];
        if gt_entry == 0 || gt_entry == 1 {
            buf[..max_read].fill(0);
            return Ok(max_read);
        }

        if header.compressed {
            if let Some(cached) = grain_data_cache.get(&grain_index) {
                let start = offset_in_grain as usize;
                let end = (start + max_read).min(cached.len());
                if start < cached.len() {
                    buf[..end - start].copy_from_slice(&cached[start..end]);
                    return Ok(end - start);
                }
                buf[..max_read].fill(0);
                return Ok(max_read);
            }
            // marker: { lba: u64, size: u32, data }
            file.seek(SeekFrom::Start(gt_entry as u64 * SECTOR_SIZE))?;
            let mut marker_buf = [0u8; 12];
            file.read_exact(&mut marker_buf)?;
            let compressed_size = u32::from_le_bytes(marker_buf[8..12].try_into().expect("4 bytes"));
            if compressed_size == 0 || compressed_size > 10_000_000 {
                diag::warn(code::VMDK_GRAIN_READ, format!("grain {grain_index}: compressed size {compressed_size}"));
                buf[..max_read].fill(0);
                return Ok(max_read);
            }
            let mut compressed_data = vec![0u8; compressed_size as usize];
            file.read_exact(&mut compressed_data)?;
            let mut decoder = ZlibDecoder::new(&compressed_data[..]);
            let mut decompressed = vec![0u8; grain_bytes as usize];
            let mut got = 0usize;
            loop {
                match decoder.read(&mut decompressed[got..]) {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(e) => {
                        diag::warn(code::VMDK_GRAIN_READ, format!("grain {grain_index}: {e}"));
                        break;
                    }
                }
                if got >= decompressed.len() {
                    break;
                }
            }
            decompressed.truncate(got);
            let start = offset_in_grain as usize;
            let end = (start + max_read).min(decompressed.len());
            if start < decompressed.len() {
                buf[..end - start].copy_from_slice(&decompressed[start..end]);
            } else {
                buf[..max_read].fill(0);
            }
            if grain_data_cache.len() > 1024 {
                grain_data_cache.clear();
            }
            let result = if start < got { end - start } else { max_read };
            grain_data_cache.insert(grain_index, decompressed);
            Ok(result)
        } else {
            file.seek(SeekFrom::Start(gt_entry as u64 * SECTOR_SIZE + offset_in_grain))?;
            Self::read_flat(file, gt_entry as u64 * SECTOR_SIZE, offset_in_grain, &mut buf[..max_read])
        }
    }

    fn load_grain_table(file: &mut File, cache: &mut HashMap<u32, Vec<u32>>, gd_entry: u32, num_entries: usize) -> io::Result<Vec<u32>> {
        if let Some(gt) = cache.get(&gd_entry) {
            return Ok(gt.clone());
        }
        file.seek(SeekFrom::Start(gd_entry as u64 * SECTOR_SIZE))?;
        let mut raw = vec![0u8; num_entries * 4];
        file.read_exact(&mut raw)?;
        let gt: Vec<u32> = raw.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        cache.insert(gd_entry, gt.clone());
        Ok(gt)
    }
}

fn is_extent_line(line: &str) -> bool {
    line.starts_with("RW ") || line.starts_with("RDONLY ") || line.starts_with("NOACCESS ")
}

/// Does the descriptor describe a snapshot delta?
pub fn descriptor_has_parent(descriptor: &str) -> bool {
    for line in descriptor.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        if l.starts_with("parentFileNameHint") {
            return true;
        }
        if let Some(v) = l.strip_prefix("parentCID") {
            let v = v.trim_start_matches(|c: char| c == '=' || c.is_whitespace()).trim();
            if !v.eq_ignore_ascii_case("ffffffff") && !v.is_empty() {
                return true;
            }
        }
    }
    false
}

/// `ACCESS SECTORS TYPE "FILENAME" [OFFSET]`.
pub fn parse_extent_line(line: &str) -> std::result::Result<ExtentLine, String> {
    if !is_extent_line(line) {
        return Err(format!("not an extent line: {line}"));
    }
    let mut chars = line.chars().peekable();
    let mut tokens: Vec<String> = Vec::new();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        if chars.peek() == Some(&'"') {
            chars.next();
            let mut tok = String::new();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                tok.push(c);
            }
            tokens.push(tok);
        } else {
            let mut tok = String::new();
            while chars.peek().is_some_and(|c| !c.is_whitespace()) {
                tok.push(chars.next().expect("peeked"));
            }
            tokens.push(tok);
        }
    }
    let is_zero = tokens.get(2).is_some_and(|t| t.eq_ignore_ascii_case("ZERO"));
    if tokens.len() < 4 && !(is_zero && tokens.len() == 3) {
        return Err(format!("malformed extent line: {line}"));
    }
    let sectors: u64 = tokens[1].parse().map_err(|_| format!("invalid sector count in extent line: {line}"))?;
    if sectors.checked_mul(SECTOR_SIZE).is_none() {
        return Err(format!("sector count out of range in extent line: {line}"));
    }
    Ok(ExtentLine { sectors, extent_type: tokens[2].clone(), filename: tokens.get(3).cloned().unwrap_or_default(), flat_offset: if tokens.len() > 4 { tokens[4].parse().unwrap_or(0) } else { 0 } })
}

impl Read for VmdkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_size {
            return Ok(0);
        }
        let Some((ext_idx, local_offset)) = self.find_extent(self.position) else { return Ok(0) };
        let extent = &mut self.extents[ext_idx];
        let read_len = buf.len().min((extent.size_bytes - local_offset) as usize);
        let n = match &mut extent.data {
            ExtentData::Zero => {
                buf[..read_len].fill(0);
                read_len
            }
            ExtentData::Flat { file, file_offset } => {
                let fo = *file_offset;
                Self::read_flat(file, fo, local_offset, &mut buf[..read_len])?
            }
            ExtentData::Sparse { file, header, grain_directory, grain_table_cache, grain_data_cache } => Self::read_sparse(file, header, grain_directory, grain_table_cache, grain_data_cache, local_offset, &mut buf[..read_len])?,
        };
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for VmdkReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::End(offset) => self.total_size as i64 + offset,
            SeekFrom::Current(offset) => self.position as i64 + offset,
        };
        if new_pos < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek to a negative position"));
        }
        self.position = new_pos as u64;
        Ok(self.position)
    }
}

impl std::fmt::Debug for VmdkReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VmdkReader({} extents, {} bytes)", self.extents.len(), self.total_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("evidencefs-vmdk-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sparse_vmdk(dir: &Path, name: &str, capacity: u64, grain: u64, gtes: u32) -> PathBuf {
        let mut img = vec![0u8; 65536];
        img[0..4].copy_from_slice(&SPARSE_MAGIC.to_le_bytes());
        img[4..8].copy_from_slice(&1u32.to_le_bytes());
        img[12..20].copy_from_slice(&capacity.to_le_bytes());
        img[20..28].copy_from_slice(&grain.to_le_bytes());
        img[44..48].copy_from_slice(&gtes.to_le_bytes());
        img[56..64].copy_from_slice(&1u64.to_le_bytes());
        let p = dir.join(name);
        std::fs::write(&p, img).unwrap();
        p
    }

    #[test]
    fn damaged_sparse_headers_are_refused_not_trusted() {
        crate::diag::set_quiet(true);
        let d = tmpdir("damaged");
        let p = sparse_vmdk(&d, "zero-gte.vmdk", 2048, 128, 0);
        assert_eq!(VmdkReader::open(&p).unwrap_err().code, code::VMDK_SPARSE_DAMAGED);
        let p2 = sparse_vmdk(&d, "huge.vmdk", 1u64 << 41, 1, 1);
        let c = VmdkReader::open(&p2).unwrap_err().code;
        assert!(c == code::VMDK_SPARSE_DAMAGED || c == code::VMDK_GD_DOES_NOT_FIT, "{c}");
        let p4 = sparse_vmdk(&d, "overflow.vmdk", u64::MAX / 256, 128, 512);
        assert_eq!(VmdkReader::open(&p4).unwrap_err().code, code::VMDK_SPARSE_DAMAGED);
        let p3 = sparse_vmdk(&d, "sane.vmdk", 2048, 128, 512);
        let r = VmdkReader::open(&p3).unwrap();
        assert_eq!(r.total_size(), 2048 * 512);
        assert_eq!(r.extent_files(), vec![p3.clone()]);
        assert_eq!(VmdkReader::probe_size(&p3), Some(2048 * 512));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn sparse_with_unallocated_grains_reads_zeros() {
        crate::diag::set_quiet(true);
        let d = tmpdir("zeros");
        let p = sparse_vmdk(&d, "empty.vmdk", 2048, 128, 512);
        let mut r = VmdkReader::open(&p).unwrap();
        let mut b = [7u8; 1024];
        r.seek(SeekFrom::Start(100_000)).unwrap();
        let n = r.read(&mut b).unwrap();
        assert!(n > 0);
        assert!(b[..n].iter().all(|x| *x == 0));
        r.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(r.read(&mut b).unwrap(), 0);
        assert!(r.seek(SeekFrom::Current(-10_000_000)).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn extent_lines() {
        let parts = parse_extent_line("RW 2048 ZERO").unwrap();
        assert_eq!(parts.extent_type, "ZERO");
        assert!(parts.filename.is_empty());
        let parts = parse_extent_line(r#"RW 41943040 FLAT "my disk-flat.vmdk" 0"#).unwrap();
        assert_eq!(parts, ExtentLine { sectors: 41943040, extent_type: "FLAT".into(), filename: "my disk-flat.vmdk".into(), flat_offset: 0 });
        assert!(parse_extent_line("RW abc FLAT \"x\"").is_err());
        assert!(parse_extent_line("RW 1").is_err());
        assert!(parse_extent_line("ddb.adapterType = \"lsilogic\"").is_err());
        assert!(parse_extent_line("RW 99999999999999999999 FLAT \"x\"").is_err());
    }

    #[test]
    fn descriptor_with_flat_extent_and_parent_detection() {
        crate::diag::set_quiet(true);
        let d = tmpdir("desc");
        std::fs::write(d.join("disk-flat.vmdk"), [3u8; 2048]).unwrap();
        let desc = "# Disk DescriptorFile\nversion=1\nCID=abcdef01\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\n\n# Extent description\nRW 4 FLAT \"disk-flat.vmdk\" 0\nRW 4 ZERO\n\nddb.adapterType = \"lsilogic\"\n";
        std::fs::write(d.join("disk.vmdk"), desc).unwrap();
        let mut r = VmdkReader::open(&d.join("disk.vmdk")).unwrap();
        assert_eq!(r.total_size(), 8 * 512);
        assert_eq!(VmdkReader::probe_size(&d.join("disk.vmdk")), Some(8 * 512));
        assert_eq!(r.extent_files(), vec![d.join("disk-flat.vmdk")]);
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all.len(), 4096);
        assert!(all[..2048].iter().all(|b| *b == 3));
        assert!(all[2048..].iter().all(|b| *b == 0));
        // Missing extent.
        let desc2 = desc.replace("disk-flat.vmdk", "gone-flat.vmdk");
        std::fs::write(d.join("disk2.vmdk"), &desc2).unwrap();
        assert_eq!(VmdkReader::open(&d.join("disk2.vmdk")).unwrap_err().code, code::VMDK_EXTENT_MISSING);
        // Filepart fallback.
        std::fs::write(d.join("gone-flat.vmdk.filepart"), [4u8; 2048]).unwrap();
        crate::diag::drain();
        assert!(VmdkReader::open(&d.join("disk2.vmdk")).is_ok());
        assert!(crate::diag::has(code::VMDK_EXTENT_FILEPART));
        // Snapshot delta.
        let delta = desc.replace("parentCID=ffffffff", "parentCID=12345678\nparentFileNameHint=\"base.vmdk\"");
        std::fs::write(d.join("delta.vmdk"), &delta).unwrap();
        assert_eq!(VmdkReader::open(&d.join("delta.vmdk")).unwrap_err().code, code::VMDK_HAS_PARENT);
        assert!(descriptor_has_parent(&delta));
        assert!(!descriptor_has_parent(desc));
        // Unknown extent type and no extents.
        std::fs::write(d.join("odd.vmdk"), "# Disk DescriptorFile\nRW 4 WEIRD \"x\"\n").unwrap();
        assert_eq!(VmdkReader::open(&d.join("odd.vmdk")).unwrap_err().code, code::VMDK_EXTENT_TYPE);
        std::fs::write(d.join("none.vmdk"), "# Disk DescriptorFile\ncreateType=\"monolithicFlat\"\n").unwrap();
        assert_eq!(VmdkReader::open(&d.join("none.vmdk")).unwrap_err().code, code::VMDK_NO_EXTENTS);
        std::fs::write(d.join("bad.vmdk"), "# Disk DescriptorFile\nRW abc FLAT \"x\"\n").unwrap();
        assert_eq!(VmdkReader::open(&d.join("bad.vmdk")).unwrap_err().code, code::VMDK_EXTENT_LINE);
        // Neither header nor descriptor: raw fallback.
        std::fs::write(d.join("raw.vmdk"), [1u8; 1024]).unwrap();
        crate::diag::drain();
        let r = VmdkReader::open(&d.join("raw.vmdk")).unwrap();
        assert_eq!(r.total_size(), 1024);
        assert!(crate::diag::has(code::VMDK_RAW_FALLBACK));
        assert_eq!(VmdkReader::probe_size(&d.join("raw.vmdk")), None);
        assert_eq!(VmdkReader::open(&d.join("missing.vmdk")).unwrap_err().code, code::VMDK_OPEN);
        std::fs::write(d.join("empty.vmdk"), b"").unwrap();
        assert_eq!(VmdkReader::open(&d.join("empty.vmdk")).unwrap_err().code, code::VMDK_READ_HEADER);
        crate::diag::drain();
        std::fs::remove_dir_all(&d).ok();
    }
}
