//! Microsoft virtual disks: VHD (fixed and dynamic) and VHDX (fixed and dynamic), as
//! `Read + Seek`. Ported from faramir, which ported it from masstin.
//!
//! VHD ("conectix"): the last 512 bytes are the footer with the disk type and the
//! virtual size. A fixed VHD is the raw disk followed by that footer. A dynamic VHD keeps
//! a "cxsparse" header pointing at a block allocation table (BAT) of big-endian sector
//! numbers, one per block; each allocated block starts with a sector bitmap whose clear
//! bits read as zeros. Differencing disks (a parent chain) are refused.
//!
//! VHDX ("vhdxfile"): region tables at 192 KB and 256 KB name the BAT and the metadata
//! regions; the metadata carries block size, logical sector size and virtual size. The BAT
//! is little-endian u64 entries, state in the low 3 bits, file offset in the upper 44;
//! after every `chunk_ratio` payload entries comes one sector-bitmap entry. Differencing
//! disks are refused and the VHDX log is not applied (a cleanly detached disk has an
//! empty log).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::diag;
use crate::error::{Error, Result};

pub mod code {
    crate::codes! {
        VHD_OPEN = 100, "the VHD file could not be opened; check the path and permissions";
        VHD_TOO_SMALL = 101, "the file is smaller than a VHD footer (512 bytes); it is not a VHD or it is truncated";
        VHD_NO_FOOTER = 102, "no 'conectix' footer at the end nor at the start of the file; the file is not a VHD or its last sector is missing";
        VHD_FOOTER_FROM_START = 103, "the footer at the end was missing or damaged, the copy at the start of the file was used; the disk was probably truncated after the last block, the data read is what remains";
        VHD_DYNAMIC_HEADER = 104, "the dynamic disk header ('cxsparse') could not be read or has the wrong signature; the footer's data offset points nowhere useful";
        VHD_BLOCK_SIZE = 105, "the dynamic disk header declares an invalid block size (zero or not a multiple of 512); the header is damaged";
        VHD_BAT_TOO_BIG = 106, "the block allocation table would be larger than the file itself; the header is damaged";
        VHD_BAT_READ = 107, "the block allocation table could not be read in full; the file is truncated";
        VHD_DIFFERENCING = 108, "the VHD is a differencing disk (it has a parent); merge it with its parent first (qemu-img convert, Hyper-V 'Merge') or give the merged disk";
        VHD_UNKNOWN_TYPE = 109, "the footer declares a disk type that is not fixed (2), dynamic (3) or differencing (4); the footer is damaged";
        VHD_BLOCK_PAST_END = 110, "a BAT entry points past the end of the file; that block reads as zeros, the disk was truncated or the BAT is damaged";
        VHDX_OPEN = 120, "the VHDX file could not be opened; check the path and permissions";
        VHDX_NOT = 121, "no 'vhdxfile' identifier at offset 0; the file is not a VHDX";
        VHDX_REGION_TABLE = 122, "neither region table (at 192 KB and 256 KB) is readable; the VHDX is truncated or damaged";
        VHDX_NO_BAT = 123, "the region table names no BAT region; the VHDX is damaged";
        VHDX_NO_METADATA = 124, "the region table names no metadata region; the VHDX is damaged";
        VHDX_METADATA_SIG = 125, "the metadata table has no 'metadata' signature; the VHDX is damaged";
        VHDX_DIFFERENCING = 126, "the VHDX has a parent (differencing disk); merge it with its parent first or give the merged disk";
        VHDX_METADATA_MISSING = 127, "the metadata carries no block size or no virtual disk size; the VHDX is damaged";
        VHDX_METADATA_DAMAGED = 128, "the metadata values are out of the range the format allows (block size, sector size or virtual size); the VHDX is damaged";
        VHDX_PARTIAL_BLOCK = 129, "a BAT entry is 'partially present', which only differencing disks have; the disk has a parent";
        VHDX_BAT_READ = 130, "the BAT could not be read in full; the file is truncated";
        VHDX_LOG_PENDING = 131, "the VHDX log region is not applied by this reader; a disk that was not cleanly detached may show stale sectors, mount it read-only in Hyper-V to replay the log if that matters";
    }
}

const VHD_FOOTER: usize = 512;
const VHD_FIXED: u32 = 2;
const VHD_DYNAMIC: u32 = 3;
const VHD_DIFFERENCING: u32 = 4;

enum VhdLayout {
    Fixed,
    Dynamic { blocks: Vec<Option<u64>>, block_size: u64, bitmap_bytes: u64 },
}

/// A VHD as `Read + Seek`.
pub struct VhdReader {
    file: File,
    file_len: u64,
    layout: VhdLayout,
    total_size: u64,
    position: u64,
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn be64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_be_bytes(a)
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn le64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

fn read_at(file: &mut File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buf)
}

impl VhdReader {
    /// Opens a `.vhd`.
    pub fn open(path: &Path) -> Result<Self> {
        let shown = path.display().to_string();
        let mut file = File::open(path).map_err(|e| Error::recorded(code::VHD_OPEN, format!("{shown}: {e}")))?;
        let len = file.metadata().map_err(|e| Error::recorded(code::VHD_OPEN, format!("{shown}: {e}")))?.len();
        if len < VHD_FOOTER as u64 {
            return Err(Error::recorded(code::VHD_TOO_SMALL, format!("{shown}: {len} bytes")));
        }
        let mut footer = [0u8; VHD_FOOTER];
        // Some writers leave a 511-byte footer; try both ends, then the copy at the start.
        let mut found = false;
        for off in [len - VHD_FOOTER as u64, len.saturating_sub(VHD_FOOTER as u64 - 1)] {
            if read_at(&mut file, off, &mut footer).is_ok() && &footer[..8] == b"conectix" {
                found = true;
                break;
            }
        }
        if !found {
            read_at(&mut file, 0, &mut footer).map_err(|e| Error::recorded(code::VHD_NO_FOOTER, format!("{shown}: {e}")))?;
            if &footer[..8] != b"conectix" {
                return Err(Error::recorded(code::VHD_NO_FOOTER, shown));
            }
            diag::warn(code::VHD_FOOTER_FROM_START, shown.clone());
        }
        let data_offset = be64(&footer, 16);
        let current_size = be64(&footer, 48);
        let disk_type = be32(&footer, 60);
        let layout = match disk_type {
            VHD_FIXED => VhdLayout::Fixed,
            VHD_DYNAMIC => {
                let mut hdr = [0u8; 1024];
                read_at(&mut file, data_offset, &mut hdr).map_err(|e| Error::recorded(code::VHD_DYNAMIC_HEADER, format!("{shown}: at {data_offset}: {e}")))?;
                if &hdr[..8] != b"cxsparse" {
                    return Err(Error::recorded(code::VHD_DYNAMIC_HEADER, format!("{shown}: no cxsparse signature at {data_offset}")));
                }
                let table_offset = be64(&hdr, 16);
                let max_entries = be32(&hdr, 28) as usize;
                let block_size = be32(&hdr, 32) as u64;
                if block_size == 0 || !block_size.is_multiple_of(512) {
                    return Err(Error::recorded(code::VHD_BLOCK_SIZE, format!("{shown}: block size {block_size}")));
                }
                let sectors = block_size / 512;
                let bitmap_bytes = sectors.div_ceil(8).div_ceil(512) * 512;
                if (max_entries as u64) * 4 > len {
                    return Err(Error::recorded(code::VHD_BAT_TOO_BIG, format!("{shown}: {max_entries} entries in a {len}-byte file")));
                }
                let mut bat = vec![0u8; max_entries * 4];
                read_at(&mut file, table_offset, &mut bat).map_err(|e| Error::recorded(code::VHD_BAT_READ, format!("{shown}: {e}")))?;
                let mut past_end = 0usize;
                let blocks = (0..max_entries)
                    .map(|i| {
                        let s = be32(&bat, i * 4);
                        if s == 0xFFFF_FFFF {
                            None
                        } else {
                            let start = s as u64 * 512;
                            if start >= len {
                                past_end += 1;
                                None
                            } else {
                                Some(start)
                            }
                        }
                    })
                    .collect();
                if past_end > 0 {
                    diag::warn(code::VHD_BLOCK_PAST_END, format!("{shown}: {past_end} block(s) point past the {len}-byte file"));
                }
                VhdLayout::Dynamic { blocks, block_size, bitmap_bytes }
            }
            VHD_DIFFERENCING => return Err(Error::recorded(code::VHD_DIFFERENCING, shown)),
            t => return Err(Error::recorded(code::VHD_UNKNOWN_TYPE, format!("{shown}: type {t}"))),
        };
        Ok(VhdReader { file, file_len: len, layout, total_size: current_size, position: 0 })
    }

    /// Virtual size of the disk.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Fixed or dynamic.
    pub fn is_dynamic(&self) -> bool {
        matches!(self.layout, VhdLayout::Dynamic { .. })
    }
}

impl Read for VhdReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_size {
            return Ok(0);
        }
        let want = buf.len().min((self.total_size - self.position) as usize);
        let pos = self.position;
        let n = match &self.layout {
            VhdLayout::Fixed => {
                if pos >= self.file_len {
                    buf[..want].fill(0);
                    want
                } else {
                    let avail = want.min((self.file_len - pos) as usize);
                    self.file.seek(SeekFrom::Start(pos))?;
                    let n = self.file.read(&mut buf[..avail])?;
                    if n == 0 {
                        buf[..want].fill(0);
                        want
                    } else {
                        n
                    }
                }
            }
            VhdLayout::Dynamic { blocks, block_size, bitmap_bytes } => {
                let bi = (pos / block_size) as usize;
                let in_block = pos % block_size;
                let n = want.min((block_size - in_block) as usize);
                match blocks.get(bi).copied().flatten() {
                    None => buf[..n].fill(0),
                    Some(start) => {
                        let first_sector = in_block / 512;
                        let last_sector = (in_block + n as u64 - 1) / 512;
                        let mut bitmap = vec![0u8; ((last_sector / 8) - (first_sector / 8) + 1) as usize];
                        read_at(&mut self.file, start + first_sector / 8, &mut bitmap)?;
                        read_at(&mut self.file, start + bitmap_bytes + in_block, &mut buf[..n])?;
                        for s in first_sector..=last_sector {
                            let byte = bitmap[(s / 8 - first_sector / 8) as usize];
                            if byte & (0x80 >> (s % 8)) == 0 {
                                let a = (s * 512).saturating_sub(in_block) as usize;
                                let b = (((s + 1) * 512).saturating_sub(in_block) as usize).min(n);
                                if a < b {
                                    buf[a..b].fill(0);
                                }
                            }
                        }
                    }
                }
                n
            }
        };
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for VhdReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        seek_to(&mut self.position, self.total_size, pos)
    }
}

fn seek_to(position: &mut u64, total: u64, pos: SeekFrom) -> io::Result<u64> {
    let new_pos = match pos {
        SeekFrom::Start(o) => o as i64,
        SeekFrom::End(o) => total as i64 + o,
        SeekFrom::Current(o) => *position as i64 + o,
    };
    if new_pos < 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek to a negative position"));
    }
    *position = new_pos as u64;
    Ok(*position)
}

// ───────────────────────────── VHDX ─────────────────────────────

const GUID_BAT: [u8; 16] = [0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08];
const GUID_METADATA: [u8; 16] = [0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E];
const GUID_FILE_PARAMETERS: [u8; 16] = [0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B];
const GUID_VIRTUAL_DISK_SIZE: [u8; 16] = [0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8];
const GUID_LOGICAL_SECTOR_SIZE: [u8; 16] = [0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F];

const VHDX_STATE_MASK: u64 = 0x7;
const VHDX_FULLY_PRESENT: u64 = 6;
const VHDX_PARTIALLY_PRESENT: u64 = 7;

/// On-disk GUIDs, for a VHDX test builder.
pub mod vhdx_guids {
    pub const BAT: [u8; 16] = super::GUID_BAT;
    pub const METADATA: [u8; 16] = super::GUID_METADATA;
    pub const FILE_PARAMETERS: [u8; 16] = super::GUID_FILE_PARAMETERS;
    pub const VIRTUAL_DISK_SIZE: [u8; 16] = super::GUID_VIRTUAL_DISK_SIZE;
    pub const LOGICAL_SECTOR_SIZE: [u8; 16] = super::GUID_LOGICAL_SECTOR_SIZE;
}

/// A VHDX as `Read + Seek`.
pub struct VhdxReader {
    file: File,
    blocks: Vec<Option<u64>>,
    block_size: u64,
    total_size: u64,
    position: u64,
}

impl VhdxReader {
    /// Opens a `.vhdx`.
    pub fn open(path: &Path) -> Result<Self> {
        let shown = path.display().to_string();
        let mut file = File::open(path).map_err(|e| Error::recorded(code::VHDX_OPEN, format!("{shown}: {e}")))?;
        let mut id = [0u8; 8];
        read_at(&mut file, 0, &mut id).map_err(|e| Error::recorded(code::VHDX_NOT, format!("{shown}: {e}")))?;
        if &id != b"vhdxfile" {
            return Err(Error::recorded(code::VHDX_NOT, shown));
        }
        // Header 1 at 64 KB: a non-empty log (log length at +0x30? the header's LogLength
        // at offset 0x40 and LogOffset at 0x48) means the disk was not detached cleanly.
        let mut hdr = vec![0u8; 4096];
        if read_at(&mut file, 64 * 1024, &mut hdr).is_ok() && &hdr[..4] == b"head" {
            let log_length = le32(&hdr, 0x40);
            let log_guid_zero = hdr[0x10..0x20].iter().all(|&b| b == 0);
            if log_length > 0 && !log_guid_zero {
                diag::info(code::VHDX_LOG_PENDING, format!("{shown}: log of {log_length} bytes"));
            }
        }
        let mut regions: Option<Vec<([u8; 16], u64, u32)>> = None;
        for off in [192 * 1024u64, 256 * 1024] {
            let mut tbl = vec![0u8; 64 * 1024];
            if read_at(&mut file, off, &mut tbl).is_err() {
                continue;
            }
            if &tbl[..4] != b"regi" {
                continue;
            }
            let count = le32(&tbl, 8) as usize;
            if count > 2047 {
                continue;
            }
            let mut v = Vec::with_capacity(count);
            for i in 0..count {
                let e = 16 + i * 32;
                let mut g = [0u8; 16];
                g.copy_from_slice(&tbl[e..e + 16]);
                v.push((g, le64(&tbl, e + 16), le32(&tbl, e + 24)));
            }
            regions = Some(v);
            break;
        }
        let regions = regions.ok_or_else(|| Error::recorded(code::VHDX_REGION_TABLE, shown.clone()))?;
        let (bat_off, bat_len) = regions.iter().find(|r| r.0 == GUID_BAT).map(|r| (r.1, r.2)).ok_or_else(|| Error::recorded(code::VHDX_NO_BAT, shown.clone()))?;
        let (meta_off, _) = regions.iter().find(|r| r.0 == GUID_METADATA).map(|r| (r.1, r.2)).ok_or_else(|| Error::recorded(code::VHDX_NO_METADATA, shown.clone()))?;

        let mut mt = vec![0u8; 64 * 1024];
        read_at(&mut file, meta_off, &mut mt).map_err(|e| Error::recorded(code::VHDX_METADATA_SIG, format!("{shown}: {e}")))?;
        if &mt[..8] != b"metadata" {
            return Err(Error::recorded(code::VHDX_METADATA_SIG, shown));
        }
        let n_items = u16::from_le_bytes([mt[10], mt[11]]) as usize;
        let mut block_size = 0u64;
        let mut has_parent = false;
        let mut virtual_size = 0u64;
        let mut sector_size = 512u64;
        for i in 0..n_items.min(2047) {
            let e = 32 + i * 32;
            let gid = &mt[e..e + 16];
            let off = le32(&mt, e + 16) as u64;
            let len = le32(&mt, e + 20) as usize;
            if len > 1 << 20 {
                continue;
            }
            let mut item = vec![0u8; len];
            if read_at(&mut file, meta_off + off, &mut item).is_err() {
                continue;
            }
            if gid == GUID_FILE_PARAMETERS && len >= 8 {
                block_size = le32(&item, 0) as u64;
                has_parent = le32(&item, 4) & 0x2 != 0;
            } else if gid == GUID_VIRTUAL_DISK_SIZE && len >= 8 {
                virtual_size = le64(&item, 0);
            } else if gid == GUID_LOGICAL_SECTOR_SIZE && len >= 4 {
                sector_size = le32(&item, 0) as u64;
            }
        }
        if has_parent {
            return Err(Error::recorded(code::VHDX_DIFFERENCING, shown));
        }
        if block_size == 0 || virtual_size == 0 {
            return Err(Error::recorded(code::VHDX_METADATA_MISSING, shown));
        }
        if !block_size.is_power_of_two() || !(1 << 20..=256 << 20).contains(&block_size) || (sector_size != 512 && sector_size != 4096) || virtual_size > 64u64 << 40 {
            return Err(Error::recorded(code::VHDX_METADATA_DAMAGED, format!("{shown}: block size {block_size}, sector size {sector_size}, virtual size {virtual_size}")));
        }
        let chunk_ratio = ((1u64 << 23) * sector_size / block_size).max(1);
        let n_blocks = virtual_size.div_ceil(block_size) as usize;
        let n_entries = n_blocks + n_blocks / chunk_ratio as usize + 1;
        let mut bat = vec![0u8; (n_entries * 8).min(bat_len as usize)];
        read_at(&mut file, bat_off, &mut bat).map_err(|e| Error::recorded(code::VHDX_BAT_READ, format!("{shown}: {e}")))?;
        let mut blocks = Vec::with_capacity(n_blocks);
        for i in 0..n_blocks {
            let idx = i + i / chunk_ratio as usize;
            if idx * 8 + 8 > bat.len() {
                blocks.push(None);
                continue;
            }
            let entry = le64(&bat, idx * 8);
            let state = entry & VHDX_STATE_MASK;
            let offset = entry & !0xF_FFFF;
            blocks.push(match state {
                VHDX_FULLY_PRESENT if offset != 0 => Some(offset),
                VHDX_PARTIALLY_PRESENT => return Err(Error::recorded(code::VHDX_PARTIAL_BLOCK, shown)),
                _ => None,
            });
        }
        Ok(VhdxReader { file, blocks, block_size, total_size: virtual_size, position: 0 })
    }

    /// Virtual size of the disk.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }
}

impl Read for VhdxReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_size {
            return Ok(0);
        }
        let want = buf.len().min((self.total_size - self.position) as usize);
        let bi = (self.position / self.block_size) as usize;
        let in_block = self.position % self.block_size;
        let n = want.min((self.block_size - in_block) as usize);
        match self.blocks.get(bi).copied().flatten() {
            None => buf[..n].fill(0),
            Some(start) => read_at(&mut self.file, start + in_block, &mut buf[..n])?,
        }
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for VhdxReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        seek_to(&mut self.position, self.total_size, pos)
    }
}

impl std::fmt::Debug for VhdReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VhdReader({}, {} bytes)", if self.is_dynamic() { "dynamic" } else { "fixed" }, self.total_size)
    }
}

impl std::fmt::Debug for VhdxReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VhdxReader({} blocks of {} bytes, {} bytes)", self.blocks.len(), self.block_size, self.total_size)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("evidencefs-vhd-test-{}-{}", std::process::id(), name))
    }

    /// A VHD footer for tests.
    pub fn vhd_footer(size: u64, disk_type: u32, data_offset: u64) -> [u8; 512] {
        let mut f = [0u8; 512];
        f[..8].copy_from_slice(b"conectix");
        f[16..24].copy_from_slice(&data_offset.to_be_bytes());
        f[40..48].copy_from_slice(&size.to_be_bytes());
        f[48..56].copy_from_slice(&size.to_be_bytes());
        f[60..64].copy_from_slice(&disk_type.to_be_bytes());
        f
    }

    /// A fixed VHD holding `data`, written to a temp file.
    pub fn write_fixed_vhd(name: &str, data: &[u8]) -> PathBuf {
        let p = tmp(name);
        let mut f = File::create(&p).unwrap();
        f.write_all(data).unwrap();
        f.write_all(&vhd_footer(data.len() as u64, VHD_FIXED, u64::MAX)).unwrap();
        p
    }

    #[test]
    fn fixed_vhd_is_raw_plus_footer() {
        crate::diag::set_quiet(true);
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let p = write_fixed_vhd("fixed.vhd", &data);
        let mut r = VhdReader::open(&p).unwrap();
        assert_eq!(r.total_size(), 4096);
        assert!(!r.is_dynamic());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
        r.seek(SeekFrom::Start(1000)).unwrap();
        let mut b = [0u8; 8];
        r.read_exact(&mut b).unwrap();
        assert_eq!(&b[..], &data[1000..1008]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn dynamic_vhd_reads_allocated_blocks_and_zero_holes() {
        crate::diag::set_quiet(true);
        let p = tmp("dyn.vhd");
        let block = 4096u64;
        let size = 3 * block;
        let mut img: Vec<u8> = Vec::new();
        img.extend_from_slice(&vhd_footer(size, VHD_DYNAMIC, 512));
        let mut hdr = vec![0u8; 1024];
        hdr[..8].copy_from_slice(b"cxsparse");
        hdr[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        hdr[16..24].copy_from_slice(&1536u64.to_be_bytes());
        hdr[28..32].copy_from_slice(&3u32.to_be_bytes());
        hdr[32..36].copy_from_slice(&(block as u32).to_be_bytes());
        img.extend_from_slice(&hdr);
        let b0 = 2048u64 / 512;
        let b2 = (2048 + 512 + block) / 512;
        let mut bat = vec![0u8; 512];
        bat[0..4].copy_from_slice(&(b0 as u32).to_be_bytes());
        bat[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        bat[8..12].copy_from_slice(&(b2 as u32).to_be_bytes());
        img.extend_from_slice(&bat);
        let mut bm = vec![0u8; 512];
        bm[0] = 0b1110_1111;
        img.extend_from_slice(&bm);
        let d0: Vec<u8> = (0..block as usize).map(|i| (i % 7 + 1) as u8).collect();
        img.extend_from_slice(&d0);
        let mut bm2 = vec![0u8; 512];
        bm2[0] = 0xFF;
        img.extend_from_slice(&bm2);
        let d2: Vec<u8> = (0..block as usize).map(|i| (i % 5 + 10) as u8).collect();
        img.extend_from_slice(&d2);
        img.extend_from_slice(&vhd_footer(size, VHD_DYNAMIC, 512));
        std::fs::write(&p, &img).unwrap();

        let mut r = VhdReader::open(&p).unwrap();
        assert_eq!(r.total_size(), size);
        assert!(r.is_dynamic());
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out.len() as u64, size);
        assert_eq!(&out[..1536], &d0[..1536]);
        assert!(out[1536..2048].iter().all(|b| *b == 0), "sector 3 of block 0 is a zero sector");
        assert_eq!(&out[2048..4096], &d0[2048..]);
        assert!(out[4096..8192].iter().all(|b| *b == 0), "unallocated block reads as zeros");
        assert_eq!(&out[8192..], &d2[..]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn refusals_carry_their_codes() {
        crate::diag::set_quiet(true);
        let p = tmp("diff.vhd");
        std::fs::write(&p, vhd_footer(4096, VHD_DIFFERENCING, 512)).unwrap();
        assert_eq!(VhdReader::open(&p).unwrap_err().code, code::VHD_DIFFERENCING);
        std::fs::write(&p, vhd_footer(4096, 9, 512)).unwrap();
        assert_eq!(VhdReader::open(&p).unwrap_err().code, code::VHD_UNKNOWN_TYPE);
        std::fs::write(&p, vec![0x41u8; 2048]).unwrap();
        assert_eq!(VhdReader::open(&p).unwrap_err().code, code::VHD_NO_FOOTER);
        std::fs::write(&p, vec![0x41u8; 100]).unwrap();
        assert_eq!(VhdReader::open(&p).unwrap_err().code, code::VHD_TOO_SMALL);
        assert_eq!(VhdReader::open(&tmp("missing.vhd")).unwrap_err().code, code::VHD_OPEN);
        // A dynamic footer pointing at garbage.
        let mut img = vhd_footer(4096, VHD_DYNAMIC, 512).to_vec();
        img.extend_from_slice(&[0u8; 1024]);
        std::fs::write(&p, &img).unwrap();
        assert_eq!(VhdReader::open(&p).unwrap_err().code, code::VHD_DYNAMIC_HEADER);
        // Bad block size.
        let mut img = vhd_footer(4096, VHD_DYNAMIC, 512).to_vec();
        let mut hdr = vec![0u8; 1024];
        hdr[..8].copy_from_slice(b"cxsparse");
        hdr[32..36].copy_from_slice(&100u32.to_be_bytes());
        img.extend_from_slice(&hdr);
        std::fs::write(&p, &img).unwrap();
        assert_eq!(VhdReader::open(&p).unwrap_err().code, code::VHD_BLOCK_SIZE);
        // A BAT bigger than the file.
        let mut img = vhd_footer(4096, VHD_DYNAMIC, 512).to_vec();
        let mut hdr = vec![0u8; 1024];
        hdr[..8].copy_from_slice(b"cxsparse");
        hdr[28..32].copy_from_slice(&1_000_000u32.to_be_bytes());
        hdr[32..36].copy_from_slice(&4096u32.to_be_bytes());
        img.extend_from_slice(&hdr);
        std::fs::write(&p, &img).unwrap();
        assert_eq!(VhdReader::open(&p).unwrap_err().code, code::VHD_BAT_TOO_BIG);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn footer_only_at_start_is_accepted_with_a_warning() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let p = tmp("start.vhd");
        let mut img = vhd_footer(1024, VHD_FIXED, u64::MAX).to_vec();
        img.extend_from_slice(&[5u8; 1024]);
        std::fs::write(&p, &img).unwrap();
        let r = VhdReader::open(&p).unwrap();
        assert_eq!(r.total_size(), 1024);
        assert!(crate::diag::has(code::VHD_FOOTER_FROM_START));
        crate::diag::drain();
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn truncated_fixed_vhd_reads_zeros_past_the_file() {
        crate::diag::set_quiet(true);
        let p = tmp("trunc.vhd");
        // Footer claims 8192 bytes; file holds 1024 + footer copy at start.
        let mut img = vhd_footer(8192, VHD_FIXED, u64::MAX).to_vec();
        img.extend_from_slice(&[5u8; 1024]);
        std::fs::write(&p, &img).unwrap();
        let mut r = VhdReader::open(&p).unwrap();
        r.seek(SeekFrom::Start(4000)).unwrap();
        let mut b = [1u8; 16];
        let n = r.read(&mut b).unwrap();
        assert_eq!(n, 16);
        assert_eq!(b, [0u8; 16]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn vhdx_bat_index_skips_bitmap_entries() {
        let chunk_ratio = 4usize;
        let idx = |i: usize| i + i / chunk_ratio;
        assert_eq!((0..6).map(idx).collect::<Vec<_>>(), vec![0, 1, 2, 3, 5, 6]);
    }

    /// A tiny dynamic VHDX: one 1 MB block present holding `pattern`, one absent.
    pub fn write_vhdx(name: &str, pattern: u8, with_parent: bool) -> PathBuf {
        let block: u64 = 1 << 20;
        let virtual_size = 2 * block;
        let bat_off: u64 = 1 << 20;
        let meta_off: u64 = bat_off + 64 * 1024;
        let data_off: u64 = 2 << 20;
        let mut img = vec![0u8; (data_off + block) as usize];
        img[..8].copy_from_slice(b"vhdxfile");
        // Header at 64 KB with an empty log.
        img[64 * 1024..64 * 1024 + 4].copy_from_slice(b"head");
        // Region table at 192 KB.
        let rt = 192 * 1024;
        img[rt..rt + 4].copy_from_slice(b"regi");
        img[rt + 8..rt + 12].copy_from_slice(&2u32.to_le_bytes());
        let e0 = rt + 16;
        img[e0..e0 + 16].copy_from_slice(&GUID_BAT);
        img[e0 + 16..e0 + 24].copy_from_slice(&bat_off.to_le_bytes());
        img[e0 + 24..e0 + 28].copy_from_slice(&(64 * 1024u32).to_le_bytes());
        let e1 = e0 + 32;
        img[e1..e1 + 16].copy_from_slice(&GUID_METADATA);
        img[e1 + 16..e1 + 24].copy_from_slice(&meta_off.to_le_bytes());
        img[e1 + 24..e1 + 28].copy_from_slice(&(64 * 1024u32).to_le_bytes());
        // Metadata table.
        let m = meta_off as usize;
        img[m..m + 8].copy_from_slice(b"metadata");
        img[m + 10..m + 12].copy_from_slice(&3u16.to_le_bytes());
        let items: [([u8; 16], Vec<u8>); 3] = [
            (GUID_FILE_PARAMETERS, [(block as u32).to_le_bytes(), (if with_parent { 2u32 } else { 0 }).to_le_bytes()].concat()),
            (GUID_VIRTUAL_DISK_SIZE, virtual_size.to_le_bytes().to_vec()),
            (GUID_LOGICAL_SECTOR_SIZE, 512u32.to_le_bytes().to_vec()),
        ];
        let mut item_off = 4096u32;
        for (i, (g, bytes)) in items.iter().enumerate() {
            let e = m + 32 + i * 32;
            img[e..e + 16].copy_from_slice(g);
            img[e + 16..e + 20].copy_from_slice(&item_off.to_le_bytes());
            img[e + 20..e + 24].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
            let at = m + item_off as usize;
            img[at..at + bytes.len()].copy_from_slice(bytes);
            item_off += 64;
        }
        // BAT: block 0 present at data_off, block 1 absent.
        let b = bat_off as usize;
        img[b..b + 8].copy_from_slice(&(data_off | VHDX_FULLY_PRESENT).to_le_bytes());
        // Data.
        for x in &mut img[data_off as usize..] {
            *x = pattern;
        }
        let p = tmp(name);
        std::fs::write(&p, &img).unwrap();
        p
    }

    #[test]
    fn vhdx_reads_present_block_and_zero_absent_block() {
        crate::diag::set_quiet(true);
        let p = write_vhdx("ok.vhdx", 0xAB, false);
        let mut r = VhdxReader::open(&p).unwrap();
        assert_eq!(r.total_size(), 2 << 20);
        let mut b = [0u8; 16];
        r.seek(SeekFrom::Start(12345)).unwrap();
        r.read_exact(&mut b).unwrap();
        assert_eq!(b, [0xAB; 16]);
        r.seek(SeekFrom::Start((1 << 20) + 5)).unwrap();
        r.read_exact(&mut b).unwrap();
        assert_eq!(b, [0u8; 16]);
        r.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(r.read(&mut b).unwrap(), 0);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn vhdx_refusals_carry_their_codes() {
        crate::diag::set_quiet(true);
        let p = write_vhdx("parent.vhdx", 0, true);
        assert_eq!(VhdxReader::open(&p).unwrap_err().code, code::VHDX_DIFFERENCING);
        std::fs::write(&p, b"not a vhdx at all, just text").unwrap();
        assert_eq!(VhdxReader::open(&p).unwrap_err().code, code::VHDX_NOT);
        let mut img = vec![0u8; 300 * 1024];
        img[..8].copy_from_slice(b"vhdxfile");
        std::fs::write(&p, &img).unwrap();
        assert_eq!(VhdxReader::open(&p).unwrap_err().code, code::VHDX_REGION_TABLE);
        assert_eq!(VhdxReader::open(&tmp("missing.vhdx")).unwrap_err().code, code::VHDX_OPEN);
        std::fs::remove_file(&p).ok();
    }
}
