//! Partitions and what they hold: MBR (with extended partition chains), GPT (primary
//! or backup header), a whole-image volume with no table, and the common offsets a
//! raw volume dump sits at. Every volume is sniffed by signature, so the table's type
//! byte never decides alone.

pub mod lvm;
pub mod vss;

use crate::diag;
use crate::source::SharedReader;

pub mod code {
    crate::codes! {
        PART_NO_TABLE = 250, "the image has no MBR signature (55 AA) at the end of its first sector; it was read as a single volume starting at offset 0";
        PART_PROTECTIVE_MBR_ONLY = 251, "the MBR marks the disk as GPT (type EE) but no GPT header was found at LBA 1 nor at the last LBA; the partition table is gone, the volumes were searched at common offsets";
        PART_GPT_HEADER_BAD = 252, "the GPT header is present but its fields are out of range (entry count, entry size, entry LBA); the entries were not read";
        PART_GPT_BACKUP_USED = 253, "the primary GPT header at LBA 1 was damaged or missing, the backup header at the last LBA was used instead";
        PART_GPT_ENTRY_PAST_END = 254, "a GPT entry starts or ends beyond the image; it was skipped, the image is truncated or the entry is damaged";
        PART_MBR_EXTENDED = 255, "the MBR has an extended partition; its EBR chain was followed and the logical partitions were added";
        PART_EBR_LOOP = 256, "the EBR chain of an extended partition loops or runs past 128 links; the chain was cut there";
        PART_MBR_ENTRY_PAST_END = 257, "an MBR entry starts beyond the image; it was skipped, the image is truncated or the entry is damaged";
        PART_OVERLAP = 258, "two partitions overlap; both were kept, the table is damaged or hand-edited";
        PART_FALLBACK_OFFSET = 259, "no partition table gave a readable volume; a file system signature was found at a common offset (0, 63 sectors, 1 MB, 2048 sectors) and that volume was added";
        PART_BITLOCKER = 260, "the volume is BitLocker-encrypted (-FVE-FS- signature); it cannot be read without the recovery key, decrypt it first (dislocker, manage-bde) and give the decrypted image";
        PART_LUKS = 261, "the volume is LUKS-encrypted; it cannot be read without the passphrase, open it with cryptsetup and image the mapped device";
        PART_FS_UNSUPPORTED = 262, "the volume holds a file system this crate does not read yet (btrfs, F2FS, APFS, HFS+, ReFS, swap); it is listed but not walked";
        PART_FS_UNKNOWN = 263, "the volume holds no file system signature this crate knows; it is listed as unknown and not walked, it may be empty, encrypted with another product, or a raw data partition";
        PART_NONE_READABLE = 264, "no volume of the image can be read (no NTFS, ext, XFS or LVM); the image holds only unsupported, encrypted or empty volumes";
        PART_LISTED = 265, "the partitions of the image, with their kinds, as the table and the signatures gave them";
        PART_SECTOR_4K = 266, "the GPT header was found at offset 4096, so the disk uses 4 KB sectors; LBAs were converted with that size";
    }
}

/// GPT partition type GUIDs (as on disk, mixed-endian).
pub const GPT_BASIC_DATA_GUID: [u8; 16] = [0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7];
/// Linux file system data.
pub const GPT_LINUX_FS_GUID: [u8; 16] = [0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4];
/// Linux LVM.
pub const GPT_LINUX_LVM_GUID: [u8; 16] = [0x79, 0xD3, 0xD6, 0xE6, 0x07, 0xF5, 0xC2, 0x44, 0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28];
/// EFI system partition.
pub const GPT_EFI_SYSTEM_GUID: [u8; 16] = [0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B];
/// Microsoft reserved.
pub const GPT_MS_RESERVED_GUID: [u8; 16] = [0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D, 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE];
/// Windows recovery.
pub const GPT_WINDOWS_RECOVERY_GUID: [u8; 16] = [0xA4, 0xBB, 0x94, 0xDE, 0xD1, 0x06, 0x40, 0x4D, 0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC];

const EXT_SUPER_MAGIC: u16 = 0xEF53;

/// What a volume holds, by signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VolumeKind {
    Ntfs,
    BitLocker,
    Ext,
    Xfs,
    Btrfs,
    F2fs,
    Swap,
    Lvm,
    Luks,
    Fat,
    ExFat,
    ReFs,
    Apfs,
    HfsPlus,
    Unknown,
}

impl VolumeKind {
    /// Short label for logs and columns.
    pub fn label(&self) -> &'static str {
        match self {
            VolumeKind::Ntfs => "NTFS",
            VolumeKind::BitLocker => "BitLocker",
            VolumeKind::Ext => "ext2/3/4",
            VolumeKind::Xfs => "XFS",
            VolumeKind::Btrfs => "btrfs",
            VolumeKind::F2fs => "F2FS",
            VolumeKind::Swap => "swap",
            VolumeKind::Lvm => "LVM2",
            VolumeKind::Luks => "LUKS",
            VolumeKind::Fat => "FAT",
            VolumeKind::ExFat => "exFAT",
            VolumeKind::ReFs => "ReFS",
            VolumeKind::Apfs => "APFS",
            VolumeKind::HfsPlus => "HFS+",
            VolumeKind::Unknown => "unknown",
        }
    }

    /// File systems this crate walks (LVM is a container of them).
    pub fn is_readable(&self) -> bool {
        matches!(self, VolumeKind::Ntfs | VolumeKind::Ext | VolumeKind::Xfs | VolumeKind::Lvm | VolumeKind::Fat | VolumeKind::ExFat)
    }

    /// Encrypted: listed, never read.
    pub fn is_encrypted(&self) -> bool {
        matches!(self, VolumeKind::BitLocker | VolumeKind::Luks)
    }
}

/// Where a volume was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Table {
    Mbr,
    /// A logical partition inside an MBR extended partition.
    MbrLogical,
    Gpt,
    /// No table: the image is the volume.
    Whole,
    /// Found by signature at a common offset.
    Fallback,
}

impl Table {
    /// `mbr`, `ebr`, `gpt`, `whole`, `fallback`.
    pub fn label(&self) -> &'static str {
        match self {
            Table::Mbr => "mbr",
            Table::MbrLogical => "ebr",
            Table::Gpt => "gpt",
            Table::Whole => "whole",
            Table::Fallback => "fallback",
        }
    }
}

/// One partition of an image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Volume {
    /// Position in the list (0-based), stable for a given image.
    pub index: usize,
    /// First byte in the image.
    pub offset: u64,
    /// Size in bytes as the table says (clipped to the image).
    pub size: u64,
    pub kind: VolumeKind,
    pub table: Table,
    /// MBR type byte (`07`) or GPT type GUID in text.
    pub type_id: String,
    /// GPT partition name, if any.
    pub name: Option<String>,
}

impl Volume {
    /// `partition_<index>`: the folder name the c00pr tools stage a partition under.
    pub fn dir_name(&self) -> String {
        format!("partition_{}", self.index)
    }

    /// One line for logs: `partition 1: NTFS at 0x100000 (59.9 GB, gpt)`.
    pub fn describe(&self) -> String {
        format!("partition {}: {} at {:#x} ({}, {}{})", self.index, self.kind.label(), self.offset, human_size(self.size), self.table.label(), self.name.as_deref().map(|n| format!(", \"{n}\"")).unwrap_or_default())
    }

    /// A reader over this partition's bytes.
    pub fn reader(&self, image: &SharedReader) -> SharedReader {
        image.view(self.offset, self.size)
    }
}

/// `1.5 GB`, `320 MB`, `4 KB`, `17 B`.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Identifies a volume by its on-disk signatures.
pub fn sniff(r: &SharedReader, offset: u64) -> VolumeKind {
    let v = r.at(offset);
    if let Some(b) = v.bytes_at(0, 11) {
        if &b[3..11] == b"NTFS    " {
            return VolumeKind::Ntfs;
        }
        if &b[3..11] == b"-FVE-FS-" {
            return VolumeKind::BitLocker;
        }
        if &b[3..11] == b"EXFAT   " {
            return VolumeKind::ExFat;
        }
        if &b[3..7] == b"ReFS" {
            return VolumeKind::ReFs;
        }
        if &b[..4] == b"XFSB" {
            return VolumeKind::Xfs;
        }
        if &b[..6] == b"LUKS\xba\xbe" {
            return VolumeKind::Luks;
        }
    }
    if let Some(b) = v.bytes_at(0x438, 2) {
        if u16::from_le_bytes([b[0], b[1]]) == EXT_SUPER_MAGIC {
            return VolumeKind::Ext;
        }
    }
    if let Some(b) = v.bytes_at(512, 8) {
        if &b == b"LABELONE" {
            return VolumeKind::Lvm;
        }
    }
    if let Some(b) = v.bytes_at(0x10040, 8) {
        if &b == b"_BHRfS_M" {
            return VolumeKind::Btrfs;
        }
    }
    if let Some(b) = v.bytes_at(0x400, 4) {
        if b == [0x10, 0x20, 0xF5, 0xF2] {
            return VolumeKind::F2fs;
        }
        if &b[..2] == b"H+" || &b[..2] == b"HX" {
            return VolumeKind::HfsPlus;
        }
    }
    if let Some(b) = v.bytes_at(32, 4) {
        if &b == b"NXSB" {
            return VolumeKind::Apfs;
        }
    }
    if let Some(b) = v.bytes_at(4096 - 10, 10) {
        if &b == b"SWAPSPACE2" || &b == b"SWAP-SPACE" {
            return VolumeKind::Swap;
        }
    }
    if let Some(b) = v.bytes_at(0x36, 8) {
        if b.starts_with(b"FAT") {
            return VolumeKind::Fat;
        }
    }
    if let Some(b) = v.bytes_at(0x52, 8) {
        if b.starts_with(b"FAT32") {
            return VolumeKind::Fat;
        }
    }
    VolumeKind::Unknown
}

/// A GUID in its usual text form (mixed-endian as GPT stores it).
pub fn guid_text(g: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

/// The name a GPT type GUID is known by, or its text.
pub fn gpt_type_name(g: &[u8; 16]) -> String {
    match *g {
        GPT_BASIC_DATA_GUID => "basic data".to_string(),
        GPT_LINUX_FS_GUID => "linux filesystem".to_string(),
        GPT_LINUX_LVM_GUID => "linux lvm".to_string(),
        GPT_EFI_SYSTEM_GUID => "efi system".to_string(),
        GPT_MS_RESERVED_GUID => "microsoft reserved".to_string(),
        GPT_WINDOWS_RECOVERY_GUID => "windows recovery".to_string(),
        _ => guid_text(g),
    }
}

fn utf16le_name(b: &[u8]) -> Option<String> {
    let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    if units.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&units))
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn le64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// Reads the GPT entries announced by a header at `hdr_off`, with `sector` bytes per LBA.
fn gpt_entries(r: &SharedReader, hdr_off: u64, sector: u64, image_size: u64, label: &str) -> Option<Vec<Volume>> {
    let h = r.bytes_at(hdr_off, 92)?;
    if &h[..8] != b"EFI PART" {
        return None;
    }
    let entry_lba = le64(&h, 72);
    let count = le32(&h, 80);
    let esize = le32(&h, 84) as u64;
    if count == 0 || count > 1024 || !(128..=4096).contains(&esize) || entry_lba == 0 || entry_lba.saturating_mul(sector) >= image_size {
        diag::warn(code::PART_GPT_HEADER_BAD, format!("{label}: {count} entries of {esize} bytes at LBA {entry_lba}"));
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for i in 0..count as u64 {
        let Some(e) = r.bytes_at(entry_lba * sector + i * esize, esize as usize) else { break };
        let type_guid: [u8; 16] = e[..16].try_into().expect("16 bytes");
        if type_guid.iter().all(|&b| b == 0) {
            continue;
        }
        let first = le64(&e, 32);
        let last = le64(&e, 40);
        let offset = first * sector;
        if first == 0 || last < first {
            continue;
        }
        if offset >= image_size {
            diag::warn(code::PART_GPT_ENTRY_PAST_END, format!("{label}: entry {i} at LBA {first} beyond {image_size} bytes"));
            continue;
        }
        let size = ((last - first + 1) * sector).min(image_size - offset);
        if (last + 1) * sector > image_size {
            diag::warn(code::PART_GPT_ENTRY_PAST_END, format!("{label}: entry {i} ends at LBA {last}, clipped to the image"));
        }
        out.push(Volume { index: 0, offset, size, kind: sniff(r, offset), table: Table::Gpt, type_id: gpt_type_name(&type_guid), name: utf16le_name(&e[56..128.min(e.len())]) });
    }
    Some(out)
}

/// Every partition of the image with what it holds. An image with no table is sniffed
/// at offset 0; an image whose table gives nothing readable is searched at common offsets.
pub fn list_volumes(r: &SharedReader) -> Vec<Volume> {
    let image_size = r.len();
    let label = format!("{}-byte image", image_size);
    let mut out: Vec<Volume> = Vec::new();
    let mbr = r.bytes_at(0, 512);
    let has_mbr = mbr.as_ref().is_some_and(|m| m[510] == 0x55 && m[511] == 0xAA);
    if let (true, Some(mbr)) = (has_mbr, &mbr) {
        let is_gpt = (0..4).any(|i| mbr[446 + i * 16 + 4] == 0xEE);
        if is_gpt {
            // Primary header at LBA 1 (512 or 4096 bytes per sector), else the backup at the end.
            let mut found = None;
            for sector in [512u64, 4096] {
                if let Some(v) = gpt_entries(r, sector, sector, image_size, &label) {
                    if sector == 4096 {
                        diag::info(code::PART_SECTOR_4K, label.clone());
                    }
                    found = Some(v);
                    break;
                }
            }
            if found.is_none() && image_size >= 1024 {
                if let Some(v) = gpt_entries(r, image_size - 512, 512, image_size, &label) {
                    diag::warn(code::PART_GPT_BACKUP_USED, label.clone());
                    found = Some(v);
                }
            }
            match found {
                Some(v) => out.extend(v),
                None => {
                    diag::warn(code::PART_PROTECTIVE_MBR_ONLY, label.clone());
                }
            }
        } else {
            let mut extended: Vec<u64> = Vec::new();
            for i in 0..4 {
                let e = &mbr[446 + i * 16..446 + (i + 1) * 16];
                let ptype = e[4];
                let lba = le32(e, 8) as u64;
                let sectors = le32(e, 12) as u64;
                if ptype == 0 || lba == 0 {
                    continue;
                }
                if matches!(ptype, 0x05 | 0x0F | 0x85) {
                    extended.push(lba * 512);
                    continue;
                }
                let offset = lba * 512;
                if offset >= image_size {
                    diag::warn(code::PART_MBR_ENTRY_PAST_END, format!("{label}: entry {i} type {ptype:02x} at LBA {lba}"));
                    continue;
                }
                out.push(Volume { index: 0, offset, size: (sectors * 512).min(image_size - offset), kind: sniff(r, offset), table: Table::Mbr, type_id: format!("{ptype:02x}"), name: None });
            }
            for ext_start in extended {
                diag::info(code::PART_MBR_EXTENDED, format!("{label}: extended partition at {ext_start:#x}"));
                let mut seen = std::collections::HashSet::new();
                let mut ebr_off = ext_start;
                let mut links = 0;
                loop {
                    if !seen.insert(ebr_off) || links >= 128 || ebr_off >= image_size {
                        diag::warn(code::PART_EBR_LOOP, format!("{label}: at {ebr_off:#x} after {links} links"));
                        break;
                    }
                    links += 1;
                    let Some(ebr) = r.bytes_at(ebr_off, 512) else { break };
                    if ebr[510] != 0x55 || ebr[511] != 0xAA {
                        break;
                    }
                    let e = &ebr[446..462];
                    let ptype = e[4];
                    let lba = le32(e, 8) as u64;
                    let sectors = le32(e, 12) as u64;
                    if ptype != 0 && lba != 0 {
                        let offset = ebr_off + lba * 512;
                        if offset < image_size {
                            out.push(Volume { index: 0, offset, size: (sectors * 512).min(image_size - offset), kind: sniff(r, offset), table: Table::MbrLogical, type_id: format!("{ptype:02x}"), name: None });
                        } else {
                            diag::warn(code::PART_MBR_ENTRY_PAST_END, format!("{label}: logical partition at {offset:#x}"));
                        }
                    }
                    let next = &ebr[462..478];
                    let next_lba = le32(next, 8) as u64;
                    if next[4] == 0 || next_lba == 0 {
                        break;
                    }
                    ebr_off = ext_start + next_lba * 512;
                }
            }
        }
    } else {
        diag::info(code::PART_NO_TABLE, label.clone());
    }
    if out.is_empty() {
        let kind = sniff(r, 0);
        if kind != VolumeKind::Unknown {
            out.push(Volume { index: 0, offset: 0, size: image_size, kind, table: Table::Whole, type_id: String::new(), name: None });
        }
    }
    if !out.iter().any(|v| v.kind.is_readable()) {
        for &offset in &[0u64, 63 * 512, 1024 * 1024, 2048 * 512, 32 * 1024 * 1024] {
            if offset >= image_size || out.iter().any(|v| v.offset == offset) {
                continue;
            }
            let kind = sniff(r, offset);
            if kind.is_readable() {
                diag::warn(code::PART_FALLBACK_OFFSET, format!("{label}: {} at {offset:#x}", kind.label()));
                out.push(Volume { index: 0, offset, size: image_size - offset, kind, table: Table::Fallback, type_id: String::new(), name: None });
            }
        }
    }
    out.sort_by_key(|v| v.offset);
    for i in 1..out.len() {
        if out[i].offset < out[i - 1].offset + out[i - 1].size && out[i - 1].table != Table::Fallback && out[i].table != Table::Fallback {
            diag::warn(code::PART_OVERLAP, format!("{label}: {:#x} and {:#x}", out[i - 1].offset, out[i].offset));
        }
    }
    for (i, v) in out.iter_mut().enumerate() {
        v.index = i;
    }
    for v in &out {
        match v.kind {
            VolumeKind::BitLocker => {
                diag::warn(code::PART_BITLOCKER, v.describe());
            }
            VolumeKind::Luks => {
                diag::warn(code::PART_LUKS, v.describe());
            }
            VolumeKind::Unknown => {
                diag::info(code::PART_FS_UNKNOWN, v.describe());
            }
            k if !k.is_readable() => {
                diag::info(code::PART_FS_UNSUPPORTED, v.describe());
            }
            _ => {}
        }
    }
    if !out.is_empty() {
        diag::info(code::PART_LISTED, out.iter().map(|v| v.describe()).collect::<Vec<_>>().join("; "));
    }
    if !out.iter().any(|v| v.kind.is_readable()) {
        diag::warn(code::PART_NONE_READABLE, label);
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An image of `sectors` zeroed sectors.
    pub fn blank(sectors: usize) -> Vec<u8> {
        vec![0u8; sectors * 512]
    }

    /// Writes an NTFS boot-sector signature at `offset`.
    pub fn stamp_ntfs(img: &mut [u8], offset: usize) {
        img[offset + 3..offset + 11].copy_from_slice(b"NTFS    ");
    }

    /// Writes an ext superblock magic at `offset`.
    pub fn stamp_ext(img: &mut [u8], offset: usize) {
        img[offset + 0x438..offset + 0x43a].copy_from_slice(&EXT_SUPER_MAGIC.to_le_bytes());
    }

    /// An MBR entry.
    pub fn mbr_entry(img: &mut [u8], slot: usize, ptype: u8, lba: u32, sectors: u32) {
        let e = 446 + slot * 16;
        img[e + 4] = ptype;
        img[e + 8..e + 12].copy_from_slice(&lba.to_le_bytes());
        img[e + 12..e + 16].copy_from_slice(&sectors.to_le_bytes());
        img[510] = 0x55;
        img[511] = 0xAA;
    }

    /// A GPT with the given (type guid, first lba, last lba, name) entries, 512-byte sectors.
    pub fn gpt(img: &mut [u8], entries: &[([u8; 16], u64, u64, &str)]) {
        mbr_entry(img, 0, 0xEE, 1, (img.len() / 512 - 1) as u32);
        let h = 512;
        img[h..h + 8].copy_from_slice(b"EFI PART");
        img[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes());
        img[h + 80..h + 84].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        img[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes());
        for (i, (g, first, last, name)) in entries.iter().enumerate() {
            let e = 1024 + i * 128;
            img[e..e + 16].copy_from_slice(g);
            img[e + 16] = 1;
            img[e + 32..e + 40].copy_from_slice(&first.to_le_bytes());
            img[e + 40..e + 48].copy_from_slice(&last.to_le_bytes());
            for (j, u) in name.encode_utf16().enumerate().take(35) {
                img[e + 56 + j * 2..e + 58 + j * 2].copy_from_slice(&u.to_le_bytes());
            }
        }
    }

    fn quiet() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
    }

    #[test]
    fn sniff_every_signature() {
        let mut img = blank(300);
        assert_eq!(sniff(&SharedReader::from_bytes(img.clone()), 0), VolumeKind::Unknown);
        stamp_ntfs(&mut img, 0);
        assert_eq!(sniff(&SharedReader::from_bytes(img.clone()), 0), VolumeKind::Ntfs);
        let mut img = blank(300);
        img[3..11].copy_from_slice(b"-FVE-FS-");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::BitLocker);
        let mut img = blank(300);
        img[3..11].copy_from_slice(b"EXFAT   ");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::ExFat);
        let mut img = blank(300);
        img[3..7].copy_from_slice(b"ReFS");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::ReFs);
        let mut img = blank(300);
        img[..4].copy_from_slice(b"XFSB");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::Xfs);
        let mut img = blank(300);
        img[..6].copy_from_slice(b"LUKS\xba\xbe");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::Luks);
        let mut img = blank(300);
        stamp_ext(&mut img, 0);
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::Ext);
        let mut img = blank(300);
        img[512..520].copy_from_slice(b"LABELONE");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::Lvm);
        let mut img = blank(300);
        img[0x10040..0x10048].copy_from_slice(b"_BHRfS_M");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::Btrfs);
        let mut img = blank(300);
        img[0x400..0x404].copy_from_slice(&[0x10, 0x20, 0xF5, 0xF2]);
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::F2fs);
        let mut img = blank(300);
        img[0x400..0x402].copy_from_slice(b"H+");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::HfsPlus);
        let mut img = blank(300);
        img[32..36].copy_from_slice(b"NXSB");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::Apfs);
        let mut img = blank(300);
        img[4096 - 10..4096].copy_from_slice(b"SWAPSPACE2");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::Swap);
        let mut img = blank(300);
        img[0x36..0x3b].copy_from_slice(b"FAT16");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::Fat);
        let mut img = blank(300);
        img[0x52..0x57].copy_from_slice(b"FAT32");
        assert_eq!(sniff(&SharedReader::from_bytes(img), 0), VolumeKind::Fat);
        assert!(VolumeKind::Lvm.is_readable() && VolumeKind::Fat.is_readable() && VolumeKind::ExFat.is_readable() && !VolumeKind::Unknown.is_readable());
        assert!(VolumeKind::Luks.is_encrypted() && !VolumeKind::Ntfs.is_encrypted());
        assert_eq!(VolumeKind::Ext.label(), "ext2/3/4");
    }

    #[test]
    fn mbr_with_two_partitions() {
        quiet();
        let mut img = blank(600);
        mbr_entry(&mut img, 0, 0x07, 64, 200);
        mbr_entry(&mut img, 1, 0x83, 300, 200);
        stamp_ntfs(&mut img, 64 * 512);
        stamp_ext(&mut img, 300 * 512);
        let vols = list_volumes(&SharedReader::from_bytes(img));
        assert_eq!(vols.len(), 2);
        assert_eq!(vols[0], Volume { index: 0, offset: 64 * 512, size: 200 * 512, kind: VolumeKind::Ntfs, table: Table::Mbr, type_id: "07".into(), name: None });
        assert_eq!(vols[1].kind, VolumeKind::Ext);
        assert_eq!(vols[1].index, 1);
        assert_eq!(vols[1].dir_name(), "partition_1");
        assert!(vols[0].describe().contains("NTFS at 0x8000"));
        assert!(crate::diag::has(code::PART_LISTED));
        assert!(!crate::diag::has(code::PART_NONE_READABLE));
        let r = SharedReader::from_bytes(blank(600));
        assert_eq!(vols[0].reader(&r).len(), 200 * 512);
    }

    #[test]
    fn mbr_extended_chain_and_loop_guard() {
        quiet();
        let mut img = blank(2000);
        mbr_entry(&mut img, 0, 0x07, 64, 100);
        stamp_ntfs(&mut img, 64 * 512);
        // Extended at 500, two logical partitions: EBR at 500 -> data at 501 (50 sectors), next EBR at 600 -> data 601.
        mbr_entry(&mut img, 1, 0x05, 500, 1000);
        let ebr1 = 500 * 512;
        img[ebr1 + 510] = 0x55;
        img[ebr1 + 511] = 0xAA;
        img[ebr1 + 446 + 4] = 0x83;
        img[ebr1 + 446 + 8..ebr1 + 446 + 12].copy_from_slice(&1u32.to_le_bytes());
        img[ebr1 + 446 + 12..ebr1 + 446 + 16].copy_from_slice(&50u32.to_le_bytes());
        img[ebr1 + 462 + 4] = 0x05;
        img[ebr1 + 462 + 8..ebr1 + 462 + 12].copy_from_slice(&100u32.to_le_bytes());
        stamp_ext(&mut img, 501 * 512);
        let ebr2 = 600 * 512;
        img[ebr2 + 510] = 0x55;
        img[ebr2 + 511] = 0xAA;
        img[ebr2 + 446 + 4] = 0x07;
        img[ebr2 + 446 + 8..ebr2 + 446 + 12].copy_from_slice(&1u32.to_le_bytes());
        img[ebr2 + 446 + 12..ebr2 + 446 + 16].copy_from_slice(&50u32.to_le_bytes());
        stamp_ntfs(&mut img, 601 * 512);
        // Make the second EBR point back at the first: a loop.
        img[ebr2 + 462 + 4] = 0x05;
        img[ebr2 + 462 + 8..ebr2 + 462 + 12].copy_from_slice(&0u32.to_le_bytes());
        let vols = list_volumes(&SharedReader::from_bytes(img.clone()));
        assert_eq!(vols.len(), 3, "{vols:?}");
        assert_eq!(vols[1].table, Table::MbrLogical);
        assert_eq!(vols[1].offset, 501 * 512);
        assert_eq!(vols[1].kind, VolumeKind::Ext);
        assert_eq!(vols[2].offset, 601 * 512);
        assert_eq!(vols[2].kind, VolumeKind::Ntfs);
        assert!(crate::diag::has(code::PART_MBR_EXTENDED));
        assert!(!crate::diag::has(code::PART_EBR_LOOP), "a zero next pointer ends the chain cleanly");
        // Now a real loop: EBR2 points at EBR1 (offset 0 from the extended start).
        crate::diag::drain();
        img[ebr2 + 462 + 8..ebr2 + 462 + 12].copy_from_slice(&0u32.to_le_bytes());
        img[ebr2 + 462 + 4] = 0x05;
        // next lba 0 is treated as end; use a pointer to itself instead
        img[ebr2 + 462 + 8..ebr2 + 462 + 12].copy_from_slice(&100u32.to_le_bytes());
        let vols = list_volumes(&SharedReader::from_bytes(img));
        assert_eq!(vols.len(), 3);
        assert!(crate::diag::has(code::PART_EBR_LOOP));
    }

    #[test]
    fn gpt_with_names_and_kinds() {
        quiet();
        let mut img = blank(1200);
        gpt(&mut img, &[(GPT_EFI_SYSTEM_GUID, 34, 233, "EFI System"), (GPT_BASIC_DATA_GUID, 300, 699, "Basic data partition"), (GPT_LINUX_LVM_GUID, 700, 1100, "")]);
        stamp_ntfs(&mut img, 300 * 512);
        img[700 * 512 + 512..700 * 512 + 520].copy_from_slice(b"LABELONE");
        img[34 * 512 + 0x36..34 * 512 + 0x3b].copy_from_slice(b"FAT32");
        let vols = list_volumes(&SharedReader::from_bytes(img));
        assert_eq!(vols.len(), 3);
        assert_eq!(vols[0].kind, VolumeKind::Fat);
        assert_eq!(vols[0].type_id, "efi system");
        assert_eq!(vols[0].name.as_deref(), Some("EFI System"));
        assert_eq!(vols[1].kind, VolumeKind::Ntfs);
        assert_eq!(vols[1].size, 400 * 512);
        assert_eq!(vols[1].table, Table::Gpt);
        assert_eq!(vols[2].kind, VolumeKind::Lvm);
        assert_eq!(vols[2].name, None);
        assert!(!crate::diag::has(code::PART_FS_UNSUPPORTED), "FAT is read now");
    }

    #[test]
    fn gpt_backup_header_and_bad_header() {
        quiet();
        let mut img = blank(1200);
        gpt(&mut img, &[(GPT_BASIC_DATA_GUID, 300, 699, "x")]);
        stamp_ntfs(&mut img, 300 * 512);
        // Kill the primary header, put a copy at the last sector pointing at the same entries.
        let hdr: Vec<u8> = img[512..604].to_vec();
        img[512..604].fill(0);
        let last = img.len() - 512;
        img[last..last + 92].copy_from_slice(&hdr);
        let vols = list_volumes(&SharedReader::from_bytes(img.clone()));
        assert_eq!(vols.len(), 1);
        assert!(crate::diag::has(code::PART_GPT_BACKUP_USED));
        // No header anywhere: protective MBR only, then the fallback finds NTFS at... nowhere common.
        crate::diag::drain();
        img[last..last + 92].fill(0);
        let vols = list_volumes(&SharedReader::from_bytes(img.clone()));
        assert!(crate::diag::has(code::PART_PROTECTIVE_MBR_ONLY));
        assert!(vols.is_empty());
        assert!(crate::diag::has(code::PART_NONE_READABLE));
        // A header with an absurd entry count.
        crate::diag::drain();
        img[512..604].copy_from_slice(&hdr);
        img[512 + 80..512 + 84].copy_from_slice(&5000u32.to_le_bytes());
        let vols = list_volumes(&SharedReader::from_bytes(img));
        assert!(crate::diag::has(code::PART_GPT_HEADER_BAD));
        assert!(vols.is_empty());
    }

    #[test]
    fn gpt_entry_past_the_image_is_skipped() {
        quiet();
        let mut img = blank(1200);
        gpt(&mut img, &[(GPT_BASIC_DATA_GUID, 5000, 6000, "far"), (GPT_BASIC_DATA_GUID, 300, 5000, "clipped")]);
        stamp_ntfs(&mut img, 300 * 512);
        let vols = list_volumes(&SharedReader::from_bytes(img));
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].size, 900 * 512, "clipped to the image");
        assert!(crate::diag::has(code::PART_GPT_ENTRY_PAST_END));
    }

    #[test]
    fn whole_image_volume_and_fallback_offsets() {
        quiet();
        let mut img = blank(300);
        stamp_ext(&mut img, 0);
        let vols = list_volumes(&SharedReader::from_bytes(img));
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].table, Table::Whole);
        assert_eq!(vols[0].kind, VolumeKind::Ext);
        assert!(crate::diag::has(code::PART_NO_TABLE));
        // MBR with a bogus entry, NTFS actually at 1 MB.
        crate::diag::drain();
        let mut img = blank(3000);
        mbr_entry(&mut img, 0, 0x07, 100_000, 10);
        stamp_ntfs(&mut img, 1024 * 1024);
        let vols = list_volumes(&SharedReader::from_bytes(img));
        assert!(crate::diag::has(code::PART_MBR_ENTRY_PAST_END));
        assert!(crate::diag::has(code::PART_FALLBACK_OFFSET));
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].table, Table::Fallback);
        assert_eq!(vols[0].offset, 1024 * 1024);
        // Nothing at all.
        crate::diag::drain();
        let vols = list_volumes(&SharedReader::from_bytes(blank(100)));
        assert!(vols.is_empty());
        assert!(crate::diag::has(code::PART_NONE_READABLE));
    }

    #[test]
    fn encrypted_and_overlapping_volumes_are_reported() {
        quiet();
        let mut img = blank(600);
        mbr_entry(&mut img, 0, 0x07, 64, 300);
        mbr_entry(&mut img, 1, 0x83, 200, 100);
        img[64 * 512 + 3..64 * 512 + 11].copy_from_slice(b"-FVE-FS-");
        img[200 * 512..200 * 512 + 6].copy_from_slice(b"LUKS\xba\xbe");
        let vols = list_volumes(&SharedReader::from_bytes(img));
        assert_eq!(vols.len(), 2);
        assert!(crate::diag::has(code::PART_BITLOCKER));
        assert!(crate::diag::has(code::PART_LUKS));
        assert!(crate::diag::has(code::PART_OVERLAP));
        assert!(crate::diag::has(code::PART_NONE_READABLE));
    }

    #[test]
    fn guid_text_and_sizes() {
        assert_eq!(guid_text(&GPT_BASIC_DATA_GUID), "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7");
        assert_eq!(gpt_type_name(&GPT_LINUX_FS_GUID), "linux filesystem");
        assert_eq!(gpt_type_name(&[1u8; 16]), "01010101-0101-0101-0101-010101010101");
        assert_eq!(human_size(17), "17 B");
        assert_eq!(human_size(4096), "4.0 KB");
        assert_eq!(human_size(1_610_612_736), "1.5 GB");
        assert_eq!(Table::MbrLogical.label(), "ebr");
    }
}
