//! Deleted files and previous versions on ext3/ext4, read from what the file system
//! left behind: the jbd2 journal keeps copies of metadata blocks (inode tables and
//! directory blocks) for every transaction until the area wraps, and a directory block
//! keeps the bytes of a removed entry off its `rec_len` chain until they are overwritten.
//! A name that is in a journal copy or in slack but not in the live tree is a deleted
//! file; a name that now points at another inode was replaced by a rename, and the old
//! inode is a previous version; a live inode whose journal copy points at other, still
//! free blocks was rewritten and the old content is a previous version too.
//!
//! Ported from faramir's `ext_journal`, generalised to every path and made streamable.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::diag;
use crate::error::{Error, Result};
use crate::source::SharedReader;

pub mod code {
    crate::codes! {
        EXT_RECOVER_GEOMETRY = 458, "the superblock could not be parsed for recovery (bad magic, impossible geometry); the live tree still works, deleted files cannot be listed";
        EXT_JOURNAL_INODE = 459, "the journal inode is unreadable or is not a file (an external journal, or ext2 without one); only directory slack is searched for deleted names";
        EXT_JOURNAL_SUPERBLOCK = 460, "the journal file does not start with a jbd2 superblock; the journal was skipped";
        EXT_JOURNAL_BLOCK_SIZE = 461, "the journal's block size differs from the file system's; the journal was skipped";
        EXT_JOURNAL_SCANNED = 462, "the journal area was walked: blocks, descriptors, commits, revokes, block copies found";
        EXT_LIVE_TREE_TRUNCATED = 463, "the live directory tree has more directories than the limit; names under the directories not walked cannot be matched";
        EXT_DELETED_FOUND = 464, "deleted files and previous versions were found: how many of each, how many with content still readable";
        EXT_BLOCKS_REUSED = 465, "a deleted file's blocks are allocated again, so its old content is gone; the entry is listed without content";
        EXT_RECOVER_READ = 466, "reading a recovered file's blocks failed part-way; the bytes read so far were kept";
        EXT_TOO_MANY_GROUPS = 467, "the superblock declares more block groups than the limit; the volume is refused for recovery";
        EXT_JOURNAL_TRUNCATED = 468, "the journal is longer than the block limit; the part beyond was not read";
        EXT_RECOVER_NOT_REGULAR = 469, "the inode of a deleted name is not a regular file in its journal copy (a directory, a device); only regular files are recovered";
    }
}

const SUPERBLOCK_OFFSET: u64 = 1024;
const EXT_MAGIC: u16 = 0xEF53;
const EXTENT_MAGIC: u16 = 0xF30A;
const INCOMPAT_64BIT: u32 = 0x80;
const INODE_EXTENTS_FL: u32 = 0x0008_0000;
const INODE_INLINE_DATA_FL: u32 = 0x1000_0000;
const ROOT_INO: u32 = 2;
const JOURNAL_INO_DEFAULT: u32 = 8;
const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR: u32 = 1;
const JBD2_COMMIT: u32 = 2;
const JBD2_SUPERBLOCK_V1: u32 = 3;
const JBD2_SUPERBLOCK_V2: u32 = 4;
const JBD2_REVOKE: u32 = 5;
const JBD2_INCOMPAT_64BIT: u32 = 2;
const JBD2_INCOMPAT_CSUM_V2: u32 = 8;
const JBD2_INCOMPAT_CSUM_V3: u32 = 0x10;
const TAG_ESCAPE: u32 = 1;
const TAG_SAME_UUID: u32 = 2;
const TAG_LAST: u32 = 8;

/// Directories walked in the live tree before giving up.
pub const MAX_DIRS: usize = 500_000;
/// Journal blocks read before giving up.
pub const MAX_JOURNAL_BLOCKS: u64 = 1 << 20;
/// Blocks of one file whose allocation is checked (beyond it the file counts as reused).
pub const MAX_CHECK_BLOCKS: usize = 1 << 18;
/// Previous versions kept per live file.
pub const MAX_VERSIONS: usize = 8;

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u16be(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

/// What the superblock says about the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Geometry {
    pub block_size: u64,
    pub blocks_count: u64,
    pub inodes_count: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub first_data_block: u32,
    pub desc_size: u16,
    pub journal_ino: u32,
    pub feature_incompat: u32,
    pub volume_name: String,
}

impl Geometry {
    /// Parses the 1024-byte superblock.
    pub fn parse(sb: &[u8]) -> Result<Self> {
        let bad = |m: String| Error::new(code::EXT_RECOVER_GEOMETRY, m);
        if sb.len() < 1024 {
            return Err(bad("superblock shorter than 1024 bytes".into()));
        }
        if u16le(sb, 0x38) != EXT_MAGIC {
            return Err(bad(format!("bad ext magic {:#06x}", u16le(sb, 0x38))));
        }
        let log = u32le(sb, 0x18);
        if log > 6 {
            return Err(bad(format!("implausible log block size {log}")));
        }
        let feature_incompat = u32le(sb, 0x60);
        let blocks_lo = u32le(sb, 0x04) as u64;
        let blocks_hi = if feature_incompat & INCOMPAT_64BIT != 0 { u32le(sb, 0x150) as u64 } else { 0 };
        let rev = u32le(sb, 0x4c);
        let inode_size = if rev >= 1 { u16le(sb, 0x58) } else { 128 };
        let desc_size = if feature_incompat & INCOMPAT_64BIT != 0 { u16le(sb, 0xfe).max(32) } else { 32 };
        let g = Geometry {
            block_size: 1024u64 << log,
            blocks_count: blocks_lo | (blocks_hi << 32),
            inodes_count: u32le(sb, 0x00),
            blocks_per_group: u32le(sb, 0x20),
            inodes_per_group: u32le(sb, 0x28),
            inode_size,
            first_data_block: u32le(sb, 0x14),
            desc_size,
            journal_ino: if rev >= 1 { u32le(sb, 0xe0) } else { JOURNAL_INO_DEFAULT },
            feature_incompat,
            volume_name: String::from_utf8_lossy(&sb[0x78..0x88]).trim_end_matches('\0').to_string(),
        };
        if g.blocks_per_group == 0 || g.inodes_per_group == 0 || !(128..=4096).contains(&g.inode_size) || g.blocks_count == 0 {
            return Err(bad(format!("implausible geometry: {} blocks/group, {} inodes/group, inode size {}, {} blocks", g.blocks_per_group, g.inodes_per_group, g.inode_size, g.blocks_count)));
        }
        Ok(g)
    }

    /// Number of block groups.
    pub fn group_count(&self) -> u64 {
        (self.blocks_count - self.first_data_block as u64).div_ceil(self.blocks_per_group as u64)
    }

    /// Blocks an inode table spans.
    pub fn inode_table_blocks(&self) -> u64 {
        (self.inodes_per_group as u64 * self.inode_size as u64).div_ceil(self.block_size)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
}

/// The volume as seen through its metadata, with a block cache.
pub struct Volume {
    reader: SharedReader,
    pub geo: Geometry,
    pub groups: Vec<Group>,
    block_cache: HashMap<u64, Vec<u8>>,
}

/// A raw inode (the fields recovery needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawInode {
    pub ino: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub crtime: Option<u32>,
    pub links: u16,
    pub flags: u32,
    pub generation: u32,
    pub block: [u8; 60],
}

impl RawInode {
    /// Parses an inode of at least 128 bytes.
    pub fn parse(ino: u32, b: &[u8]) -> Option<RawInode> {
        if b.len() < 128 {
            return None;
        }
        let mut block = [0u8; 60];
        block.copy_from_slice(&b[40..100]);
        let extra = if b.len() >= 132 { u16le(b, 128) as usize } else { 0 };
        let crtime = (b.len() >= 148 && extra >= 20).then(|| u32le(b, 144));
        Some(RawInode {
            ino,
            mode: u16le(b, 0),
            uid: u16le(b, 2) as u32 | ((if b.len() >= 122 { u16le(b, 120) } else { 0 } as u32) << 16),
            gid: u16le(b, 24) as u32 | ((if b.len() >= 124 { u16le(b, 122) } else { 0 } as u32) << 16),
            size: u32le(b, 4) as u64 | ((u32le(b, 108) as u64) << 32),
            atime: u32le(b, 8),
            ctime: u32le(b, 12),
            mtime: u32le(b, 16),
            dtime: u32le(b, 20),
            crtime,
            links: u16le(b, 26),
            flags: u32le(b, 32),
            generation: u32le(b, 100),
            block,
        })
    }

    pub fn is_regular(&self) -> bool {
        self.mode & 0xF000 == 0x8000
    }
    pub fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & 0xF000 == 0xA000
    }
    pub fn uses_extents(&self) -> bool {
        self.flags & INODE_EXTENTS_FL != 0
    }
    pub fn inline_data(&self) -> bool {
        self.flags & INODE_INLINE_DATA_FL != 0
    }
    /// Looks like an inode that is or was in use (a zeroed slot is not).
    pub fn plausible(&self) -> bool {
        self.mode != 0 && (self.is_regular() || self.is_dir() || self.is_symlink()) && self.mtime != 0
    }
}

/// `(logical block, length, physical block)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub logical: u32,
    pub len: u32,
    pub physical: u64,
}

type ExtentEntry = (u32, u32, u64);

/// Parses an extent node: its depth and entries (leaves, or index pointers with len 0).
pub fn parse_extent_node(b: &[u8]) -> Option<(u16, Vec<ExtentEntry>)> {
    if b.len() < 12 || u16le(b, 0) != EXTENT_MAGIC {
        return None;
    }
    let entries = u16le(b, 2) as usize;
    let depth = u16le(b, 6);
    if entries > (b.len() - 12) / 12 || entries > 340 {
        return None;
    }
    let mut out = Vec::with_capacity(entries);
    for i in 0..entries {
        let e = &b[12 + i * 12..24 + i * 12];
        if depth == 0 {
            let raw_len = u16le(e, 4) as u32;
            let len = if raw_len > 32768 { raw_len - 32768 } else { raw_len };
            let phys = u32le(e, 8) as u64 | ((u16le(e, 6) as u64) << 32);
            out.push((u32le(e, 0), len, phys));
        } else {
            let leaf = u32le(e, 4) as u64 | ((u16le(e, 8) as u64) << 32);
            out.push((u32le(e, 0), 0, leaf));
        }
    }
    Some((depth, out))
}

impl Volume {
    /// Opens the volume whose first byte is the start of the partition.
    pub fn open(reader: SharedReader) -> Result<Self> {
        let mut sb = vec![0u8; 1024];
        reader.read_at(SUPERBLOCK_OFFSET, &mut sb).map_err(|e| Error::recorded(code::EXT_RECOVER_GEOMETRY, format!("superblock: {e}")))?;
        let geo = Geometry::parse(&sb).map_err(|e| Error::recorded(e.code, e.msg))?;
        let mut v = Volume { reader, geo, groups: Vec::new(), block_cache: HashMap::new() };
        let count = v.geo.group_count();
        if count > 1 << 20 {
            return Err(Error::recorded(code::EXT_TOO_MANY_GROUPS, format!("{count} block groups")));
        }
        let table_block = v.geo.first_data_block as u64 + 1;
        let per_block = v.geo.block_size / v.geo.desc_size as u64;
        let mut groups = Vec::with_capacity(count as usize);
        for g in 0..count {
            let blk = v.read_block(table_block + g / per_block)?;
            let o = ((g % per_block) * v.geo.desc_size as u64) as usize;
            let d = &blk[o..o + v.geo.desc_size as usize];
            let hi = |off: usize| if v.geo.desc_size >= 64 { u32le(d, off) as u64 } else { 0 };
            groups.push(Group { block_bitmap: u32le(d, 0) as u64 | (hi(32) << 32), inode_bitmap: u32le(d, 4) as u64 | (hi(36) << 32), inode_table: u32le(d, 8) as u64 | (hi(40) << 32) });
        }
        v.groups = groups;
        Ok(v)
    }

    /// One block, cached.
    pub fn read_block(&mut self, block: u64) -> Result<Vec<u8>> {
        if block >= self.geo.blocks_count {
            return Err(Error::new(code::EXT_RECOVER_READ, format!("block {block} beyond the volume")));
        }
        if let Some(b) = self.block_cache.get(&block) {
            return Ok(b.clone());
        }
        let mut buf = vec![0u8; self.geo.block_size as usize];
        self.reader.read_at(block * self.geo.block_size, &mut buf).map_err(|e| Error::new(code::EXT_RECOVER_READ, format!("block {block}: {e}")))?;
        if self.block_cache.len() < 4096 {
            self.block_cache.insert(block, buf.clone());
        }
        Ok(buf)
    }

    /// Several contiguous blocks, uncached.
    pub fn read_blocks(&mut self, first: u64, count: u64) -> Result<Vec<u8>> {
        if first + count > self.geo.blocks_count {
            return Err(Error::new(code::EXT_RECOVER_READ, format!("blocks {first}+{count} beyond the volume")));
        }
        let mut buf = vec![0u8; (count * self.geo.block_size) as usize];
        self.reader.read_at(first * self.geo.block_size, &mut buf).map_err(|e| Error::new(code::EXT_RECOVER_READ, format!("blocks {first}+{count}: {e}")))?;
        Ok(buf)
    }

    fn inode_location(&self, ino: u32) -> Option<(usize, u64)> {
        if ino == 0 || ino > self.geo.inodes_count {
            return None;
        }
        let idx = (ino - 1) as u64;
        let group = (idx / self.geo.inodes_per_group as u64) as usize;
        let within = idx % self.geo.inodes_per_group as u64;
        Some((group, within * self.geo.inode_size as u64))
    }

    /// The live inode.
    pub fn read_inode(&mut self, ino: u32) -> Option<RawInode> {
        let (group, off) = self.inode_location(ino)?;
        let table = self.groups.get(group)?.inode_table;
        let bs = self.geo.block_size;
        let blk = self.read_block(table + off / bs).ok()?;
        let o = (off % bs) as usize;
        RawInode::parse(ino, &blk[o..o + self.geo.inode_size as usize])
    }

    /// Every extent of an inode, index nodes followed, in logical order.
    pub fn extents(&mut self, inode: &RawInode) -> Vec<Extent> {
        let mut out = Vec::new();
        if inode.inline_data() {
            return out;
        }
        if inode.uses_extents() {
            let mut stack: Vec<(Vec<u8>, usize)> = vec![(inode.block.to_vec(), 0)];
            let mut visited = 0usize;
            while let Some((node, depth_guard)) = stack.pop() {
                visited += 1;
                if visited > 4096 || depth_guard > 6 {
                    break;
                }
                let Some((depth, entries)) = parse_extent_node(&node) else { continue };
                for (logical, len, phys) in entries {
                    if depth == 0 {
                        if len > 0 && phys < self.geo.blocks_count {
                            out.push(Extent { logical, len, physical: phys });
                        }
                    } else if let Ok(b) = self.read_block(phys) {
                        stack.push((b, depth_guard + 1));
                    }
                }
            }
        } else {
            for i in 0..12 {
                let p = u32le(&inode.block, i * 4) as u64;
                if p != 0 && p < self.geo.blocks_count {
                    out.push(Extent { logical: i as u32, len: 1, physical: p });
                }
            }
            let ind = u32le(&inode.block, 48) as u64;
            if ind != 0 && ind < self.geo.blocks_count {
                if let Ok(b) = self.read_block(ind) {
                    for (i, c) in b.chunks_exact(4).enumerate() {
                        let p = u32le(c, 0) as u64;
                        if p != 0 && p < self.geo.blocks_count {
                            out.push(Extent { logical: 12 + i as u32, len: 1, physical: p });
                        }
                    }
                }
            }
        }
        out.sort_by_key(|e| e.logical);
        out
    }

    /// Physical blocks in logical order, capped.
    pub fn block_list(&mut self, inode: &RawInode, cap: usize) -> Vec<u64> {
        let mut blocks = Vec::new();
        for e in self.extents(inode) {
            for i in 0..e.len as u64 {
                if blocks.len() >= cap {
                    return blocks;
                }
                blocks.push(e.physical + i);
            }
        }
        blocks
    }

    /// Is this block allocated right now, per the live block bitmap?
    pub fn block_allocated(&mut self, block: u64) -> Option<bool> {
        let rel = block.checked_sub(self.geo.first_data_block as u64)?;
        let group = (rel / self.geo.blocks_per_group as u64) as usize;
        let bit = (rel % self.geo.blocks_per_group as u64) as usize;
        let bitmap_block = self.groups.get(group)?.block_bitmap;
        let bm = self.read_block(bitmap_block).ok()?;
        bm.get(bit / 8).map(|b| b & (1 << (bit % 8)) != 0)
    }

    /// Which inode table `(group, first inode number)` a block belongs to, if any.
    pub fn inode_table_owner(&self, block: u64) -> Option<(usize, u32)> {
        let span = self.geo.inode_table_blocks();
        for (g, grp) in self.groups.iter().enumerate() {
            if block >= grp.inode_table && block < grp.inode_table + span {
                let per_block = (self.geo.block_size / self.geo.inode_size as u64) as u32;
                let first = g as u32 * self.geo.inodes_per_group + ((block - grp.inode_table) as u32) * per_block + 1;
                return Some((g, first));
            }
        }
        None
    }

    /// Inodes stored in a copy of an inode table block.
    pub fn inodes_in_block(&self, block: u64, data: &[u8]) -> Vec<RawInode> {
        let Some((_, first)) = self.inode_table_owner(block) else { return Vec::new() };
        let isz = self.geo.inode_size as usize;
        data.chunks_exact(isz).enumerate().filter_map(|(i, chunk)| RawInode::parse(first + i as u32, chunk)).filter(|ino| ino.plausible() && ino.ino <= self.geo.inodes_count).collect()
    }
}

/// A directory entry on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub ino: u32,
    pub name: String,
    pub file_type: u8,
    /// Byte offset of the entry in its block.
    pub offset: usize,
}

/// Entries of a directory block following the `rec_len` chain; `None` when the block does
/// not look like a directory block.
pub fn parse_dir_block(b: &[u8]) -> Option<Vec<DirEntry>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut live = 0usize;
    while off + 8 <= b.len() {
        let ino = u32le(b, off);
        let rec_len = u16le(b, off + 4) as usize;
        let name_len = b[off + 6] as usize;
        let ftype = b[off + 7];
        if rec_len < 8 || !rec_len.is_multiple_of(4) || off + rec_len > b.len() || 8 + name_len > rec_len {
            return None;
        }
        if ino != 0 {
            if name_len == 0 || ftype > 7 && ftype != 0xDE {
                return None;
            }
            let raw = &b[off + 8..off + 8 + name_len];
            if raw.iter().any(|&c| c == 0 || c == b'/') {
                return None;
            }
            out.push(DirEntry { ino, name: String::from_utf8_lossy(raw).to_string(), file_type: ftype, offset: off });
            live += 1;
        }
        off += rec_len;
    }
    (off == b.len() && live > 0).then_some(out)
}

/// Entries off the `rec_len` chain: what `rm` leaves behind when the kernel does not zero
/// them.
pub fn slack_dir_entries(b: &[u8], chain: &[DirEntry]) -> Vec<DirEntry> {
    let on_chain: HashSet<usize> = chain.iter().map(|e| e.offset).collect();
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 12 <= b.len() {
        if !on_chain.contains(&off) {
            let ino = u32le(b, off);
            let rec_len = u16le(b, off + 4) as usize;
            let name_len = b[off + 6] as usize;
            let ftype = b[off + 7];
            if ino != 0 && rec_len >= 8 + name_len && rec_len.is_multiple_of(4) && off + 8 + name_len <= b.len() && (1..=255).contains(&name_len) && ftype <= 7 {
                let raw = &b[off + 8..off + 8 + name_len];
                if raw.iter().all(|&c| c >= 0x20 && c != b'/' && c != 0x7f) {
                    out.push(DirEntry { ino, name: String::from_utf8_lossy(raw).to_string(), file_type: ftype, offset: off });
                }
            }
        }
        off += 4;
    }
    out
}

/// Directory inodes, their paths, their blocks and their live entries.
#[derive(Debug, Default)]
pub struct LiveTree {
    pub dir_path: HashMap<u32, String>,
    pub block_owner: HashMap<u64, u32>,
    pub entries: HashMap<u32, HashMap<String, u32>>,
    /// `(path, inode)` of regular files.
    pub files: HashMap<String, u32>,
    pub dirs_walked: usize,
    pub truncated: bool,
}

impl LiveTree {
    /// Walks every directory from the root.
    pub fn walk(vol: &mut Volume) -> LiveTree {
        let mut t = LiveTree::default();
        let mut queue: Vec<(u32, String)> = vec![(ROOT_INO, String::new())];
        let mut seen: HashSet<u32> = HashSet::new();
        while let Some((ino, path)) = queue.pop() {
            if !seen.insert(ino) {
                continue;
            }
            if t.dirs_walked >= MAX_DIRS {
                t.truncated = true;
                diag::warn(code::EXT_LIVE_TREE_TRUNCATED, format!("{} directories", t.dirs_walked));
                break;
            }
            let Some(inode) = vol.read_inode(ino) else { continue };
            if !inode.is_dir() || inode.inline_data() {
                continue;
            }
            t.dirs_walked += 1;
            t.dir_path.insert(ino, if path.is_empty() { "/".to_string() } else { path.clone() });
            let mut names: HashMap<String, u32> = HashMap::new();
            for blk in vol.block_list(&inode, MAX_CHECK_BLOCKS) {
                t.block_owner.insert(blk, ino);
                let Ok(data) = vol.read_block(blk) else { continue };
                let Some(entries) = parse_dir_block(&data) else { continue };
                for e in entries {
                    if e.name == "." || e.name == ".." {
                        continue;
                    }
                    let child = format!("{path}/{}", e.name);
                    names.insert(e.name.clone(), e.ino);
                    match e.file_type {
                        2 => queue.push((e.ino, child)),
                        1 => {
                            t.files.insert(child, e.ino);
                        }
                        0 => {
                            if let Some(ci) = vol.read_inode(e.ino) {
                                if ci.is_dir() {
                                    queue.push((e.ino, child));
                                } else if ci.is_regular() {
                                    t.files.insert(child, e.ino);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            t.entries.insert(ino, names);
        }
        t
    }
}

/// What the journal superblock and the walk said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalInfo {
    pub block_size: u32,
    pub max_len: u32,
    pub first: u32,
    pub sequence: u32,
    pub start: u32,
    pub incompat: u32,
    pub blocks_scanned: u32,
    pub descriptors: usize,
    pub commits: usize,
    pub revokes: usize,
    pub copies: usize,
}

/// One block copy found in the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockCopy {
    pub sequence: u32,
    pub fs_block: u64,
    /// Physical block holding the copy.
    pub journal_phys: u64,
    pub escaped: bool,
}

/// Size of a descriptor tag for the journal's feature set.
pub fn tag_size(incompat: u32) -> usize {
    if incompat & JBD2_INCOMPAT_CSUM_V3 != 0 {
        16
    } else if incompat & JBD2_INCOMPAT_64BIT != 0 {
        12
    } else {
        8
    }
}

/// Tags of a descriptor block: `(fs block, flags)` in order.
pub fn parse_descriptor_tags(b: &[u8], incompat: u32) -> Vec<(u64, u32)> {
    let ts = tag_size(incompat);
    let csum_v3 = incompat & JBD2_INCOMPAT_CSUM_V3 != 0;
    let tail = if incompat & (JBD2_INCOMPAT_CSUM_V2 | JBD2_INCOMPAT_CSUM_V3) != 0 { 4 } else { 0 };
    let mut out = Vec::new();
    let mut off = 12usize;
    while off + ts <= b.len().saturating_sub(tail) {
        let t = &b[off..off + ts];
        let (blocknr, flags, high) = if csum_v3 {
            (u32be(t, 0) as u64, u32be(t, 4), u32be(t, 8) as u64)
        } else {
            let high = if ts == 12 { u32be(t, 8) as u64 } else { 0 };
            (u32be(t, 0) as u64, u16be(t, 6) as u32, high)
        };
        out.push((blocknr | (high << 32), flags));
        off += ts;
        if flags & TAG_SAME_UUID == 0 {
            off += 16;
        }
        if flags & TAG_LAST != 0 || out.len() > 4096 {
            break;
        }
    }
    out
}

/// Walks the whole journal area (old, checkpointed copies included) and lists every block
/// copy with the physical block that holds it.
pub fn scan_journal(vol: &mut Volume) -> Result<(JournalInfo, Vec<BlockCopy>)> {
    let jino = vol.geo.journal_ino;
    let inode = vol.read_inode(jino).ok_or_else(|| Error::recorded(code::EXT_JOURNAL_INODE, format!("journal inode {jino} unreadable")))?;
    if !inode.is_regular() || inode.size == 0 {
        return Err(Error::recorded(code::EXT_JOURNAL_INODE, format!("journal inode {jino} is not a file (mode {:#o}, {} bytes)", inode.mode, inode.size)));
    }
    let mut jblocks: Vec<u64> = Vec::new();
    'outer: for e in vol.extents(&inode) {
        for i in 0..e.len as u64 {
            jblocks.push(e.physical + i);
            if jblocks.len() as u64 > MAX_JOURNAL_BLOCKS {
                diag::warn(code::EXT_JOURNAL_TRUNCATED, format!("{} blocks", jblocks.len()));
                break 'outer;
            }
        }
    }
    if jblocks.is_empty() {
        return Err(Error::recorded(code::EXT_JOURNAL_INODE, "journal has no extents"));
    }
    let sb = vol.read_block(jblocks[0])?;
    if u32be(&sb, 0) != JBD2_MAGIC || !matches!(u32be(&sb, 4), JBD2_SUPERBLOCK_V1 | JBD2_SUPERBLOCK_V2) {
        return Err(Error::recorded(code::EXT_JOURNAL_SUPERBLOCK, "no jbd2 superblock in the journal file"));
    }
    let v2 = u32be(&sb, 4) == JBD2_SUPERBLOCK_V2;
    let mut info = JournalInfo { block_size: u32be(&sb, 12), max_len: u32be(&sb, 16), first: u32be(&sb, 20), sequence: u32be(&sb, 24), start: u32be(&sb, 28), incompat: if v2 { u32be(&sb, 40) } else { 0 }, ..Default::default() };
    if info.block_size as u64 != vol.geo.block_size {
        return Err(Error::recorded(code::EXT_JOURNAL_BLOCK_SIZE, format!("journal {} vs file system {}", info.block_size, vol.geo.block_size)));
    }
    let max_len = (info.max_len as usize).min(jblocks.len());
    let first = info.first as usize;
    if first >= max_len {
        return Err(Error::recorded(code::EXT_JOURNAL_SUPERBLOCK, format!("first block {first} beyond the length {max_len}")));
    }
    let mut copies = Vec::new();
    let mut j = first;
    while j < max_len {
        let Ok(b) = vol.read_block(jblocks[j]) else { break };
        info.blocks_scanned += 1;
        if u32be(&b, 0) != JBD2_MAGIC {
            j += 1;
            continue;
        }
        let kind = u32be(&b, 4);
        let seq = u32be(&b, 8);
        match kind {
            JBD2_DESCRIPTOR => {
                info.descriptors += 1;
                let tags = parse_descriptor_tags(&b, info.incompat);
                let mut data_idx = j + 1;
                for (fs_block, flags) in tags {
                    if data_idx >= max_len {
                        data_idx = first;
                    }
                    copies.push(BlockCopy { sequence: seq, fs_block, journal_phys: jblocks[data_idx], escaped: flags & TAG_ESCAPE != 0 });
                    data_idx += 1;
                }
                j = if data_idx <= j { max_len } else { data_idx };
            }
            JBD2_COMMIT => {
                info.commits += 1;
                j += 1;
            }
            JBD2_REVOKE => {
                info.revokes += 1;
                j += 1;
            }
            _ => j += 1,
        }
    }
    let blocks_count = vol.geo.blocks_count;
    copies.retain(|c| c.fs_block < blocks_count);
    info.copies = copies.len();
    diag::info(code::EXT_JOURNAL_SCANNED, format!("{} blocks, {} descriptors, {} commits, {} revokes, {} copies", info.blocks_scanned, info.descriptors, info.commits, info.revokes, info.copies));
    Ok((info, copies))
}

/// Bytes of a block copy as they were in the file system (escape undone).
pub fn read_copy(vol: &mut Volume, c: &BlockCopy) -> Option<Vec<u8>> {
    let mut b = vol.read_block(c.journal_phys).ok()?;
    if c.escaped && b.len() >= 4 {
        b[..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    }
    Some(b)
}

/// What kind of recovered file this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveredKind {
    /// Named in a journal directory copy or in directory slack, gone from the live tree.
    Deleted,
    /// An older content of a file that still exists (replaced by rename or rewritten).
    PreviousVersion,
}

/// A recovered file: metadata always, content when its blocks are still free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredFile {
    pub path: String,
    pub ino: u32,
    pub kind: RecoveredKind,
    /// Journal sequence the inode copy came from (0: slack or live slot only).
    pub seq: u32,
    /// Where the name came from.
    pub source: String,
    pub size: u64,
    pub mtime: u32,
    pub crtime: Option<u32>,
    pub dtime: Option<u32>,
    /// Inline content (small files stored in the inode).
    pub inline: Option<Vec<u8>>,
    /// Extents of the content when not inline.
    pub extents: Vec<Extent>,
    /// The old blocks are allocated again (content gone), or no inode copy was found.
    pub blocks_reused: bool,
    /// Content can be streamed.
    pub recoverable: bool,
    /// `<ino>` or `<ino>.v<seq>`, unique in the list (a `.N` suffix when needed).
    pub id: String,
}

/// Everything a recovery pass found.
#[derive(Debug, Default, Clone)]
pub struct Recovery {
    pub journal: Option<JournalInfo>,
    pub inode_copies: usize,
    pub dir_copies: usize,
    pub files: Vec<RecoveredFile>,
    pub live_dirs: usize,
    pub block_size: u64,
}

fn all_free(vol: &mut Volume, extents: &[Extent]) -> bool {
    let mut checked = 0usize;
    if extents.is_empty() {
        return false;
    }
    for e in extents {
        for i in 0..e.len as u64 {
            if checked >= MAX_CHECK_BLOCKS {
                return false;
            }
            if vol.block_allocated(e.physical + i) != Some(false) {
                return false;
            }
            checked += 1;
        }
    }
    true
}

/// Finds deleted files and previous versions everywhere on the volume.
pub fn recover(reader: SharedReader, progress: Option<&mut dyn FnMut(u64, u64)>) -> Result<Recovery> {
    let mut vol = Volume::open(reader)?;
    let mut progress = progress;
    let mut report = Recovery { block_size: vol.geo.block_size, ..Default::default() };
    let live = LiveTree::walk(&mut vol);
    report.live_dirs = live.dirs_walked;
    if let Some(p) = progress.as_deref_mut() {
        p(1, 4);
    }

    // 1. Journal copies: inodes by number, directory blocks by owner.
    let (info, copies) = match scan_journal(&mut vol) {
        Ok(x) => (Some(x.0), x.1),
        Err(_) => (None, Vec::new()),
    };
    let mut inode_copies: BTreeMap<u32, Vec<(u32, RawInode)>> = BTreeMap::new();
    let mut dir_names: BTreeMap<(u32, String), Vec<(u32, u32)>> = BTreeMap::new();
    for c in &copies {
        let Some(data) = read_copy(&mut vol, c) else { continue };
        if vol.inode_table_owner(c.fs_block).is_some() {
            let inodes = vol.inodes_in_block(c.fs_block, &data);
            if !inodes.is_empty() {
                report.inode_copies += 1;
            }
            for ino in inodes {
                inode_copies.entry(ino.ino).or_default().push((c.sequence, ino));
            }
            continue;
        }
        if let Some(entries) = parse_dir_block(&data) {
            report.dir_copies += 1;
            let owner = live.block_owner.get(&c.fs_block).copied().or_else(|| entries.iter().find(|e| e.name == ".").map(|e| e.ino));
            let Some(owner) = owner else { continue };
            for e in entries.into_iter().filter(|e| e.name != "." && e.name != "..") {
                let seen = dir_names.entry((owner, e.name)).or_default();
                match seen.iter_mut().find(|(ino, _)| *ino == e.ino) {
                    Some(slot) => slot.1 = slot.1.max(c.sequence),
                    None => seen.push((e.ino, c.sequence)),
                }
            }
        }
    }
    for v in inode_copies.values_mut() {
        v.sort_by_key(|(seq, _)| std::cmp::Reverse(*seq));
    }
    report.journal = info;
    if let Some(p) = progress.as_deref_mut() {
        p(2, 4);
    }

    // 2. Directory slack of the live tree.
    let mut owners: Vec<(u64, u32)> = live.block_owner.iter().map(|(b, o)| (*b, *o)).collect();
    owners.sort();
    let mut slack: Vec<(u32, DirEntry)> = Vec::new();
    for (blk, owner) in owners {
        let Ok(data) = vol.read_block(blk) else { continue };
        let Some(chain) = parse_dir_block(&data) else { continue };
        for e in slack_dir_entries(&data, &chain) {
            slack.push((owner, e));
        }
    }

    // 3. Names gone from the live tree, or pointing at another inode now.
    // (dir, name, ino, source, replaced, seq the name was seen at)
    let mut candidates: Vec<(u32, String, u32, String, bool, Option<u32>)> = Vec::new();
    for ((dir, name), history) in &dir_names {
        let live_ino = live.entries.get(dir).and_then(|m| m.get(name)).copied();
        for (ino, seq) in history {
            if live_ino != Some(*ino) {
                candidates.push((*dir, name.clone(), *ino, format!("journal seq {seq}"), live_ino.is_some(), Some(*seq)));
            }
        }
    }
    for (dir, e) in slack {
        let live_ino = live.entries.get(&dir).and_then(|m| m.get(&e.name)).copied();
        if live_ino != Some(e.ino) && !candidates.iter().any(|c| c.0 == dir && c.1 == e.name && c.2 == e.ino) {
            candidates.push((dir, e.name, e.ino, "directory slack".to_string(), live_ino.is_some(), None));
        }
    }
    let mut seen: HashSet<(String, u32)> = HashSet::new();
    let mut not_regular = 0usize;
    for (dir, name, ino, source, replaced, name_seq) in candidates {
        let Some(dir_path) = live.dir_path.get(&dir) else { continue };
        let path = if dir_path == "/" { format!("/{name}") } else { format!("{dir_path}/{name}") };
        if !seen.insert((path.clone(), ino)) {
            continue;
        }
        let live_inode = vol.read_inode(ino);
        let before = inode_copies.get(&ino).and_then(|v| v.iter().filter(|(seq, i)| i.dtime == 0 && i.is_regular() && name_seq.is_none_or(|ns| *seq <= ns)).max_by_key(|(seq, _)| *seq).cloned());
        if before.is_none() && inode_copies.get(&ino).is_some_and(|v| v.iter().any(|(_, i)| i.dtime == 0 && !i.is_regular())) {
            not_regular += 1;
        }
        let generation = before.as_ref().map(|(_, i)| i.generation);
        let dtime = live_inode
            .as_ref()
            .filter(|i| i.dtime != 0 && generation.is_none_or(|g| g == i.generation))
            .map(|i| i.dtime)
            .or_else(|| inode_copies.get(&ino).and_then(|v| v.iter().filter(|(_, i)| i.dtime != 0 && generation.is_none_or(|g| g == i.generation)).map(|(_, i)| i.dtime).max()));
        let (seq, size, mtime, crtime, inline, extents, reused) = match &before {
            Some((seq, old)) => {
                let extents = vol.extents(old);
                let inline = old.inline_data().then(|| old.block[..(old.size as usize).min(60)].to_vec());
                let free = inline.is_some() || all_free(&mut vol, &extents);
                if !free {
                    diag::info(code::EXT_BLOCKS_REUSED, format!("{path} (inode {ino})"));
                }
                (*seq, old.size, old.mtime, old.crtime, inline, if free { extents } else { Vec::new() }, !free)
            }
            None => match &live_inode {
                Some(li) if li.dtime != 0 => (0, 0, li.mtime, li.crtime, None, Vec::new(), false),
                _ => (0, 0, 0, None, None, Vec::new(), false),
            },
        };
        let recoverable = inline.is_some() || (!extents.is_empty() && !reused);
        report.files.push(RecoveredFile {
            path,
            ino,
            kind: if replaced { RecoveredKind::PreviousVersion } else { RecoveredKind::Deleted },
            seq,
            source: match &before {
                Some((seq, _)) => format!("journal seq {seq}{}", if replaced { " (replaced by rename)" } else { "" }),
                None => source,
            },
            size,
            mtime,
            crtime,
            dtime,
            inline,
            extents,
            blocks_reused: reused,
            recoverable,
            id: String::new(),
        });
    }
    if not_regular > 0 {
        diag::info(code::EXT_RECOVER_NOT_REGULAR, format!("{not_regular} names"));
    }
    if let Some(p) = progress.as_deref_mut() {
        p(3, 4);
    }

    // 4. Previous versions of live files (in-place rewrites whose old blocks were freed).
    let mut live_files: Vec<(&String, &u32)> = live.files.iter().collect();
    live_files.sort();
    for (path, &ino) in live_files {
        let Some(versions) = inode_copies.get(&ino) else { continue };
        let Some(live_inode) = vol.read_inode(ino) else { continue };
        let live_blocks: HashSet<u64> = vol.block_list(&live_inode, MAX_CHECK_BLOCKS).into_iter().collect();
        let mut emitted = 0usize;
        for (seq, old) in versions {
            if !old.is_regular() || old.dtime != 0 || old.generation != live_inode.generation || (old.mtime == live_inode.mtime && old.size == live_inode.size) {
                continue;
            }
            let extents = vol.extents(old);
            if extents.is_empty() || extents.iter().any(|e| (0..e.len as u64).any(|i| live_blocks.contains(&(e.physical + i)))) {
                continue;
            }
            let free = all_free(&mut vol, &extents);
            report.files.push(RecoveredFile {
                path: path.clone(),
                ino,
                kind: RecoveredKind::PreviousVersion,
                seq: *seq,
                source: format!("journal seq {seq}"),
                size: old.size,
                mtime: old.mtime,
                crtime: old.crtime,
                dtime: None,
                inline: None,
                extents: if free { extents } else { Vec::new() },
                blocks_reused: !free,
                recoverable: free,
                id: String::new(),
            });
            emitted += 1;
            if emitted >= MAX_VERSIONS {
                break;
            }
        }
    }

    // Identical versions of one inode collapse to the latest; then a stable order and ids.
    let mut keep: Vec<RecoveredFile> = Vec::new();
    for f in report.files.drain(..) {
        if let Some(existing) = keep.iter_mut().find(|k| k.path == f.path && k.ino == f.ino && k.kind == f.kind && k.mtime == f.mtime && k.size == f.size && k.extents == f.extents && k.inline == f.inline) {
            if f.seq > existing.seq {
                *existing = f;
            }
            continue;
        }
        keep.push(f);
    }
    keep.sort_by(|a, b| (a.ino, a.kind, a.seq, &a.path).cmp(&(b.ino, b.kind, b.seq, &b.path)));
    let mut used: HashMap<String, usize> = HashMap::new();
    for f in &mut keep {
        let base = match f.kind {
            RecoveredKind::Deleted => f.ino.to_string(),
            RecoveredKind::PreviousVersion => format!("{}.v{}", f.ino, f.seq),
        };
        let n = used.entry(base.clone()).or_insert(0);
        f.id = if *n == 0 { base } else { format!("{base}.{n}") };
        *n += 1;
    }
    report.files = keep;
    let deleted = report.files.iter().filter(|f| f.kind == RecoveredKind::Deleted).count();
    let recoverable = report.files.iter().filter(|f| f.recoverable).count();
    diag::info(code::EXT_DELETED_FOUND, format!("{deleted} deleted, {} previous versions, {recoverable} with content", report.files.len() - deleted));
    if let Some(p) = progress {
        p(4, 4);
    }
    Ok(report)
}

/// Streams a recovered file's content into `sink`. Returns the bytes written.
pub fn stream(reader: SharedReader, file: &RecoveredFile, sink: &mut dyn std::io::Write, mut progress: Option<&mut dyn FnMut(u64, u64)>) -> Result<u64> {
    if let Some(inline) = &file.inline {
        sink.write_all(inline).map_err(|e| Error::recorded(crate::extract::code::EXTRACT_WRITE, format!("{}: {e}", file.path)))?;
        return Ok(inline.len() as u64);
    }
    let mut vol = Volume::open(reader)?;
    let bs = vol.geo.block_size;
    let total = file.size;
    let mut done = 0u64;
    let step = ((4u64 << 20) / bs).max(1);
    for e in &file.extents {
        let mut left = e.len as u64;
        let mut phys = e.physical;
        while left > 0 && done < total {
            let n = left.min(step);
            let want = (n * bs).min(total - done);
            let bytes = match vol.read_blocks(phys, n) {
                Ok(b) => b,
                Err(err) => {
                    diag::warn(code::EXT_RECOVER_READ, format!("{}: after {done} of {total} bytes: {err}", file.path));
                    return Err(Error::new(crate::fs::code::FS_READ, format!("{}: {err}", file.path)));
                }
            };
            sink.write_all(&bytes[..want as usize]).map_err(|e| Error::recorded(crate::extract::code::EXTRACT_WRITE, format!("{}: {e}", file.path)))?;
            done += want;
            phys += n;
            left -= n;
            if let Some(p) = progress.as_deref_mut() {
                p(done, total);
            }
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() {
        diag::set_quiet(true);
        diag::drain();
    }

    #[test]
    fn geometry_rejects_garbage_and_parses_a_minimal_superblock() {
        quiet();
        assert_eq!(Geometry::parse(&[0u8; 100]).unwrap_err().code, code::EXT_RECOVER_GEOMETRY);
        let mut sb = vec![0u8; 1024];
        sb[0x38..0x3a].copy_from_slice(&EXT_MAGIC.to_le_bytes());
        assert!(Geometry::parse(&sb).is_err(), "zero geometry is implausible");
        sb[0x00..0x04].copy_from_slice(&1024u32.to_le_bytes()); // inodes
        sb[0x04..0x08].copy_from_slice(&4096u32.to_le_bytes()); // blocks
        sb[0x18..0x1c].copy_from_slice(&2u32.to_le_bytes()); // 4 KB blocks
        sb[0x20..0x24].copy_from_slice(&32768u32.to_le_bytes());
        sb[0x28..0x2c].copy_from_slice(&1024u32.to_le_bytes());
        sb[0x4c..0x50].copy_from_slice(&1u32.to_le_bytes());
        sb[0x58..0x5a].copy_from_slice(&256u16.to_le_bytes());
        sb[0xe0..0xe4].copy_from_slice(&8u32.to_le_bytes());
        sb[0x78..0x7c].copy_from_slice(b"root");
        let g = Geometry::parse(&sb).unwrap();
        assert_eq!(g.block_size, 4096);
        assert_eq!(g.group_count(), 1);
        assert_eq!(g.inode_table_blocks(), 64);
        assert_eq!(g.volume_name, "root");
        assert_eq!(g.journal_ino, 8);
    }

    #[test]
    fn raw_inode_fields() {
        let mut b = vec![0u8; 256];
        b[0..2].copy_from_slice(&0x81A4u16.to_le_bytes());
        b[4..8].copy_from_slice(&1234u32.to_le_bytes());
        b[16..20].copy_from_slice(&1_700_000_000u32.to_le_bytes());
        b[20..24].copy_from_slice(&1_700_000_100u32.to_le_bytes());
        b[26..28].copy_from_slice(&1u16.to_le_bytes());
        b[32..36].copy_from_slice(&INODE_EXTENTS_FL.to_le_bytes());
        b[128..130].copy_from_slice(&32u16.to_le_bytes());
        b[144..148].copy_from_slice(&1_600_000_000u32.to_le_bytes());
        let i = RawInode::parse(7, &b).unwrap();
        assert!(i.is_regular() && !i.is_dir() && i.uses_extents() && !i.inline_data() && i.plausible());
        assert_eq!(i.size, 1234);
        assert_eq!(i.dtime, 1_700_000_100);
        assert_eq!(i.crtime, Some(1_600_000_000));
        assert!(RawInode::parse(1, &[0u8; 64]).is_none());
        assert!(!RawInode::parse(1, &[0u8; 128]).unwrap().plausible());
    }

    #[test]
    fn extent_nodes_leaf_index_and_junk() {
        let mut n = vec![0u8; 60];
        n[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        n[2..4].copy_from_slice(&1u16.to_le_bytes());
        n[6..8].copy_from_slice(&0u16.to_le_bytes());
        n[12..16].copy_from_slice(&0u32.to_le_bytes());
        n[16..18].copy_from_slice(&(32768u16 + 3).to_le_bytes()); // uninitialised extent of 3
        n[18..20].copy_from_slice(&0u16.to_le_bytes());
        n[20..24].copy_from_slice(&500u32.to_le_bytes());
        let (depth, entries) = parse_extent_node(&n).unwrap();
        assert_eq!(depth, 0);
        assert_eq!(entries, vec![(0, 3, 500)]);
        n[6..8].copy_from_slice(&1u16.to_le_bytes());
        n[16..20].copy_from_slice(&900u32.to_le_bytes());
        n[20..22].copy_from_slice(&0u16.to_le_bytes());
        let (depth, entries) = parse_extent_node(&n).unwrap();
        assert_eq!(depth, 1);
        assert_eq!(entries[0].1, 0);
        assert_eq!(entries[0].2, 900);
        assert!(parse_extent_node(&[0u8; 60]).is_none());
    }

    fn dirent(ino: u32, rec_len: u16, name: &str, ftype: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&ino.to_le_bytes());
        v.extend_from_slice(&rec_len.to_le_bytes());
        v.push(name.len() as u8);
        v.push(ftype);
        v.extend_from_slice(name.as_bytes());
        while v.len() < rec_len as usize {
            v.push(0);
        }
        v
    }

    #[test]
    fn directory_blocks_chain_and_slack() {
        let mut b = Vec::new();
        b.extend(dirent(2, 12, ".", 2));
        b.extend(dirent(2, 12, "..", 2));
        // "gone" was absorbed into "keep"'s rec_len the old way: bytes intact, off the chain.
        b.extend(dirent(11, 24, "keep", 1));
        let gone = dirent(12, 16, "gone", 1);
        let keep_len = b.len();
        b.truncate(keep_len - 12);
        b.extend(&gone[..12]);
        let rest = 4096 - b.len();
        b.extend(dirent(13, rest as u16, "last.txt", 1));
        assert_eq!(b.len(), 4096);
        let chain = parse_dir_block(&b).expect("a directory block");
        let names: Vec<&str> = chain.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec![".", "..", "keep", "last.txt"]);
        let slack = slack_dir_entries(&b, &chain);
        assert!(slack.iter().any(|e| e.name == "gone" && e.ino == 12), "{slack:?}");
        assert!(parse_dir_block(&[0u8; 4096]).is_none());
        assert!(parse_dir_block(b"FILE0".as_ref()).is_none());
    }

    #[test]
    fn descriptor_tags_in_every_layout() {
        assert_eq!(tag_size(0), 8);
        assert_eq!(tag_size(JBD2_INCOMPAT_64BIT), 12);
        assert_eq!(tag_size(JBD2_INCOMPAT_CSUM_V3), 16);
        let mut b = vec![0u8; 64];
        b[12..16].copy_from_slice(&100u32.to_be_bytes());
        b[18..20].copy_from_slice(&(TAG_SAME_UUID as u16).to_be_bytes());
        b[20..24].copy_from_slice(&200u32.to_be_bytes());
        b[26..28].copy_from_slice(&((TAG_SAME_UUID | TAG_LAST) as u16).to_be_bytes());
        assert_eq!(parse_descriptor_tags(&b, 0), vec![(100, TAG_SAME_UUID), (200, TAG_SAME_UUID | TAG_LAST)]);
        let mut v3 = vec![0u8; 64];
        v3[12..16].copy_from_slice(&7u32.to_be_bytes());
        v3[16..20].copy_from_slice(&(TAG_SAME_UUID | TAG_LAST | TAG_ESCAPE).to_be_bytes());
        v3[20..24].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(parse_descriptor_tags(&v3, JBD2_INCOMPAT_CSUM_V3), vec![((1u64 << 32) | 7, TAG_SAME_UUID | TAG_LAST | TAG_ESCAPE)]);
    }

    #[test]
    fn garbage_volume_is_refused_for_recovery() {
        quiet();
        let r = SharedReader::from_bytes(vec![0u8; 1 << 20]);
        assert_eq!(recover(r, None).unwrap_err().code, code::EXT_RECOVER_GEOMETRY);
        assert!(diag::has(code::EXT_RECOVER_GEOMETRY));
    }
}
