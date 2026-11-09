//! Byte sources: the image formats, opened as one seekable reader that several
//! consumers can share.
//!
//! [`open_image`] decides the format by extension, then by signature when the extension
//! lies, and returns an [`Image`] whose [`SharedReader`] hands every partition, shadow copy
//! and file system reader a view of the same bytes without copying them.

pub mod split;
pub mod vhd;
pub mod vmdk;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::diag;
use crate::error::{Error, Result};

pub mod code {
    crate::codes! {
        IMAGE_NOT_FOUND = 1, "the image path does not exist or cannot be read; check the path and that the first segment (E01, .001, the VMDK descriptor) is the one given";
        IMAGE_UNKNOWN_FORMAT = 2, "the file is not a disk image this crate knows (EWF, raw, split raw, VHD, VHDX, VMDK) by extension or by signature; if it is a raw dump with another extension, rename it to .raw or .dd";
        IMAGE_SECONDARY_SEGMENT = 3, "the file is a later segment of an image set (E02, .002, -s002.vmdk, -flat.vmdk); it was skipped because the first segment carries the whole set";
        IMAGE_OPEN = 4, "the image exists but could not be opened; another process may hold it, or the permissions deny reading";
        IMAGE_READ = 5, "a read inside the image failed; the file is truncated or the medium is failing, the bytes past that point are unreadable";
        IMAGE_EMPTY = 6, "the image has zero bytes; nothing to read";
        IMAGE_BY_SIGNATURE = 7, "the extension did not say what the image is, the first bytes did; the format was taken from the signature";
        IMAGE_DEVICE_UNSUPPORTED = 8, "a raw device path (\\\\.\\PhysicalDrive0, /dev/sdb) was given; live devices are not read by this crate yet, acquire an image first";
        IMAGE_SIZE_UNKNOWN = 9, "the reader could not tell the size of the image; seeking to the end failed, the file is a pipe or a device";
        READER_LOCK_POISONED = 10, "a thread panicked while holding the shared reader; the image is still readable, the operation that panicked is lost";
        IMAGE_SEGMENTS_LISTED = 11, "the segments of a multi-part image were found next to the first one; this is the list that was opened";
        IMAGE_SEGMENT_GAP = 12, "the numbered segments of an image set have a gap (for example .001 and .003 without .002); the set is incomplete, reads past the gap return zeros";
    }
}

/// A seekable reader that can cross threads.
pub trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

/// A clonable handle over one `Read + Seek`, so the partition table, the NTFS reader, the
/// shadow copy walker and the ext4 driver (which wants to own its reader) all use the same
/// image. Every call seeks explicitly, so the shared position never leaks between users.
pub struct SharedReader {
    inner: Arc<Mutex<Box<dyn ReadSeek>>>,
    /// Bytes visible through this view.
    len: u64,
    /// Where the view starts inside the underlying reader.
    offset: u64,
    /// This view's own cursor.
    pos: u64,
}

impl Clone for SharedReader {
    fn clone(&self) -> Self {
        SharedReader { inner: Arc::clone(&self.inner), len: self.len, offset: self.offset, pos: 0 }
    }
}

impl std::fmt::Debug for SharedReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedReader(offset {:#x}, len {})", self.offset, self.len)
    }
}

impl SharedReader {
    /// Wraps a reader; the size is what seeking to the end says.
    pub fn new(mut reader: Box<dyn ReadSeek>) -> Result<Self> {
        let len = reader.seek(SeekFrom::End(0)).map_err(|e| Error::new(code::IMAGE_SIZE_UNKNOWN, e.to_string()))?;
        Ok(SharedReader { inner: Arc::new(Mutex::new(reader)), len, offset: 0, pos: 0 })
    }

    /// Wraps a reader whose size is known (virtual disks say theirs).
    pub fn with_len(reader: Box<dyn ReadSeek>, len: u64) -> Self {
        SharedReader { inner: Arc::new(Mutex::new(reader)), len, offset: 0, pos: 0 }
    }

    /// In-memory bytes, for tests and carved blobs.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let len = bytes.len() as u64;
        SharedReader::with_len(Box::new(io::Cursor::new(bytes)), len)
    }

    /// A view starting `offset` bytes further in, to the end of this view.
    pub fn at(&self, offset: u64) -> Self {
        self.view(offset, self.len.saturating_sub(offset))
    }

    /// A view of `len` bytes starting `offset` bytes further in (a partition).
    pub fn view(&self, offset: u64, len: u64) -> Self {
        let len = len.min(self.len.saturating_sub(offset));
        SharedReader { inner: Arc::clone(&self.inner), len, offset: self.offset + offset, pos: 0 }
    }

    /// Bytes visible through this view.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Is the view empty?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Where the view starts in the underlying image.
    pub fn base_offset(&self) -> u64 {
        self.offset
    }

    /// Absolute read, independent of the cursor. Reads past the view's end fail.
    pub fn read_at(&self, start: u64, dst: &mut [u8]) -> io::Result<()> {
        if start.saturating_add(dst.len() as u64) > self.len {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("read of {} bytes at {start} past the end of a {}-byte view", dst.len(), self.len)));
        }
        let mut r = self.inner.lock().map_err(|_| {
            diag::warn(code::READER_LOCK_POISONED, "shared reader");
            io::Error::other("reader lock poisoned")
        })?;
        r.seek(SeekFrom::Start(self.offset + start))?;
        r.read_exact(dst)
    }

    /// `n` bytes at `start`, or None when they cannot be read.
    pub fn bytes_at(&self, start: u64, n: usize) -> Option<Vec<u8>> {
        let mut b = vec![0u8; n];
        self.read_at(start, &mut b).ok().map(|_| b)
    }
}

impl Read for SharedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let want = buf.len().min((self.len - self.pos) as usize);
        let mut r = self.inner.lock().map_err(|_| io::Error::other("reader lock poisoned"))?;
        r.seek(SeekFrom::Start(self.offset + self.pos))?;
        let n = r.read(&mut buf[..want])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SharedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?,
            SeekFrom::End(d) => self.len.checked_add_signed(d).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?,
        };
        Ok(self.pos)
    }
}

/// The XFS driver wants a block device answering positioned reads from a shared reference.
impl fs_core::BlockRead for SharedReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
        SharedReader::read_at(self, offset, buf).map_err(fs_core::Error::Io)
    }

    fn size_bytes(&self) -> u64 {
        self.len
    }
}

/// The ext4 driver wants a positioned reader it owns.
impl ext4_view::Ext4Read for SharedReader {
    fn read(&mut self, start_byte: u64, dst: &mut [u8]) -> std::result::Result<(), Box<dyn core::error::Error + Send + Sync + 'static>> {
        self.read_at(start_byte, dst).map_err(|e| -> Box<dyn core::error::Error + Send + Sync + 'static> { Box::new(e) })
    }
}

/// The formats an image can come in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImageKind {
    /// Expert Witness (E01 / Ex01 / L01), one or more segments.
    Ewf,
    /// A raw dump in one file (`.dd`, `.raw`, `.img`, `.bin`).
    Raw,
    /// A raw dump split in numbered files (`.001`, `.002`, ...).
    SplitRaw,
    /// Microsoft VHD, fixed or dynamic.
    Vhd,
    /// Microsoft VHDX, fixed or dynamic.
    Vhdx,
    /// VMware VMDK: descriptor, monolithic sparse or flat, split, streamOptimized.
    Vmdk,
}

impl ImageKind {
    /// Short label for logs and columns.
    pub fn label(&self) -> &'static str {
        match self {
            ImageKind::Ewf => "E01",
            ImageKind::Raw => "raw",
            ImageKind::SplitRaw => "split raw",
            ImageKind::Vhd => "VHD",
            ImageKind::Vhdx => "VHDX",
            ImageKind::Vmdk => "VMDK",
        }
    }
}

/// An open image.
pub struct Image {
    /// The path given.
    pub path: PathBuf,
    pub kind: ImageKind,
    /// Virtual size of the disk in bytes.
    pub size: u64,
    /// The files that make up the image, first segment first.
    pub segments: Vec<PathBuf>,
    /// The bytes.
    pub reader: SharedReader,
}

impl std::fmt::Debug for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Image({} {}, {} bytes, {} segment(s))", self.kind.label(), self.path.display(), self.size, self.segments.len())
    }
}

/// An EWF segment extension: `e01`..`e99`, `ex01`.., `l01`.., `lx01`.. After `E99` the
/// segments continue as `EAA`..`EZZ`; those letter forms collide with ordinary
/// extensions (`exe`, `eml`), so they count only next to a first segment on disk.
fn is_ewf_segment_ext(ext: &str) -> bool {
    let b = ext.as_bytes();
    (b.len() == 3 && (b[0] == b'e' || b[0] == b'l') && b[1].is_ascii_digit() && b[2].is_ascii_alphanumeric())
        || (b.len() == 4 && (b[0] == b'e' || b[0] == b'l') && b[1] == b'x' && b[2].is_ascii_alphanumeric() && b[3].is_ascii_alphanumeric())
}

/// `EAA`..`EZZ` (and `LAA`..): a later EWF segment, when the set's first segment sits next to it.
fn is_ewf_letter_segment(path: &Path) -> bool {
    let Some(name) = lower_name(path) else { return false };
    let Some((stem, ext)) = name.rsplit_once('.') else { return false };
    let b = ext.as_bytes();
    if !(b.len() == 3 && (b[0] == b'e' || b[0] == b'l') && b[1].is_ascii_alphabetic() && b[2].is_ascii_alphabetic()) {
        return false;
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    let first = format!("{}.{}01", stem, &ext[..1]);
    std::fs::read_dir(dir).map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().to_lowercase() == first)).unwrap_or(false)
}

fn lower_name(path: &Path) -> Option<String> {
    path.file_name().map(|n| n.to_string_lossy().to_lowercase())
}

/// Any file that belongs to a forensic image set, first segment or not.
pub fn is_image_file(path: &Path) -> bool {
    let Some(filename) = lower_name(path) else { return false };
    let Some((_, ext)) = filename.rsplit_once('.') else { return false };
    matches!(ext, "e01" | "ex01" | "l01" | "lx01" | "vmdk" | "vhd" | "vhdx" | "dd" | "raw" | "img" | "bin" | "aff4" | "qcow2" | "vdi")
        || is_ewf_segment_ext(ext)
        || (ext.len() == 3 && ext.bytes().all(|b| b.is_ascii_digit()))
        || is_ewf_letter_segment(path)
}

/// Is this the FIRST segment of an image set, the one to open? `.E01` / `.Ex01` / `.L01`,
/// the VMDK descriptor, `.vhd(x)`, `.dd/.raw/.img/.bin`, `.001`. Later EWF segments, VMDK
/// `-flat` / `-ctk` / `-sNNN` extents, VMware snapshots (`-000001.vmdk`) and split-raw
/// continuations (`.002`...) are not.
pub fn is_primary_image_segment(path: &Path) -> bool {
    let Some(filename) = lower_name(path) else { return false };
    if filename.ends_with(".e01") || filename.ends_with(".ex01") || filename.ends_with(".l01") || filename.ends_with(".lx01") {
        return true;
    }
    if let Some((_, ext)) = filename.rsplit_once('.') {
        if is_ewf_segment_ext(ext) || is_ewf_letter_segment(path) {
            return false;
        }
    }
    if let Some(stem) = filename.strip_suffix(".vmdk") {
        if stem.ends_with("-flat") || stem.ends_with("-ctk") || stem.ends_with("-delta") {
            return false;
        }
        if let Some(pos) = stem.rfind("-s") {
            let a = &stem[pos + 2..];
            if !a.is_empty() && a.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
        }
        if let Some(pos) = stem.rfind("-0") {
            let a = &stem[pos + 1..];
            if a.len() >= 6 && a[..6].chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
        }
        return true;
    }
    if filename.ends_with(".vhd") || filename.ends_with(".vhdx") {
        return true;
    }
    if filename.ends_with(".dd") || filename.ends_with(".raw") || filename.ends_with(".img") || filename.ends_with(".bin") || filename.ends_with(".001") {
        return true;
    }
    false
}

/// `true` when the file is part of an image set but not its first segment.
pub fn is_secondary_image_segment(path: &Path) -> bool {
    is_image_file(path) && !is_primary_image_segment(path)
}

/// Is this a raw device path rather than a file?
pub fn is_device_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("\\\\.\\") || s.starts_with("/dev/")
}

/// The format the first bytes of the file announce, if any.
pub fn sniff_image(path: &Path) -> Option<ImageKind> {
    let mut f = File::open(path).ok()?;
    let mut head = [0u8; 64];
    let n = f.read(&mut head).ok()?;
    let head = &head[..n];
    if head.starts_with(b"EVF\x09\x0d\x0a\xff\x00") || head.starts_with(b"LVF\x09\x0d\x0a\xff\x00") || head.starts_with(b"EVF2\x0d\x0a\x81\x00") || head.starts_with(b"LEF2\x0d\x0a\x81\x00") {
        return Some(ImageKind::Ewf);
    }
    if head.starts_with(b"vhdxfile") {
        return Some(ImageKind::Vhdx);
    }
    if head.starts_with(b"KDMV") || head.starts_with(b"# Disk DescriptorFile") {
        return Some(ImageKind::Vmdk);
    }
    if head.starts_with(b"conectix") {
        return Some(ImageKind::Vhd);
    }
    // A VHD normally carries its footer at the end.
    let len = f.metadata().ok()?.len();
    if len >= 512 {
        let mut tail = [0u8; 8];
        if f.seek(SeekFrom::Start(len - 512)).is_ok() && f.read_exact(&mut tail).is_ok() && &tail == b"conectix" {
            return Some(ImageKind::Vhd);
        }
        if f.seek(SeekFrom::Start(len - 511)).is_ok() && f.read_exact(&mut tail).is_ok() && &tail == b"conectix" {
            return Some(ImageKind::Vhd);
        }
    }
    None
}

/// The format by extension alone.
pub fn kind_by_extension(path: &Path) -> Option<ImageKind> {
    let filename = lower_name(path)?;
    let (_, ext) = filename.rsplit_once('.')?;
    Some(match ext {
        "e01" | "ex01" | "l01" | "lx01" => ImageKind::Ewf,
        "vhd" => ImageKind::Vhd,
        "vhdx" => ImageKind::Vhdx,
        "vmdk" => ImageKind::Vmdk,
        "dd" | "raw" | "img" | "bin" => ImageKind::Raw,
        "001" => ImageKind::SplitRaw,
        _ => return None,
    })
}

/// Sibling files of an EWF set, in segment order (`.E01`, `.E02`, ... `.EAA`...).
pub fn ewf_segments(first: &Path) -> Vec<PathBuf> {
    let Some(dir) = first.parent() else { return vec![first.to_path_buf()] };
    let Some(stem) = first.file_stem().map(|s| s.to_string_lossy().to_lowercase()) else { return vec![first.to_path_buf()] };
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            let name = lower_name(&p).unwrap_or_default();
            let Some((s, ext)) = name.rsplit_once('.') else { continue };
            if s == stem && is_ewf_segment_ext(ext) {
                out.push(p);
            }
        }
    }
    out.sort_by_key(|p| lower_name(p).unwrap_or_default());
    if out.is_empty() {
        out.push(first.to_path_buf());
    }
    out
}

/// Opens an image of any supported kind.
pub fn open_image(path: &Path) -> Result<Image> {
    if is_device_path(path) {
        return Err(Error::recorded(code::IMAGE_DEVICE_UNSUPPORTED, path.display().to_string()));
    }
    let meta = std::fs::metadata(path).map_err(|e| Error::recorded(code::IMAGE_NOT_FOUND, format!("{}: {e}", path.display())))?;
    if is_secondary_image_segment(path) && sniff_image(path).is_none() {
        return Err(Error::recorded(code::IMAGE_SECONDARY_SEGMENT, path.display().to_string()));
    }
    let kind = match kind_by_extension(path) {
        Some(k) => {
            // The extension may lie (a VHD renamed .img, an E01 renamed .raw).
            match sniff_image(path) {
                Some(s) if s != k && k == ImageKind::Raw => {
                    diag::info(code::IMAGE_BY_SIGNATURE, format!("{}: extension says raw, bytes say {}", path.display(), s.label()));
                    s
                }
                _ => k,
            }
        }
        None => match sniff_image(path) {
            Some(s) => {
                diag::info(code::IMAGE_BY_SIGNATURE, format!("{}: {}", path.display(), s.label()));
                s
            }
            None => return Err(Error::recorded(code::IMAGE_UNKNOWN_FORMAT, path.display().to_string())),
        },
    };
    if meta.len() == 0 {
        return Err(Error::recorded(code::IMAGE_EMPTY, path.display().to_string()));
    }
    let (reader, size, segments): (Box<dyn ReadSeek>, u64, Vec<PathBuf>) = match kind {
        ImageKind::Ewf => {
            let segs = ewf_segments(path);
            let r = ewf::EwfReader::open(path).map_err(|e| Error::recorded(code::IMAGE_OPEN, format!("{}: EWF: {e}", path.display())))?;
            let size = r.total_size();
            if segs.len() > 1 {
                diag::info(code::IMAGE_SEGMENTS_LISTED, format!("{}: {} segments", path.display(), segs.len()));
            }
            (Box::new(r), size, segs)
        }
        ImageKind::Raw => {
            let f = File::open(path).map_err(|e| Error::recorded(code::IMAGE_OPEN, format!("{}: {e}", path.display())))?;
            (Box::new(f), meta.len(), vec![path.to_path_buf()])
        }
        ImageKind::SplitRaw => {
            let r = split::SplitRaw::open(path)?;
            let size = r.total_size();
            let segs = r.segments().to_vec();
            (Box::new(r), size, segs)
        }
        ImageKind::Vhd => {
            let r = vhd::VhdReader::open(path)?;
            let size = r.total_size();
            (Box::new(r), size, vec![path.to_path_buf()])
        }
        ImageKind::Vhdx => {
            let r = vhd::VhdxReader::open(path)?;
            let size = r.total_size();
            (Box::new(r), size, vec![path.to_path_buf()])
        }
        ImageKind::Vmdk => {
            let r = vmdk::VmdkReader::open(path)?;
            let size = r.total_size();
            let segs = r.extent_files();
            (Box::new(r), size, segs)
        }
    };
    if size == 0 {
        return Err(Error::recorded(code::IMAGE_EMPTY, path.display().to_string()));
    }
    Ok(Image { path: path.to_path_buf(), kind, size, segments, reader: SharedReader::with_len(reader, size) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn primary_and_secondary_segments() {
        for s in ["disk.E01", "disk.Ex01", "logical.L01", "d.vmdk", "d.vhd", "d.vhdx", "d.dd", "d.raw", "d.img", "d.bin", "d.001"] {
            assert!(is_primary_image_segment(&p(s)), "{s} is primary");
            assert!(is_image_file(&p(s)), "{s} is an image file");
            assert!(!is_secondary_image_segment(&p(s)));
        }
        for s in ["disk.E02", "disk.Ex02", "d-flat.vmdk", "d-ctk.vmdk", "d-s003.vmdk", "d-000001.vmdk", "d-delta.vmdk", "d.002", "d.137"] {
            assert!(!is_primary_image_segment(&p(s)), "{s} is not primary");
            assert!(is_secondary_image_segment(&p(s)), "{s} is secondary");
        }
        for s in ["notes.txt", "a.zip", "SYSTEM", "x.evtx", "tool.exe", "mail.eml", "disk.EAA"] {
            assert!(!is_image_file(&p(s)), "{s} is not an image");
            assert!(!is_secondary_image_segment(&p(s)));
        }
        // EAA..EZZ count only next to the first segment.
        let dir = std::env::temp_dir().join(format!("evidencefs-eaa-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("disk.E01"), b"x").unwrap();
        std::fs::write(dir.join("disk.EAA"), b"x").unwrap();
        std::fs::write(dir.join("tool.exe"), b"x").unwrap();
        assert!(is_secondary_image_segment(&dir.join("disk.EAA")));
        assert!(!is_primary_image_segment(&dir.join("disk.EAA")));
        assert!(!is_image_file(&dir.join("tool.exe")));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn kinds_by_extension() {
        assert_eq!(kind_by_extension(&p("A.E01")), Some(ImageKind::Ewf));
        assert_eq!(kind_by_extension(&p("a.VHDX")), Some(ImageKind::Vhdx));
        assert_eq!(kind_by_extension(&p("a.vhd")), Some(ImageKind::Vhd));
        assert_eq!(kind_by_extension(&p("a.vmdk")), Some(ImageKind::Vmdk));
        assert_eq!(kind_by_extension(&p("a.001")), Some(ImageKind::SplitRaw));
        assert_eq!(kind_by_extension(&p("a.img")), Some(ImageKind::Raw));
        assert_eq!(kind_by_extension(&p("a.csv")), None);
        assert_eq!(ImageKind::SplitRaw.label(), "split raw");
    }

    #[test]
    fn device_paths() {
        assert!(is_device_path(&p("\\\\.\\PhysicalDrive0")));
        assert!(is_device_path(&p("/dev/sdb")));
        assert!(!is_device_path(&p("D:\\x.E01")));
        crate::diag::set_quiet(true);
        let e = open_image(&p("\\\\.\\PhysicalDrive9")).unwrap_err();
        assert_eq!(e.code, code::IMAGE_DEVICE_UNSUPPORTED);
    }

    #[test]
    fn missing_unknown_and_empty() {
        crate::diag::set_quiet(true);
        let dir = std::env::temp_dir().join(format!("evidencefs-src-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(open_image(&dir.join("nope.E01")).unwrap_err().code, code::IMAGE_NOT_FOUND);
        let txt = dir.join("notes.txt");
        std::fs::write(&txt, b"hello").unwrap();
        assert_eq!(open_image(&txt).unwrap_err().code, code::IMAGE_UNKNOWN_FORMAT);
        let empty = dir.join("empty.raw");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(open_image(&empty).unwrap_err().code, code::IMAGE_EMPTY);
        let seg = dir.join("disk.E02");
        std::fs::write(&seg, b"junk").unwrap();
        assert_eq!(open_image(&seg).unwrap_err().code, code::IMAGE_SECONDARY_SEGMENT);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn raw_opens_and_signature_overrides_extension() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let dir = std::env::temp_dir().join(format!("evidencefs-raw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = dir.join("disk.raw");
        std::fs::write(&raw, vec![7u8; 4096]).unwrap();
        let img = open_image(&raw).unwrap();
        assert_eq!(img.kind, ImageKind::Raw);
        assert_eq!(img.size, 4096);
        assert_eq!(img.segments, vec![raw.clone()]);
        assert_eq!(img.reader.bytes_at(4090, 6).unwrap(), vec![7u8; 6]);
        assert!(format!("{img:?}").contains("raw"));
        // A VHDX renamed .img is recognised by its signature (and then fails to parse, which is fine here).
        let fake = dir.join("renamed.img");
        std::fs::write(&fake, b"vhdxfile junk junk junk junk junk").unwrap();
        assert_eq!(sniff_image(&fake), Some(ImageKind::Vhdx));
        let e = open_image(&fake).unwrap_err();
        assert!(crate::diag::has(code::IMAGE_BY_SIGNATURE));
        assert_ne!(e.code, code::IMAGE_UNKNOWN_FORMAT);
        // A file with no extension but an EWF signature.
        let noext = dir.join("evidence");
        std::fs::write(&noext, b"EVF\x09\x0d\x0a\xff\x00 and more").unwrap();
        assert_eq!(sniff_image(&noext), Some(ImageKind::Ewf));
        assert_eq!(sniff_image(&dir.join("disk.raw")), None);
        std::fs::remove_dir_all(&dir).ok();
        crate::diag::drain();
    }

    #[test]
    fn ewf_segment_listing_sorts_siblings() {
        let dir = std::env::temp_dir().join(format!("evidencefs-ewf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for n in ["case.E03", "case.E01", "case.E02", "case.txt", "other.E01"] {
            std::fs::write(dir.join(n), b"x").unwrap();
        }
        let segs = ewf_segments(&dir.join("case.E01"));
        let names: Vec<String> = segs.iter().map(|p| p.file_name().unwrap().to_string_lossy().to_string()).collect();
        assert_eq!(names, vec!["case.E01", "case.E02", "case.E03"]);
        assert_eq!(ewf_segments(&dir.join("lonely.E01")), vec![dir.join("lonely.E01")]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shared_reader_views_do_not_share_cursors() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let r = SharedReader::from_bytes(data.clone());
        assert_eq!(r.len(), 4096);
        assert!(!r.is_empty());
        let mut a = r.clone();
        let mut b = r.at(1000);
        assert_eq!(b.len(), 3096);
        assert_eq!(b.base_offset(), 1000);
        let mut buf = [0u8; 4];
        a.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0, 1, 2, 3]);
        b.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[1000..1004]);
        a.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [4, 5, 6, 7], "a's cursor was not moved by b");
        // Seeks.
        assert_eq!(b.seek(SeekFrom::End(-4)).unwrap(), 3092);
        b.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[4092..]);
        assert_eq!(b.read(&mut buf).unwrap(), 0, "at the end");
        assert!(a.seek(SeekFrom::Current(-1000)).is_err());
        // Absolute reads and bounds.
        assert_eq!(r.bytes_at(4094, 2).unwrap(), vec![data[4094], data[4095]]);
        assert!(r.bytes_at(4095, 2).is_none());
        let v = r.view(100, 50);
        assert_eq!(v.len(), 50);
        assert!(v.bytes_at(49, 2).is_none());
        assert_eq!(v.bytes_at(0, 1).unwrap(), vec![data[100]]);
        // The view is clipped to its parent.
        assert_eq!(r.view(4000, 1000).len(), 96);
        assert_eq!(r.at(5000).len(), 0);
        assert!(r.at(5000).is_empty());
    }

    #[test]
    fn shared_reader_as_block_device_and_ext4_reader() {
        use fs_core::BlockRead;
        let r = SharedReader::from_bytes(vec![9u8; 1024]);
        assert_eq!(r.size_bytes(), 1024);
        let mut buf = [0u8; 8];
        BlockRead::read_at(&r, 1016, &mut buf).unwrap();
        assert_eq!(buf, [9u8; 8]);
        assert!(BlockRead::read_at(&r, 1020, &mut buf).is_err());
        let mut e = r.clone();
        ext4_view::Ext4Read::read(&mut e, 0, &mut buf).unwrap();
        assert!(ext4_view::Ext4Read::read(&mut e, 1020, &mut buf).is_err());
    }

    #[test]
    fn shared_reader_new_measures_the_reader() {
        let r = SharedReader::new(Box::new(io::Cursor::new(vec![1u8; 77]))).unwrap();
        assert_eq!(r.len(), 77);
        assert!(format!("{r:?}").contains("77"));
    }
}
