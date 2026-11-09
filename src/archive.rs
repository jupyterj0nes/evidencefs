//! Archives as evidence: a zip is read in place ([`crate::fs::zipfs::ZipFs`]); a tar,
//! `.tar.gz` or `.tgz` is unpacked once into a temporary folder that lives as long as the
//! evidence does. 7z and RAR are recognised and refused with a code.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use crate::diag;
use crate::error::{Error, Result};

pub mod code {
    crate::codes! {
        ARCHIVE_UNSUPPORTED = 200, "the archive format (7z, RAR, xz, bz2) is not read by this crate; unpack it with 7-Zip or bsdtar and give the folder";
        ARCHIVE_OPEN = 201, "the archive could not be opened; the file is truncated, not an archive, or locked";
        ARCHIVE_ENTRY_UNSAFE = 202, "a member path climbs out of the destination ('..', absolute, drive letter) or is a device link; it was skipped";
        ARCHIVE_ENTRY_ERROR = 203, "a member could not be unpacked; the archive is damaged there, the rest went on";
        ARCHIVE_UNPACKED = 204, "an archive was unpacked into a temporary folder: members, bytes, destination";
        ARCHIVE_NESTED = 205, "an archive inside the evidence was found and opened as a nested mount";
        ARCHIVE_NESTED_LIMIT = 206, "an archive is nested deeper than the limit; it was listed as a file, not opened";
        ARCHIVE_TEMP_DIR = 207, "the temporary folder for unpacking could not be created; check the temp location and free space";
        ARCHIVE_GZIP = 208, "the gzip stream is damaged or truncated; the members unpacked before the damage are kept";
        ARCHIVE_EMPTY = 209, "the archive has no members";
        ARCHIVE_BY_SIGNATURE = 210, "the extension did not say what the archive is, the first bytes did";
        ARCHIVE_TEMP_CLEANUP = 211, "the temporary folder could not be removed when the evidence was closed; remove it by hand";
        ARCHIVE_TAR_SPARSE = 212, "a tar member is sparse or of a type (device, fifo) that is not unpacked; it was skipped";
        ARCHIVE_SYMLINK_SKIPPED = 213, "a tar member is a symbolic or hard link; links are not recreated, the member was skipped and noted";
    }
}

/// The archive formats recognised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArchiveKind {
    Zip,
    Tar,
    TarGz,
    /// Recognised, not read.
    TarBz2,
    /// Recognised, not read.
    TarXz,
    /// Recognised, not read.
    SevenZip,
    /// Recognised, not read.
    Rar,
}

impl ArchiveKind {
    /// Short label.
    pub fn label(&self) -> &'static str {
        match self {
            ArchiveKind::Zip => "zip",
            ArchiveKind::Tar => "tar",
            ArchiveKind::TarGz => "tar.gz",
            ArchiveKind::TarBz2 => "tar.bz2",
            ArchiveKind::TarXz => "tar.xz",
            ArchiveKind::SevenZip => "7z",
            ArchiveKind::Rar => "rar",
        }
    }

    /// Can this crate read it?
    pub fn is_supported(&self) -> bool {
        matches!(self, ArchiveKind::Zip | ArchiveKind::Tar | ArchiveKind::TarGz)
    }
}

/// The archive kind by file name.
pub fn kind_by_extension(path: &Path) -> Option<ArchiveKind> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    Some(if name.ends_with(".zip") || name.ends_with(".kape") {
        ArchiveKind::Zip
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        ArchiveKind::TarGz
    } else if name.ends_with(".tar.bz2") || name.ends_with(".tbz2") || name.ends_with(".tbz") {
        ArchiveKind::TarBz2
    } else if name.ends_with(".tar.xz") || name.ends_with(".txz") {
        ArchiveKind::TarXz
    } else if name.ends_with(".tar") {
        ArchiveKind::Tar
    } else if name.ends_with(".7z") {
        ArchiveKind::SevenZip
    } else if name.ends_with(".rar") {
        ArchiveKind::Rar
    } else {
        return None;
    })
}

/// The archive kind by signature.
pub fn sniff(path: &Path) -> Option<ArchiveKind> {
    let mut f = File::open(path).ok()?;
    let mut head = [0u8; 8];
    let n = f.read(&mut head).ok()?;
    let head = &head[..n];
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        return Some(ArchiveKind::Zip);
    }
    if head.starts_with(&[0x1f, 0x8b]) {
        return Some(ArchiveKind::TarGz);
    }
    if head.starts_with(b"BZh") {
        return Some(ArchiveKind::TarBz2);
    }
    if head.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some(ArchiveKind::TarXz);
    }
    if head.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some(ArchiveKind::SevenZip);
    }
    if head.starts_with(b"Rar!\x1a\x07") {
        return Some(ArchiveKind::Rar);
    }
    // ustar magic at 257.
    use std::io::{Seek, SeekFrom};
    let mut magic = [0u8; 5];
    if f.seek(SeekFrom::Start(257)).is_ok() && f.read_exact(&mut magic).is_ok() && &magic == b"ustar" {
        return Some(ArchiveKind::Tar);
    }
    None
}

/// The archive kind: extension first, signature when the extension says nothing or lies.
pub fn archive_kind(path: &Path) -> Option<ArchiveKind> {
    match (kind_by_extension(path), sniff(path)) {
        (Some(k), Some(s)) if k != s && !(k == ArchiveKind::Tar && s == ArchiveKind::Tar) => {
            diag::info(code::ARCHIVE_BY_SIGNATURE, format!("{}: extension says {}, bytes say {}", path.display(), k.label(), s.label()));
            Some(s)
        }
        (Some(k), _) => Some(k),
        (None, Some(s)) => {
            diag::info(code::ARCHIVE_BY_SIGNATURE, format!("{}: {}", path.display(), s.label()));
            Some(s)
        }
        (None, None) => None,
    }
}

/// Is the file an archive this crate reads?
pub fn is_supported_archive(path: &Path) -> bool {
    kind_by_extension(path).is_some_and(|k| k.is_supported())
}

/// A temporary folder removed on drop.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
    keep: bool,
}

impl TempDir {
    /// Creates a unique folder under `base` (or the system temp dir).
    pub fn new(base: Option<&Path>, hint: &str) -> Result<Self> {
        let base = base.map(|p| p.to_path_buf()).unwrap_or_else(std::env::temp_dir);
        let hint: String = hint.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(32).collect();
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        for attempt in 0..100u32 {
            let path = base.join(format!("evidencefs-{}-{}-{nanos:x}{attempt}", std::process::id(), hint));
            match std::fs::create_dir_all(&path) {
                Ok(()) if std::fs::read_dir(&path).map(|mut d| d.next().is_none()).unwrap_or(false) => return Ok(TempDir { path, keep: false }),
                Ok(()) => continue,
                Err(e) => return Err(Error::recorded(code::ARCHIVE_TEMP_DIR, format!("{}: {e}", path.display()))),
            }
        }
        Err(Error::recorded(code::ARCHIVE_TEMP_DIR, base.display().to_string()))
    }

    /// The folder.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Leave the folder on disk when dropped.
    pub fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            if self.path.exists() {
                diag::warn(code::ARCHIVE_TEMP_CLEANUP, format!("{}: {e}", self.path.display()));
            }
        }
    }
}

/// What an unpack did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unpacked {
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
    pub skipped: usize,
    pub errors: usize,
    /// Members that were links, with their targets.
    pub links: Vec<(String, String)>,
}

/// Unpacks a tar, `.tar.gz` or `.tgz` into `dest`, keeping member times. Links, devices
/// and sparse members are skipped and counted.
pub fn unpack_tar(path: &Path, dest: &Path, progress: Option<&mut dyn FnMut(u64, u64)>) -> Result<Unpacked> {
    let kind = archive_kind(path).ok_or_else(|| Error::recorded(code::ARCHIVE_OPEN, format!("{}: not an archive", path.display())))?;
    if !matches!(kind, ArchiveKind::Tar | ArchiveKind::TarGz) {
        return Err(Error::recorded(code::ARCHIVE_UNSUPPORTED, format!("{}: {}", path.display(), kind.label())));
    }
    let f = File::open(path).map_err(|e| Error::recorded(code::ARCHIVE_OPEN, format!("{}: {e}", path.display())))?;
    let total = f.metadata().map(|m| m.len()).unwrap_or(0);
    let counted = CountingReader { inner: BufReader::new(f), read: 0 };
    let reader: Box<dyn Read> = if kind == ArchiveKind::TarGz { Box::new(flate2::read::MultiGzDecoder::new(counted)) } else { Box::new(counted) };
    std::fs::create_dir_all(dest).map_err(|e| Error::recorded(code::ARCHIVE_TEMP_DIR, format!("{}: {e}", dest.display())))?;
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(false);
    archive.set_preserve_permissions(false);
    let mut stats = Unpacked::default();
    let entries = archive.entries().map_err(|e| Error::recorded(code::ARCHIVE_OPEN, format!("{}: {e}", path.display())))?;
    let mut progress = progress;
    let mut any = false;
    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                let text = e.to_string();
                if kind == ArchiveKind::TarGz && (text.contains("gzip") || text.contains("corrupt") || text.contains("invalid")) {
                    diag::warn(code::ARCHIVE_GZIP, format!("{}: {text}", path.display()));
                } else {
                    diag::warn(code::ARCHIVE_ENTRY_ERROR, format!("{}: {text}", path.display()));
                }
                stats.errors += 1;
                break;
            }
        };
        any = true;
        let member = entry.path().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| "?".to_string());
        let ty = entry.header().entry_type();
        if ty.is_symlink() || ty.is_hard_link() {
            let target = entry.link_name().ok().flatten().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            diag::info(code::ARCHIVE_SYMLINK_SKIPPED, format!("{member} -> {target}"));
            stats.links.push((member, target));
            stats.skipped += 1;
            continue;
        }
        if !(ty.is_file() || ty.is_dir() || ty.is_pax_global_extensions() || ty.is_pax_local_extensions() || ty.is_gnu_longname() || ty.is_gnu_longlink()) {
            diag::info(code::ARCHIVE_TAR_SPARSE, format!("{member}: {ty:?}"));
            stats.skipped += 1;
            continue;
        }
        let size = entry.header().size().unwrap_or(0);
        match entry.unpack_in(dest) {
            Ok(true) => {
                if ty.is_dir() {
                    stats.dirs += 1;
                } else {
                    stats.files += 1;
                    stats.bytes += size;
                }
            }
            Ok(false) => {
                diag::warn(code::ARCHIVE_ENTRY_UNSAFE, member);
                stats.skipped += 1;
            }
            Err(e) => {
                diag::warn(code::ARCHIVE_ENTRY_ERROR, format!("{member}: {e}"));
                stats.errors += 1;
            }
        }
        if let Some(p) = progress.as_deref_mut() {
            p(entry.raw_file_position().min(total), total);
        }
    }
    if !any {
        diag::warn(code::ARCHIVE_EMPTY, path.display().to_string());
    }
    diag::info(code::ARCHIVE_UNPACKED, format!("{}: {} files, {} dirs, {} bytes into {}", path.display(), stats.files, stats.dirs, stats.bytes, dest.display()));
    Ok(stats)
}

struct CountingReader<R> {
    inner: R,
    read: u64,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("evidencefs-arch-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// One raw ustar member (header + data padded to 512), so names the `tar` crate refuses
    /// to write (`../escape.txt`) can be tested.
    fn raw_member(name: &str, data: &[u8], typeflag: u8, link: &str, mtime: u64) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        h[108..115].copy_from_slice(b"0000000");
        h[116..123].copy_from_slice(b"0000000");
        h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        h[136..147].copy_from_slice(format!("{mtime:011o}").as_bytes());
        h[148..156].copy_from_slice(b"        ");
        h[156] = typeflag;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
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

    /// A tar.gz with two files, a symlink and a member that escapes the destination.
    pub fn sample_tgz(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        let mut tar = Vec::new();
        tar.extend(raw_member("etc/hostname", b"lnx01", b'0', "", 1_700_000_000));
        tar.extend(raw_member("var/log/auth.log", b"log", b'0', "", 1_700_000_100));
        tar.extend(raw_member("etc/link", b"", b'2', "hostname", 1_700_000_000));
        tar.extend(raw_member("../escape.txt", b"evil", b'0', "", 1_700_000_000));
        tar.extend(vec![0u8; 1024]);
        let f = File::create(&p).unwrap();
        let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        enc.write_all(&tar).unwrap();
        enc.finish().unwrap();
        p
    }

    #[test]
    fn kinds_by_extension_and_signature() {
        assert_eq!(kind_by_extension(Path::new("a.ZIP")), Some(ArchiveKind::Zip));
        assert_eq!(kind_by_extension(Path::new("a.tar.gz")), Some(ArchiveKind::TarGz));
        assert_eq!(kind_by_extension(Path::new("a.tgz")), Some(ArchiveKind::TarGz));
        assert_eq!(kind_by_extension(Path::new("a.tar")), Some(ArchiveKind::Tar));
        assert_eq!(kind_by_extension(Path::new("a.tar.bz2")), Some(ArchiveKind::TarBz2));
        assert_eq!(kind_by_extension(Path::new("a.7z")), Some(ArchiveKind::SevenZip));
        assert_eq!(kind_by_extension(Path::new("a.rar")), Some(ArchiveKind::Rar));
        assert_eq!(kind_by_extension(Path::new("a.txt")), None);
        assert!(is_supported_archive(Path::new("x.zip")) && !is_supported_archive(Path::new("x.7z")));
        assert!(ArchiveKind::TarGz.is_supported() && !ArchiveKind::Rar.is_supported());
        assert_eq!(ArchiveKind::SevenZip.label(), "7z");
        let d = tmpdir("sig");
        std::fs::write(d.join("z"), b"PK\x03\x04rest").unwrap();
        assert_eq!(sniff(&d.join("z")), Some(ArchiveKind::Zip));
        std::fs::write(d.join("g"), [0x1f, 0x8b, 8, 0]).unwrap();
        assert_eq!(sniff(&d.join("g")), Some(ArchiveKind::TarGz));
        std::fs::write(d.join("s"), b"7z\xbc\xaf\x27\x1c").unwrap();
        assert_eq!(sniff(&d.join("s")), Some(ArchiveKind::SevenZip));
        std::fs::write(d.join("r"), b"Rar!\x1a\x07\x00").unwrap();
        assert_eq!(sniff(&d.join("r")), Some(ArchiveKind::Rar));
        std::fs::write(d.join("b"), b"BZh91AY").unwrap();
        assert_eq!(sniff(&d.join("b")), Some(ArchiveKind::TarBz2));
        std::fs::write(d.join("x"), [0xFD, b'7', b'z', b'X', b'Z', 0x00]).unwrap();
        assert_eq!(sniff(&d.join("x")), Some(ArchiveKind::TarXz));
        let mut t = vec![0u8; 512];
        t[257..262].copy_from_slice(b"ustar");
        std::fs::write(d.join("t"), &t).unwrap();
        assert_eq!(sniff(&d.join("t")), Some(ArchiveKind::Tar));
        std::fs::write(d.join("n"), b"plain text").unwrap();
        assert_eq!(sniff(&d.join("n")), None);
        crate::diag::set_quiet(true);
        crate::diag::drain();
        // A zip renamed .txt is found by signature; a .zip that is really gzip is corrected.
        std::fs::write(d.join("renamed.txt"), b"PK\x03\x04rest").unwrap();
        assert_eq!(archive_kind(&d.join("renamed.txt")), Some(ArchiveKind::Zip));
        assert!(crate::diag::has(code::ARCHIVE_BY_SIGNATURE));
        std::fs::write(d.join("lying.zip"), [0x1f, 0x8b, 8, 0]).unwrap();
        assert_eq!(archive_kind(&d.join("lying.zip")), Some(ArchiveKind::TarGz));
        assert_eq!(archive_kind(&d.join("n")), None);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn temp_dir_is_unique_and_removed() {
        crate::diag::set_quiet(true);
        let a = TempDir::new(None, "unit test").unwrap();
        let b = TempDir::new(None, "unit test").unwrap();
        assert_ne!(a.path(), b.path());
        assert!(a.path().is_dir());
        let p = a.path().to_path_buf();
        drop(a);
        assert!(!p.exists());
        let mut c = TempDir::new(None, "kept").unwrap();
        let pc = c.path().to_path_buf();
        c.keep();
        drop(c);
        assert!(pc.exists());
        std::fs::remove_dir_all(&pc).ok();
        let bad = TempDir::new(Some(Path::new("Q:\\no\\such\\drive\\here")), "x");
        if let Err(e) = bad {
            assert_eq!(e.code, code::ARCHIVE_TEMP_DIR);
        }
    }

    #[test]
    fn unpacks_tgz_skipping_links_and_escapes() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let d = tmpdir("tgz");
        let p = sample_tgz(&d, "lnx01.tgz");
        let dest = d.join("out");
        let mut seen = 0;
        let stats = unpack_tar(&p, &dest, Some(&mut |_, _| seen += 1)).unwrap();
        assert_eq!(stats.files, 2);
        assert_eq!(stats.bytes, 8);
        assert_eq!(stats.skipped, 2, "the symlink and the escaping member");
        assert_eq!(stats.links, vec![("etc/link".to_string(), "hostname".to_string())]);
        assert!(seen >= 2);
        assert_eq!(std::fs::read_to_string(dest.join("etc").join("hostname")).unwrap(), "lnx01");
        assert!(!d.join("escape.txt").exists());
        assert!(crate::diag::has(code::ARCHIVE_ENTRY_UNSAFE));
        assert!(crate::diag::has(code::ARCHIVE_SYMLINK_SKIPPED));
        assert!(crate::diag::has(code::ARCHIVE_UNPACKED));
        let m = std::fs::metadata(dest.join("etc").join("hostname")).unwrap().modified().unwrap();
        assert_eq!(m.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), 1_700_000_000, "member times are kept");
        // Refusals.
        std::fs::write(d.join("x.7z"), b"7z\xbc\xaf\x27\x1c").unwrap();
        assert_eq!(unpack_tar(&d.join("x.7z"), &dest, None).unwrap_err().code, code::ARCHIVE_UNSUPPORTED);
        std::fs::write(d.join("x.txt"), b"nothing").unwrap();
        assert_eq!(unpack_tar(&d.join("x.txt"), &dest, None).unwrap_err().code, code::ARCHIVE_OPEN);
        assert_eq!(unpack_tar(&d.join("missing.tar"), &dest, None).unwrap_err().code, code::ARCHIVE_OPEN);
        // A damaged gzip.
        crate::diag::drain();
        let mut bytes = std::fs::read(&p).unwrap();
        bytes.truncate(bytes.len() / 2);
        let mut f = File::create(d.join("broken.tgz")).unwrap();
        f.write_all(&bytes).unwrap();
        drop(f);
        let stats = unpack_tar(&d.join("broken.tgz"), &d.join("out2"), None).unwrap();
        assert!(stats.errors >= 1 || stats.files < 2);
        std::fs::remove_dir_all(&d).ok();
    }
}
