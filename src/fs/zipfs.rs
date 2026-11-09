//! A zip archive as a file system, read in place: no unpacking, every member streamed
//! when asked. Triage packages (KAPE, Velociraptor, CyLR) come as zips.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use zip::read::ZipArchive;

use crate::diag;
use crate::error::{Error, Result};
use crate::fs::{code as fscode, join, normalize, Entry, EntryKind, FileSystem, FsKind, Progress, Sink};
use crate::time::{Timestamp, Timestamps};

pub mod code {
    crate::codes! {
        ZIP_OPEN = 575, "the zip archive could not be opened or its central directory is damaged; the file is truncated (an interrupted download or copy) or not a zip";
        ZIP_ENTRY_UNSAFE = 576, "a member name climbs out of the archive ('..', an absolute path or a drive letter); it was listed under a sanitised name";
        ZIP_ENTRY_READ = 577, "a member could not be decompressed; the archive is damaged there, or the method is one this reader does not support";
        ZIP_ENCRYPTED = 578, "a member is encrypted; it is listed but cannot be read without the password";
        ZIP_INDEXED = 579, "the zip was indexed: members, directories implied by member names, total compressed and uncompressed sizes";
        ZIP_NAME_UNDECODABLE = 580, "a member name is not valid UTF-8 nor CP437; it is shown with replacement characters";
        ZIP_METHOD_UNSUPPORTED = 581, "a member uses a compression method this reader does not decode (not stored, deflate, bzip2, zstd or lzma); it is listed but not readable";
        ZIP_DUPLICATE_NAME = 582, "two members have the same name; the later one is listed, the earlier is unreachable through this API";
    }
}

#[derive(Clone, Debug)]
struct Member {
    index: usize,
    size: u64,
    compressed: u64,
    is_dir: bool,
    modified: Option<Timestamp>,
    encrypted: bool,
}

/// A zip archive as a file system.
pub struct ZipFs {
    path: PathBuf,
    archive: Mutex<ZipArchive<BufReader<File>>>,
    /// Normalized path -> member.
    members: BTreeMap<String, Member>,
    /// Normalized directory path -> child names (sorted), including implied directories.
    dirs: BTreeMap<String, Vec<String>>,
}

impl ZipFs {
    /// Opens and indexes a zip.
    pub fn open(path: &Path) -> Result<Self> {
        let shown = path.display().to_string();
        let f = File::open(path).map_err(|e| Error::recorded(code::ZIP_OPEN, format!("{shown}: {e}")))?;
        let mut archive = ZipArchive::new(BufReader::new(f)).map_err(|e| Error::recorded(code::ZIP_OPEN, format!("{shown}: {e}")))?;
        let mut members: BTreeMap<String, Member> = BTreeMap::new();
        let mut dirs: BTreeMap<String, Vec<String>> = BTreeMap::new();
        dirs.insert("/".to_string(), Vec::new());
        let (mut total, mut comp) = (0u64, 0u64);
        for i in 0..archive.len() {
            let file = match archive.by_index_raw(i) {
                Ok(f) => f,
                Err(e) => {
                    diag::warn(code::ZIP_ENTRY_READ, format!("{shown}: member {i}: {e}"));
                    continue;
                }
            };
            let raw_name = match file.name() {
                Ok(n) => n.to_string(),
                Err(e) => {
                    diag::warn(code::ZIP_NAME_UNDECODABLE, format!("{shown}: member {i}: {e}"));
                    format!("_undecodable_/member{i}")
                }
            };
            let safe = match file.enclosed_name() {
                Some(p) => p.to_string_lossy().replace('\\', "/"),
                None => {
                    diag::warn(code::ZIP_ENTRY_UNSAFE, format!("{shown}: {raw_name}"));
                    sanitize_name(&raw_name)
                }
            };
            if raw_name.contains('\u{FFFD}') {
                diag::warn(code::ZIP_NAME_UNDECODABLE, format!("{shown}: member {i}"));
            }
            let is_dir = file.is_dir() || raw_name.ends_with('/');
            let norm = normalize(&safe);
            if norm == "/" {
                continue;
            }
            let modified = file.last_modified().and_then(|dt| Timestamp::from_civil(dt.year() as i32, dt.month() as u32, dt.day() as u32, dt.hour() as u32, dt.minute() as u32, dt.second() as u32));
            let m = Member { index: i, size: file.size(), compressed: file.compressed_size(), is_dir, modified, encrypted: file.encrypted() };
            if !is_dir {
                total += m.size;
                comp += m.compressed;
            }
            if members.insert(norm.clone(), m).is_some() {
                diag::warn(code::ZIP_DUPLICATE_NAME, format!("{shown}: {norm}"));
            }
            // Every ancestor is a directory.
            let mut parent = norm.clone();
            while let Some((p, name)) = parent.rsplit_once('/') {
                let p = if p.is_empty() { "/".to_string() } else { p.to_string() };
                let children = dirs.entry(p.clone()).or_default();
                if !children.iter().any(|c| c == name) {
                    children.push(name.to_string());
                }
                if p == "/" {
                    break;
                }
                parent = p;
            }
        }
        for children in dirs.values_mut() {
            children.sort();
        }
        diag::info(code::ZIP_INDEXED, format!("{shown}: {} members, {} directories, {} bytes ({} compressed)", members.len(), dirs.len(), total, comp));
        Ok(ZipFs { path: path.to_path_buf(), archive: Mutex::new(archive), members, dirs })
    }

    /// The archive file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of members (files and explicit directories).
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// The member names as stored, normalized, for triage detection.
    pub fn names(&self) -> Vec<String> {
        self.members.keys().map(|k| k.trim_start_matches('/').to_string()).collect()
    }

    fn lookup(&self, path: &str) -> Option<(String, Option<&Member>)> {
        let norm = normalize(path);
        if let Some(m) = self.members.get(&norm) {
            return Some((norm, Some(m)));
        }
        if self.dirs.contains_key(&norm) {
            return Some((norm, None));
        }
        // Case-insensitive fallback.
        let lower = norm.to_lowercase();
        if let Some((k, m)) = self.members.iter().find(|(k, _)| k.to_lowercase() == lower) {
            return Some((k.clone(), Some(m)));
        }
        if let Some(k) = self.dirs.keys().find(|k| k.to_lowercase() == lower) {
            return Some((k.clone(), None));
        }
        None
    }

    fn entry(&self, norm: &str, m: Option<&Member>) -> Entry {
        let kind = match m {
            Some(m) if !m.is_dir => EntryKind::File,
            _ => EntryKind::Dir,
        };
        let mut e = Entry::new(norm, kind);
        if let Some(m) = m {
            e.size = if m.is_dir { 0 } else { m.size };
            e.times = Timestamps { modified: m.modified, ..Default::default() };
            e.id = m.index as u64 + 1;
        }
        e
    }
}

/// A listing-safe name for a member that escapes the archive.
fn sanitize_name(raw: &str) -> String {
    let s = raw.replace('\\', "/");
    let s = s.split(':').next_back().unwrap_or(&s).to_string();
    let parts: Vec<&str> = s.split('/').filter(|c| !c.is_empty() && *c != "." && *c != "..").collect();
    format!("_unsafe_/{}", parts.join("/"))
}

impl FileSystem for ZipFs {
    fn kind(&self) -> FsKind {
        FsKind::Zip
    }

    fn label(&self) -> Option<String> {
        self.path.file_name().map(|n| n.to_string_lossy().to_string())
    }

    fn size(&self) -> Option<u64> {
        std::fs::metadata(&self.path).ok().map(|m| m.len())
    }

    fn metadata(&self, path: &str) -> Result<Entry> {
        let (norm, m) = self.lookup(path).ok_or_else(|| Error::new(fscode::FS_NOT_FOUND, path.to_string()))?;
        Ok(self.entry(&norm, m))
    }

    fn read_dir(&self, path: &str) -> Result<Vec<Entry>> {
        let (norm, m) = self.lookup(path).ok_or_else(|| Error::new(fscode::FS_NOT_FOUND, path.to_string()))?;
        if m.is_some_and(|m| !m.is_dir) {
            return Err(Error::new(fscode::FS_NOT_A_DIR, path.to_string()));
        }
        let children = self.dirs.get(&norm).cloned().unwrap_or_default();
        Ok(children
            .iter()
            .map(|name| {
                let child = join(&norm, name);
                self.entry(&child, self.members.get(&child))
            })
            .collect())
    }

    fn copy_to(&self, path: &str, stream: Option<&str>, sink: Sink<'_>, progress: Option<Progress<'_>>) -> Result<u64> {
        if stream.is_some_and(|s| !s.is_empty()) {
            return Err(Error::new(fscode::FS_STREAM_NOT_FOUND, path.to_string()));
        }
        let (norm, m) = self.lookup(path).ok_or_else(|| Error::new(fscode::FS_NOT_FOUND, path.to_string()))?;
        let Some(m) = m.filter(|m| !m.is_dir) else {
            return Err(Error::new(fscode::FS_NOT_A_FILE, path.to_string()));
        };
        if m.encrypted {
            return Err(Error::recorded(code::ZIP_ENCRYPTED, norm));
        }
        let mut archive = self.archive.lock().map_err(|_| Error::new(crate::source::code::READER_LOCK_POISONED, norm.clone()))?;
        let mut file = archive.by_index(m.index).map_err(|e| {
            let text = e.to_string();
            if text.contains("Unsupported") || text.contains("unsupported") {
                Error::recorded(code::ZIP_METHOD_UNSUPPORTED, format!("{norm}: {text}"))
            } else {
                Error::recorded(code::ZIP_ENTRY_READ, format!("{norm}: {text}"))
            }
        })?;
        let total = m.size;
        let mut done = 0u64;
        let mut buf = vec![0u8; 1 << 20];
        let mut progress = progress;
        loop {
            let n = file.read(&mut buf).map_err(|e| Error::recorded(code::ZIP_ENTRY_READ, format!("{norm}: after {done} bytes: {e}")))?;
            if n == 0 {
                break;
            }
            sink.write_all(&buf[..n]).map_err(|e| Error::recorded(crate::extract::code::EXTRACT_WRITE, format!("{norm}: {e}")))?;
            done += n as u64;
            if let Some(p) = progress.as_deref_mut() {
                p(done, total);
            }
        }
        Ok(done)
    }
}

impl std::fmt::Debug for ZipFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZipFs({}, {} members)", self.path.display(), self.members.len())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::fs::{walk, WalkOptions, WalkStep};
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    /// A zip with a few members, some under implied directories.
    pub fn sample_zip(name: &str, members: &[(&str, &[u8])]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("evidencefs-zip-{}-{}.zip", name, std::process::id()));
        let f = File::create(&p).unwrap();
        let mut w = zip::ZipWriter::new(f);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated).last_modified_time(zip::DateTime::from_date_and_time(2026, 3, 4, 5, 6, 8).unwrap());
        for (n, data) in members {
            if n.ends_with('/') {
                w.add_directory(n.trim_end_matches('/'), opts).unwrap();
            } else {
                w.start_file(*n, opts).unwrap();
                w.write_all(data).unwrap();
            }
        }
        w.finish().unwrap();
        p
    }

    #[test]
    fn indexes_implied_directories_and_reads_members() {
        crate::diag::set_quiet(true);
        let p = sample_zip("basic", &[("C/Windows/System32/config/SYSTEM", b"hive"), ("C/Windows/System32/winevt/Logs/Security.evtx", b"evtx!"), ("_kape.cli", b"cli"), ("Docs/", b"")]);
        let fs = ZipFs::open(&p).unwrap();
        assert_eq!(fs.kind(), FsKind::Zip);
        assert_eq!(fs.member_count(), 4);
        assert!(fs.size().unwrap() > 0);
        assert!(fs.label().unwrap().ends_with(".zip"));
        let top = fs.read_dir("/").unwrap();
        assert_eq!(top.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), vec!["C", "Docs", "_kape.cli"]);
        assert!(top[0].is_dir() && top[1].is_dir() && top[2].is_file());
        let cfg = fs.read_dir("/C/Windows/System32/config").unwrap();
        assert_eq!(cfg.len(), 1);
        assert_eq!(cfg[0].size, 4);
        assert_eq!(cfg[0].times.modified.unwrap().to_human(), "2026-03-04 05:06:08");
        assert_eq!(fs.read("/C/Windows/System32/config/SYSTEM", None, 100).unwrap(), b"hive");
        // Case-insensitive lookups and backslashes.
        assert_eq!(fs.read("c\\windows\\system32\\CONFIG\\system", None, 100).unwrap(), b"hive");
        assert!(fs.exists("/docs"));
        assert_eq!(fs.metadata("/missing").unwrap_err().code, fscode::FS_NOT_FOUND);
        assert_eq!(fs.read_dir("/_kape.cli").unwrap_err().code, fscode::FS_NOT_A_DIR);
        assert_eq!(fs.copy_to("/C", None, &mut Vec::new(), None).unwrap_err().code, fscode::FS_NOT_A_FILE);
        assert_eq!(fs.copy_to("/_kape.cli", Some("ads"), &mut Vec::new(), None).unwrap_err().code, fscode::FS_STREAM_NOT_FOUND);
        let names = fs.names();
        assert!(names.contains(&"_kape.cli".to_string()) && names.contains(&"C/Windows/System32/config/SYSTEM".to_string()));
        let mut all = Vec::new();
        let stats = walk(&fs, "/", &WalkOptions::default(), &mut |e| {
            all.push(e.path.clone());
            WalkStep::Continue
        });
        assert_eq!(stats.files, 3);
        assert_eq!(stats.dirs, 7, "C, Windows, System32, config, winevt, Logs, Docs");
        assert_eq!(all[0], "/C");
        assert_eq!(all.last().unwrap(), "/_kape.cli");
        let mut seen = Vec::new();
        let mut sink = Vec::new();
        fs.copy_to("/C/Windows/System32/winevt/Logs/Security.evtx", None, &mut sink, Some(&mut |d, t| seen.push((d, t)))).unwrap();
        assert_eq!(sink, b"evtx!");
        assert_eq!(seen, vec![(5, 5)]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn unsafe_names_are_listed_under_a_safe_prefix() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let p = sample_zip("unsafe", &[("../../etc/passwd", b"root"), ("ok.txt", b"fine")]);
        let fs = ZipFs::open(&p).unwrap();
        assert!(crate::diag::has(code::ZIP_ENTRY_UNSAFE));
        assert_eq!(fs.read("/_unsafe_/etc/passwd", None, 100).unwrap(), b"root");
        assert_eq!(sanitize_name("C:\\evil\\..\\x.txt"), "_unsafe_/evil/x.txt");
        crate::diag::drain();
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn not_a_zip() {
        crate::diag::set_quiet(true);
        let p = std::env::temp_dir().join(format!("evidencefs-notzip-{}.zip", std::process::id()));
        std::fs::write(&p, b"this is not a zip").unwrap();
        assert_eq!(ZipFs::open(&p).unwrap_err().code, code::ZIP_OPEN);
        assert_eq!(ZipFs::open(&p.with_extension("missing")).unwrap_err().code, code::ZIP_OPEN);
        std::fs::remove_file(&p).ok();
    }
}
