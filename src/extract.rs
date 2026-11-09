//! Copying files out of the evidence onto the host disk, with the original times, names
//! made safe for the host, and progress.

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::diag;
use crate::error::{Error, Result};
use crate::fs::{walk, Entry, EntryKind, FileSystem, WalkOptions, WalkStep};
use crate::time::Timestamps;

pub mod code {
    crate::codes! {
        EXTRACT_DEST_CREATE = 650, "the destination folder could not be created; check the path, permissions and free space";
        EXTRACT_WRITE = 651, "writing the copy failed; the disk is full, the path is too long, or the file is locked";
        EXTRACT_READ = 652, "reading the source failed part-way; the copy is incomplete and was removed";
        EXTRACT_TIMES = 653, "the original times could not be set on the copy; the content is intact, the file carries the host's times";
        EXTRACT_NAME_CHANGED = 654, "the original name has characters or a form the host file system refuses; the copy carries a sanitised name (the original is in the manifest)";
        EXTRACT_SKIPPED_LARGE = 655, "a file above the size limit was not copied; raise max_bytes or copy it alone";
        EXTRACT_DONE = 656, "an extraction finished: files, bytes, errors";
        EXTRACT_STREAM = 657, "an alternate data stream was written as its own file, named <file>__<stream>";
        EXTRACT_LINK_SKIPPED = 658, "a symbolic link or reparse point was not copied; its target is noted";
        EXTRACT_LONG_PATH = 659, "a destination path is longer than 240 characters; the Windows long-path prefix was used";
        EXTRACT_EXISTS = 660, "the destination file already exists and overwrite was not asked; it was left as it was";
    }
}

/// Characters Windows refuses in names.
const BAD_CHARS: [char; 9] = ['<', '>', ':', '"', '|', '?', '*', '/', '\\'];
const RESERVED: [&str; 22] = ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"];

/// A name the host accepts: bad characters and controls become `_`, trailing dots and
/// spaces go, reserved device names get a prefix.
pub fn safe_name(name: &str) -> String {
    let mut s: String = name.chars().map(|c| if BAD_CHARS.contains(&c) || (c as u32) < 32 { '_' } else { c }).collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    if s.is_empty() {
        s = "_".to_string();
    }
    let stem = s.split('.').next().unwrap_or("").to_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        s = format!("_{s}");
    }
    s
}

/// Adds the Windows long-path prefix when needed.
pub fn long_path(p: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let s = p.to_string_lossy();
        if s.len() > 240 && !s.starts_with("\\\\?\\") {
            if let Ok(abs) = std::path::absolute(p) {
                diag::info(code::EXTRACT_LONG_PATH, abs.display().to_string());
                return PathBuf::from(format!("\\\\?\\{}", abs.display()));
            }
        }
    }
    p.to_path_buf()
}

/// Sets the copy's times from the entry's.
pub fn set_times(dest: &Path, times: &Timestamps) {
    let Ok(f) = File::options().write(true).open(dest) else {
        diag::info(code::EXTRACT_TIMES, dest.display().to_string());
        return;
    };
    let mut ft = std::fs::FileTimes::new();
    let mut any = false;
    if let Some(m) = times.modified.and_then(|t| t.to_system_time()) {
        ft = ft.set_modified(m);
        any = true;
    }
    if let Some(a) = times.accessed.and_then(|t| t.to_system_time()) {
        ft = ft.set_accessed(a);
        any = true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileTimesExt;
        if let Some(c) = times.created.and_then(|t| t.to_system_time()) {
            ft = ft.set_created(c);
            any = true;
        }
    }
    if any {
        if let Err(e) = f.set_times(ft) {
            diag::info(code::EXTRACT_TIMES, format!("{}: {e}", dest.display()));
        }
    }
}

/// Copies one file (or one of its streams) to `dest`, creating parent folders. Returns
/// the bytes written. An existing destination is left alone unless `overwrite`.
pub fn extract_file(fs: &dyn FileSystem, path: &str, stream: Option<&str>, dest: &Path, overwrite: bool, progress: Option<&mut dyn FnMut(u64, u64)>) -> Result<u64> {
    let meta = fs.metadata(path)?;
    if meta.kind == EntryKind::Symlink {
        diag::info(code::EXTRACT_LINK_SKIPPED, format!("{path} -> {}", meta.link_target.as_deref().unwrap_or("?")));
        return Err(Error::new(crate::fs::code::FS_SYMLINK_NOT_FOLLOWED, path.to_string()));
    }
    if meta.kind != EntryKind::File {
        return Err(Error::new(crate::fs::code::FS_NOT_A_FILE, path.to_string()));
    }
    if dest.exists() && !overwrite {
        diag::info(code::EXTRACT_EXISTS, dest.display().to_string());
        return Err(Error::new(code::EXTRACT_EXISTS, dest.display().to_string()));
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(long_path(parent)).map_err(|e| Error::recorded(code::EXTRACT_DEST_CREATE, format!("{}: {e}", parent.display())))?;
    }
    let dest_lp = long_path(dest);
    let mut out = File::create(&dest_lp).map_err(|e| Error::recorded(code::EXTRACT_WRITE, format!("{}: {e}", dest.display())))?;
    let result = fs.copy_to(path, stream, &mut out, progress);
    drop(out);
    match result {
        Ok(n) => {
            set_times(&dest_lp, &meta.times);
            if let Some(s) = stream {
                diag::info(code::EXTRACT_STREAM, format!("{path}:{s} -> {}", dest.display()));
            }
            Ok(n)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&dest_lp);
            diag::warn(code::EXTRACT_READ, format!("{path}: {e}"));
            Err(e)
        }
    }
}

/// Limits of a tree extraction.
#[derive(Clone, Debug)]
pub struct ExtractOptions {
    pub walk: WalkOptions,
    /// Files above this size are skipped (default 4 GB).
    pub max_bytes: u64,
    /// Also write alternate data streams as `<name>__<stream>`.
    pub streams: bool,
    pub overwrite: bool,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        ExtractOptions { walk: WalkOptions::default(), max_bytes: 4 << 30, streams: true, overwrite: false }
    }
}

/// Progress of a tree extraction: the entry being copied, bytes done, bytes expected.
pub type TreeProgress<'a> = &'a mut dyn FnMut(&Entry, u64, u64);

/// What a tree extraction did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtractStats {
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
    pub streams: usize,
    pub skipped_large: usize,
    pub skipped_links: usize,
    pub errors: usize,
    /// (evidence path, host path) for names that had to change.
    pub renamed: Vec<(String, PathBuf)>,
}

/// The host path for an evidence path under `dest`, every component made safe.
pub fn host_path_for(dest: &Path, root: &str, entry_path: &str) -> (PathBuf, bool) {
    let rel = entry_path.strip_prefix(root.trim_end_matches('/')).unwrap_or(entry_path);
    let mut p = dest.to_path_buf();
    let mut changed = false;
    for c in rel.split('/').filter(|c| !c.is_empty()) {
        let safe = safe_name(c);
        if safe != c {
            changed = true;
        }
        p.push(safe);
    }
    (p, changed)
}

/// Copies the tree under `root` into `dest`, folder by folder, with times.
pub fn extract_tree(fs: &dyn FileSystem, root: &str, dest: &Path, opts: &ExtractOptions, mut progress: Option<TreeProgress<'_>>) -> ExtractStats {
    let mut stats = ExtractStats::default();
    if let Err(e) = std::fs::create_dir_all(long_path(dest)) {
        diag::error(code::EXTRACT_DEST_CREATE, format!("{}: {e}", dest.display()));
        stats.errors += 1;
        return stats;
    }
    let root_norm = crate::fs::normalize(root);
    let mut entries: Vec<Entry> = Vec::new();
    walk(fs, &root_norm, &opts.walk, &mut |e| {
        entries.push(e.clone());
        WalkStep::Continue
    });
    let total: u64 = entries.iter().filter(|e| e.is_file()).map(|e| e.size).sum();
    let mut done_bytes = 0u64;
    for e in &entries {
        let (host, changed) = host_path_for(dest, &root_norm, &e.path);
        if changed {
            diag::info(code::EXTRACT_NAME_CHANGED, format!("{} -> {}", e.path, host.display()));
            stats.renamed.push((e.path.clone(), host.clone()));
        }
        match e.kind {
            EntryKind::Dir => {
                if let Err(err) = std::fs::create_dir_all(long_path(&host)) {
                    diag::warn(code::EXTRACT_DEST_CREATE, format!("{}: {err}", host.display()));
                    stats.errors += 1;
                } else {
                    stats.dirs += 1;
                }
            }
            EntryKind::Symlink => {
                diag::info(code::EXTRACT_LINK_SKIPPED, format!("{} -> {}", e.path, e.link_target.as_deref().unwrap_or("?")));
                stats.skipped_links += 1;
            }
            EntryKind::Other => {}
            EntryKind::File => {
                if e.size > opts.max_bytes {
                    diag::warn(code::EXTRACT_SKIPPED_LARGE, format!("{}: {} bytes", e.path, e.size));
                    stats.skipped_large += 1;
                    continue;
                }
                let base = done_bytes;
                let mut cb = |d: u64, _t: u64| {
                    if let Some(p) = progress.as_deref_mut() {
                        p(e, base + d, total);
                    }
                };
                match extract_file(fs, &e.path, None, &host, opts.overwrite, Some(&mut cb)) {
                    Ok(n) => {
                        stats.files += 1;
                        stats.bytes += n;
                        done_bytes += e.size;
                    }
                    Err(err) if err.code == code::EXTRACT_EXISTS => {
                        done_bytes += e.size;
                    }
                    Err(_) => {
                        stats.errors += 1;
                        done_bytes += e.size;
                    }
                }
                if opts.streams {
                    for s in &e.streams {
                        let sdest = host.with_file_name(format!("{}__{}", host.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), safe_name(&s.name)));
                        match extract_file(fs, &e.path, Some(&s.name), &sdest, opts.overwrite, None) {
                            Ok(n) => {
                                stats.streams += 1;
                                stats.bytes += n;
                            }
                            Err(err) if err.code == code::EXTRACT_EXISTS => {}
                            Err(_) => stats.errors += 1,
                        }
                    }
                }
            }
        }
    }
    // Directory times last, so writing children did not move them.
    for e in entries.iter().filter(|e| e.is_dir()) {
        let (host, _) = host_path_for(dest, &root_norm, &e.path);
        set_times(&long_path(&host), &e.times);
    }
    diag::info(code::EXTRACT_DONE, format!("{root_norm} -> {}: {} files, {} dirs, {} streams, {} bytes, {} errors", dest.display(), stats.files, stats.dirs, stats.streams, stats.bytes, stats.errors));
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::folder::FolderFs;

    #[test]
    fn safe_names() {
        assert_eq!(safe_name("normal.txt"), "normal.txt");
        assert_eq!(safe_name("a:b|c?d*e<f>g\"h"), "a_b_c_d_e_f_g_h");
        assert_eq!(safe_name("trailing. "), "trailing");
        assert_eq!(safe_name("..."), "_");
        assert_eq!(safe_name("CON"), "_CON");
        assert_eq!(safe_name("com1.txt"), "_com1.txt");
        assert_eq!(safe_name("console"), "console");
        assert_eq!(safe_name("tab\there"), "tab_here");
        assert_eq!(safe_name("$MFT"), "$MFT");
    }

    #[test]
    fn host_paths() {
        let (p, changed) = host_path_for(Path::new("out"), "/", "/Windows/System32/config/SYSTEM");
        assert_eq!(p, Path::new("out").join("Windows").join("System32").join("config").join("SYSTEM"));
        assert!(!changed);
        let (p, changed) = host_path_for(Path::new("out"), "/Users/bob", "/Users/bob/Desktop/a:b.txt");
        assert_eq!(p, Path::new("out").join("Desktop").join("a_b.txt"));
        assert!(changed);
        assert_eq!(long_path(Path::new("short")), PathBuf::from("short"));
    }

    #[test]
    fn extracts_a_tree_with_times_and_progress() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let src = crate::fs::folder::tests::tree("extract-src");
        let fs = FolderFs::open(&src).unwrap();
        let dest = std::env::temp_dir().join(format!("evidencefs-extract-dest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        let mut last = (0u64, 0u64);
        let stats = extract_tree(&fs, "/", &dest, &ExtractOptions::default(), Some(&mut |_, d, t| last = (d, t)));
        assert_eq!(stats.files, 3);
        assert_eq!(stats.dirs, 3);
        assert_eq!(stats.bytes, 5 + 3000 + 7);
        assert_eq!(stats.errors, 0);
        assert_eq!(last, (3012, 3012));
        assert_eq!(std::fs::read(dest.join("sub").join("deep").join("c.txt")).unwrap(), b"charlie");
        assert!(dest.join("empty").is_dir());
        let src_m = std::fs::metadata(src.join("a.txt")).unwrap().modified().unwrap();
        let dst_m = std::fs::metadata(dest.join("a.txt")).unwrap().modified().unwrap();
        let diff = src_m.duration_since(dst_m).or_else(|e| Ok::<_, ()>(e.duration())).unwrap();
        assert!(diff.as_secs() < 2, "modified time kept ({diff:?})");
        assert!(crate::diag::has(code::EXTRACT_DONE));
        // A second run without overwrite leaves files and reports nothing new.
        crate::diag::drain();
        let stats2 = extract_tree(&fs, "/", &dest, &ExtractOptions::default(), None);
        assert_eq!(stats2.files, 0);
        assert_eq!(stats2.errors, 0);
        assert!(crate::diag::has(code::EXTRACT_EXISTS));
        // With overwrite the files are written again.
        let stats3 = extract_tree(&fs, "/", &dest, &ExtractOptions { overwrite: true, ..Default::default() }, None);
        assert_eq!(stats3.files, 3);
        // Size limit.
        crate::diag::drain();
        let dest2 = dest.with_file_name("evidencefs-extract-dest2");
        let _ = std::fs::remove_dir_all(&dest2);
        let stats4 = extract_tree(&fs, "/", &dest2, &ExtractOptions { max_bytes: 100, ..Default::default() }, None);
        assert_eq!(stats4.skipped_large, 1);
        assert_eq!(stats4.files, 2);
        assert!(crate::diag::has(code::EXTRACT_SKIPPED_LARGE));
        // A subtree, a single file, and the refusals.
        let one = dest2.join("single.bin");
        assert_eq!(extract_file(&fs, "/sub/b.bin", None, &one, false, None).unwrap(), 3000);
        assert_eq!(extract_file(&fs, "/sub/b.bin", None, &one, false, None).unwrap_err().code, code::EXTRACT_EXISTS);
        assert_eq!(extract_file(&fs, "/sub", None, &dest2.join("x"), false, None).unwrap_err().code, crate::fs::code::FS_NOT_A_FILE);
        assert_eq!(extract_file(&fs, "/nope", None, &dest2.join("x"), false, None).unwrap_err().code, crate::fs::code::FS_NOT_FOUND);
        let stats5 = extract_tree(&fs, "/sub", &dest2.join("subonly"), &ExtractOptions::default(), None);
        assert_eq!(stats5.files, 2);
        assert!(dest2.join("subonly").join("deep").join("c.txt").exists());
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dest).ok();
        std::fs::remove_dir_all(&dest2).ok();
        crate::diag::drain();
    }
}
