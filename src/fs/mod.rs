//! File systems behind one trait: NTFS, ext2/3/4 and XFS inside images, a plain folder,
//! a zip archive. Paths are always `/`-separated with a leading `/`, whatever the source
//! used, so a tool asks for `/Windows/System32/config/SYSTEM` the same way everywhere.

pub mod ext;
pub mod extjournal;
pub mod folder;
pub mod mft;
pub mod ntfs;
pub mod tarfs;
pub mod xfs;
pub mod zipfs;

use std::io::Write;

use crate::diag;
use crate::error::{Error, Result};
use crate::time::Timestamps;

pub mod code {
    crate::codes! {
        FS_NOT_FOUND = 600, "the path does not exist in this file system; check the spelling (NTFS and zip lookups ignore case, ext and XFS do not) and that the volume is the right one";
        FS_NOT_A_DIR = 601, "the path exists but is a file, and a directory listing was asked; use metadata() or read() on it";
        FS_NOT_A_FILE = 602, "the path exists but is a directory or a link, and its content was asked; list it instead";
        FS_READ = 603, "reading the content failed part-way; the file system structures for this file are damaged or the image is truncated, the bytes read so far are kept";
        FS_SYMLINK_NOT_FOLLOWED = 604, "the path is a symbolic link or a reparse point; links are listed with their target but never followed, open the target yourself if it is inside the evidence";
        WALK_DEPTH_LIMIT = 605, "a directory is deeper than the walk's depth limit; its content was not listed, raise max_depth if it matters";
        WALK_FILE_LIMIT = 606, "the walk reached its file limit and stopped; raise max_files or walk a subtree";
        WALK_DIR_UNREADABLE = 607, "a directory could not be listed; its index is damaged or the image is truncated there, the walk went on with the rest";
        WALK_NAME_UNDECODABLE = 608, "a file name is not valid Unicode; it is shown with replacement characters, the bytes are not recoverable through this API";
        FS_FILE_TOO_LARGE = 609, "the file is larger than the limit given to read(); use copy_to() to stream it, or raise the limit";
        FS_STREAM_NOT_FOUND = 610, "the file has no alternate data stream of that name; list the entry's streams to see which exist";
        WALK_PATTERN_INVALID = 611, "a search pattern is empty or malformed; patterns are globs such as *.evtx, **/config/SYSTEM or Users/*/NTUSER.DAT";
        FS_OPENED = 612, "a file system was opened; its kind, label and size";
        FS_PATH_ESCAPES = 613, "a path tries to climb above the root with '..'; it was refused";
        WALK_STOPPED = 614, "the caller stopped the walk before the end";
        FS_DELETED_UNSUPPORTED = 615, "this file system keeps no trace of deleted files that the reader can list (folders, zips, XFS); NTFS and ext volumes do, open the image instead of a copied tree";
        FS_DELETED_NOT_FOUND = 616, "no deleted entry has that record or inode number under $DELETED; list $DELETED to see the ones there are";
        FS_DELETED_UNRECOVERABLE = 617, "the deleted entry's metadata is listed but its content cannot be read back: a directory, clusters reused or unknown, compressed data, or a bare $MFT without the volume";
        FS_DELETED_LISTED = 618, "the deleted entries of a file system were listed: how many, how many recoverable";
    }
}

/// What a file system is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FsKind {
    Ntfs,
    Ext,
    Xfs,
    Folder,
    Zip,
    /// A tar read in place (a compressed one through its single decompressed copy).
    Tar,
}

impl FsKind {
    /// Short label.
    pub fn label(&self) -> &'static str {
        match self {
            FsKind::Ntfs => "NTFS",
            FsKind::Ext => "ext4",
            FsKind::Xfs => "XFS",
            FsKind::Folder => "folder",
            FsKind::Zip => "zip",
            FsKind::Tar => "tar",
        }
    }

    /// Does name lookup ignore case?
    pub fn case_insensitive(&self) -> bool {
        matches!(self, FsKind::Ntfs | FsKind::Zip | FsKind::Folder | FsKind::Tar)
    }
}

/// What an entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    /// Device, socket, fifo, or anything else.
    Other,
}

/// An alternate data stream of an NTFS file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub name: String,
    pub size: u64,
}

/// One file, directory or link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// `/`-separated, leading `/`, as the file system spells it.
    pub path: String,
    /// The last component.
    pub name: String,
    pub kind: EntryKind,
    /// Content size (0 for directories).
    pub size: u64,
    pub times: Timestamps,
    /// MFT record number, inode number, or 0 where the source has none.
    pub id: u64,
    /// NTFS alternate data streams (empty elsewhere).
    pub streams: Vec<Stream>,
    /// Target of a symbolic link, when known.
    pub link_target: Option<String>,
    /// The entry is a deleted file or directory recovered from file system metadata
    /// (an `$MFT` record not in use, an ext4 journal copy); its `path` starts with
    /// [`DELETED_DIR`].
    pub deleted: bool,
    /// A deleted entry whose content can still be read back through `copy_to`.
    pub recoverable: bool,
    /// When the entry was deleted, where the file system records it (ext4 `dtime`).
    pub deleted_at: Option<crate::time::Timestamp>,
}

impl Entry {
    /// A bare entry; callers fill the rest.
    pub fn new(path: &str, kind: EntryKind) -> Self {
        let path = normalize(path);
        let name = path.rsplit('/').next().unwrap_or("").to_string();
        Entry { path, name, kind, size: 0, times: Timestamps::default(), id: 0, streams: Vec::new(), link_target: None, deleted: false, recoverable: false, deleted_at: None }
    }

    /// Is it a directory?
    pub fn is_dir(&self) -> bool {
        self.kind == EntryKind::Dir
    }

    /// Is it a regular file?
    pub fn is_file(&self) -> bool {
        self.kind == EntryKind::File
    }

    /// The extension, lower case, without the dot.
    pub fn extension(&self) -> Option<String> {
        let (stem, ext) = self.name.rsplit_once('.')?;
        if stem.is_empty() {
            return None;
        }
        Some(ext.to_lowercase())
    }

    /// Parent path (`/` for top-level entries, None for the root).
    pub fn parent(&self) -> Option<String> {
        if self.path == "/" {
            return None;
        }
        let p = self.path.rsplit_once('/').map(|(a, _)| a).unwrap_or("");
        Some(if p.is_empty() { "/".to_string() } else { p.to_string() })
    }

    /// Depth below the root (`/a` is 1).
    pub fn depth(&self) -> usize {
        if self.path == "/" {
            0
        } else {
            self.path.matches('/').count()
        }
    }
}

/// The virtual folder deleted entries live under: `/$DELETED/<id>/<original path>`,
/// where `<id>` is the `$MFT` record number or the inode (with `.v<seq>` for an earlier
/// version of a file that still exists). It is never listed by `read_dir("/")`; ask for it.
pub const DELETED_DIR: &str = "$DELETED";

/// Builds the path of a deleted entry: `/$DELETED/<id><original path>`.
pub fn deleted_path(id: &str, original: &str) -> String {
    let orig = normalize(original);
    if orig == "/" {
        format!("/{DELETED_DIR}/{id}")
    } else {
        format!("/{DELETED_DIR}/{id}{orig}")
    }
}

/// Splits a `$DELETED` path into `(id, original path)`; `None` for any other path.
pub fn parse_deleted(path: &str) -> Option<(String, String)> {
    let norm = normalize(path);
    let parts = components(&norm);
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case(DELETED_DIR) {
        return None;
    }
    let rest = if parts.len() > 2 { format!("/{}", parts[2..].join("/")) } else { "/".to_string() };
    Some((parts[1].to_string(), rest))
}

/// Is the path the `$DELETED` folder itself?
pub fn is_deleted_root(path: &str) -> bool {
    let norm = normalize(path);
    let parts = components(&norm);
    parts.len() == 1 && parts[0].eq_ignore_ascii_case(DELETED_DIR)
}

/// `/`-separated, leading `/`, no trailing `/` (except the root), `.` and empty components
/// dropped, `..` resolved against the path itself (never above the root).
pub fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let unified = path.replace('\\', "/");
    for c in unified.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            x => parts.push(x),
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Does the path try to climb above the root?
pub fn escapes(path: &str) -> bool {
    let mut depth: i64 = 0;
    let unified = path.replace('\\', "/");
    for c in unified.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

/// The components of a normalized path.
pub fn components(path: &str) -> Vec<&str> {
    path.split('/').filter(|c| !c.is_empty()).collect()
}

/// Joins a directory and a name.
pub fn join(dir: &str, name: &str) -> String {
    if dir == "/" || dir.is_empty() {
        format!("/{name}")
    } else {
        format!("{}/{name}", dir.trim_end_matches('/'))
    }
}

/// Who may receive the bytes of a file: anything that writes.
pub type Sink<'a> = &'a mut dyn Write;

/// Progress of a copy: bytes done, bytes expected (0 when unknown).
pub type Progress<'a> = &'a mut dyn FnMut(u64, u64);

/// A read-only file system.
pub trait FileSystem {
    /// What it is.
    fn kind(&self) -> FsKind;

    /// Volume label, if the file system has one.
    fn label(&self) -> Option<String> {
        None
    }

    /// Size of the volume in bytes, if known.
    fn size(&self) -> Option<u64> {
        None
    }

    /// The entry at a path (links are described, not followed).
    fn metadata(&self, path: &str) -> Result<Entry>;

    /// The entries of a directory, sorted by name.
    fn read_dir(&self, path: &str) -> Result<Vec<Entry>>;

    /// Streams the content of a file (or of one of its alternate data streams) into
    /// `sink`, calling `progress` as it goes. Returns the bytes written.
    fn copy_to(&self, path: &str, stream: Option<&str>, sink: Sink<'_>, progress: Option<Progress<'_>>) -> Result<u64>;

    /// The content of a file up to `limit` bytes (refused above it with [`code::FS_FILE_TOO_LARGE`]).
    fn read(&self, path: &str, stream: Option<&str>, limit: u64) -> Result<Vec<u8>> {
        let meta = self.metadata(path)?;
        let size = match stream {
            Some(s) => meta.streams.iter().find(|x| x.name.eq_ignore_ascii_case(s)).map(|x| x.size).unwrap_or(meta.size),
            None => meta.size,
        };
        if size > limit {
            return Err(Error::recorded(code::FS_FILE_TOO_LARGE, format!("{path}: {size} bytes, limit {limit}")));
        }
        let mut out = Vec::with_capacity(size as usize);
        self.copy_to(path, stream, &mut out, None)?;
        Ok(out)
    }

    /// The content as text (lossy UTF-8), up to `limit` bytes.
    fn read_to_string(&self, path: &str, limit: u64) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.read(path, None, limit)?).into_owned())
    }

    /// Does the path exist?
    fn exists(&self, path: &str) -> bool {
        self.metadata(path).is_ok()
    }

    /// Can this file system list deleted entries?
    fn supports_deleted(&self) -> bool {
        false
    }

    /// The deleted entries the metadata still describes, each with a path under
    /// [`DELETED_DIR`] that `metadata`, `copy_to` and `read` accept. The first call does
    /// the work (a scan of the `$MFT`, of the ext4 journal); `progress` gets bytes read
    /// and total. Sorted by id.
    fn deleted(&self, progress: Option<Progress<'_>>) -> Result<Vec<Entry>> {
        let _ = progress;
        Err(Error::new(code::FS_DELETED_UNSUPPORTED, self.kind().label().to_string()))
    }
}

/// What the walk should do after an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkStep {
    /// Go on (into the directory, if it is one).
    Continue,
    /// Do not descend into this directory.
    SkipDir,
    /// End the walk now.
    Stop,
}

/// Limits of a walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalkOptions {
    /// Deepest directory level listed (the root's children are depth 1).
    pub max_depth: usize,
    /// Entries visited before the walk stops.
    pub max_files: usize,
    /// Directory names never descended into (compared ignoring case).
    pub skip_dirs: Vec<String>,
}

impl Default for WalkOptions {
    fn default() -> Self {
        WalkOptions { max_depth: 64, max_files: 10_000_000, skip_dirs: Vec::new() }
    }
}

/// What a walk did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalkStats {
    pub files: usize,
    pub dirs: usize,
    pub links: usize,
    pub others: usize,
    pub bytes: u64,
    /// Directories that could not be listed.
    pub errors: usize,
    /// Ended by a limit or by the caller.
    pub truncated: bool,
}

impl WalkStats {
    /// Every entry visited.
    pub fn entries(&self) -> usize {
        self.files + self.dirs + self.links + self.others
    }
}

/// Walks `root` depth-first, directories before their content, names in order. `f` is
/// called for every entry (the root itself excluded).
pub fn walk(fs: &dyn FileSystem, root: &str, opts: &WalkOptions, f: &mut dyn FnMut(&Entry) -> WalkStep) -> WalkStats {
    let mut stats = WalkStats::default();
    let root = normalize(root);
    walk_dir(fs, &root, 0, opts, f, &mut stats);
    stats
}

/// One directory, pre-order: each entry is reported, then a directory's content follows
/// before the next sibling. Returns false when the walk must stop.
fn walk_dir(fs: &dyn FileSystem, dir: &str, depth: usize, opts: &WalkOptions, f: &mut dyn FnMut(&Entry) -> WalkStep, stats: &mut WalkStats) -> bool {
    if depth >= opts.max_depth {
        diag::info(code::WALK_DEPTH_LIMIT, format!("{dir}: depth {depth}"));
        stats.truncated = true;
        return true;
    }
    let entries = match fs.read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            stats.errors += 1;
            diag::warn(code::WALK_DIR_UNREADABLE, format!("{dir}: {e}"));
            return true;
        }
    };
    for e in &entries {
        if stats.entries() >= opts.max_files {
            diag::warn(code::WALK_FILE_LIMIT, format!("{} entries", stats.entries()));
            stats.truncated = true;
            return false;
        }
        match e.kind {
            EntryKind::File => {
                stats.files += 1;
                stats.bytes += e.size;
            }
            EntryKind::Dir => stats.dirs += 1,
            EntryKind::Symlink => stats.links += 1,
            EntryKind::Other => stats.others += 1,
        }
        match f(e) {
            WalkStep::Continue => {
                if e.kind == EntryKind::Dir && !opts.skip_dirs.iter().any(|s| s.eq_ignore_ascii_case(&e.name)) && !walk_dir(fs, &e.path, depth + 1, opts, f, stats) {
                    return false;
                }
            }
            WalkStep::SkipDir => {}
            WalkStep::Stop => {
                diag::info(code::WALK_STOPPED, e.path.clone());
                stats.truncated = true;
                return false;
            }
        }
    }
    true
}

/// A case-insensitive glob over `/`-paths: `*` matches within a component, `?` one
/// character, `**` any number of components. A pattern without `/` matches the name
/// alone; one with `/` matches the full path, from the root or from any component when
/// it starts with `**/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Glob {
    pattern: String,
    on_name: bool,
    anchored: bool,
}

impl Glob {
    /// Compiles a pattern.
    pub fn new(pattern: &str) -> Result<Self> {
        let p = pattern.trim().replace('\\', "/");
        if p.is_empty() || p == "/" {
            return Err(Error::recorded(code::WALK_PATTERN_INVALID, format!("'{pattern}'")));
        }
        let on_name = !p.contains('/');
        let anchored = p.starts_with('/');
        let p = if anchored || on_name || p.starts_with("**/") { p } else { format!("**/{p}") };
        Ok(Glob { pattern: p.to_lowercase(), on_name, anchored })
    }

    /// Does the entry match?
    pub fn matches(&self, entry: &Entry) -> bool {
        if self.on_name {
            glob_match(&self.pattern, &entry.name.to_lowercase())
        } else {
            let path = entry.path.to_lowercase();
            let subject = if self.anchored { path } else { path.trim_start_matches('/').to_string() };
            glob_match(self.pattern.trim_start_matches('/'), subject.trim_start_matches('/')) || (self.anchored && glob_match(&self.pattern, &entry.path.to_lowercase()))
        }
    }
}

/// Glob matching with `*` (within a component), `?` and `**` (across components).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(p: &[char], t: &[char]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        if p.len() >= 2 && p[0] == '*' && p[1] == '*' {
            // `**/` or `**`: swallow any run of components.
            let rest = if p.len() >= 3 && p[2] == '/' { &p[3..] } else { &p[2..] };
            if rec(rest, t) {
                return true;
            }
            for (i, c) in t.iter().enumerate() {
                if *c == '/' && rec(rest, &t[i + 1..]) {
                    return true;
                }
            }
            // `**` at the end matches everything left.
            return rest.is_empty();
        }
        match p[0] {
            '*' => {
                let mut i = 0;
                loop {
                    if rec(&p[1..], &t[i..]) {
                        return true;
                    }
                    if i >= t.len() || t[i] == '/' {
                        return false;
                    }
                    i += 1;
                }
            }
            '?' => !t.is_empty() && t[0] != '/' && rec(&p[1..], &t[1..]),
            c => !t.is_empty() && t[0] == c && rec(&p[1..], &t[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    rec(&p, &t)
}

/// Every entry under `root` matching any of the globs, in walk order.
pub fn find(fs: &dyn FileSystem, root: &str, globs: &[Glob], opts: &WalkOptions) -> Vec<Entry> {
    let mut out = Vec::new();
    walk(fs, root, opts, &mut |e| {
        if globs.iter().any(|g| g.matches(e)) {
            out.push(e.clone());
        }
        WalkStep::Continue
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_paths() {
        assert_eq!(normalize("Windows\\System32\\config"), "/Windows/System32/config");
        assert_eq!(normalize("/a//b/./c/"), "/a/b/c");
        assert_eq!(normalize("/a/b/../c"), "/a/c");
        assert_eq!(normalize("../../x"), "/x");
        assert_eq!(normalize(""), "/");
        assert_eq!(normalize("/"), "/");
        assert_eq!(normalize("."), "/");
        assert!(escapes("../x"));
        assert!(escapes("a/../../x"));
        assert!(!escapes("a/../x"));
        assert!(!escapes("/a/b"));
        assert_eq!(components("/a/b/c"), vec!["a", "b", "c"]);
        assert!(components("/").is_empty());
        assert_eq!(join("/", "x"), "/x");
        assert_eq!(join("/a/", "x"), "/a/x");
        assert_eq!(join("", "x"), "/x");
    }

    #[test]
    fn entry_helpers() {
        let e = Entry::new("Users\\bob\\NTUSER.DAT", EntryKind::File);
        assert_eq!(e.path, "/Users/bob/NTUSER.DAT");
        assert_eq!(e.name, "NTUSER.DAT");
        assert_eq!(e.extension().as_deref(), Some("dat"));
        assert_eq!(e.parent().as_deref(), Some("/Users/bob"));
        assert_eq!(e.depth(), 3);
        assert!(e.is_file() && !e.is_dir());
        let root = Entry::new("/", EntryKind::Dir);
        assert_eq!(root.parent(), None);
        assert_eq!(root.depth(), 0);
        assert_eq!(root.name, "");
        let top = Entry::new("/SYSTEM", EntryKind::File);
        assert_eq!(top.parent().as_deref(), Some("/"));
        assert_eq!(top.extension(), None);
        assert_eq!(Entry::new("/.bashrc", EntryKind::File).extension(), None);
        assert_eq!(FsKind::Ntfs.label(), "NTFS");
        assert!(FsKind::Ntfs.case_insensitive() && !FsKind::Ext.case_insensitive());
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("*.evtx", "security.evtx"));
        assert!(!glob_match("*.evtx", "logs/security.evtx"), "* stays inside a component");
        assert!(glob_match("**/*.evtx", "logs/security.evtx"));
        assert!(glob_match("**/*.evtx", "security.evtx"));
        assert!(glob_match("windows/**/config/system", "windows/system32/config/system"));
        assert!(glob_match("windows/**", "windows/a/b/c"));
        assert!(glob_match("users/*/ntuser.dat", "users/bob/ntuser.dat"));
        assert!(!glob_match("users/*/ntuser.dat", "users/bob/x/ntuser.dat"));
        assert!(glob_match("s?stem", "system"));
        assert!(!glob_match("s?stem", "sstem"));
        assert!(glob_match("**", "anything/at/all"));
        assert!(!glob_match("a", "b"));
    }

    #[test]
    fn glob_on_entries() {
        let e = Entry::new("/Windows/System32/config/SYSTEM", EntryKind::File);
        assert!(Glob::new("system").unwrap().matches(&e));
        assert!(Glob::new("SYSTEM").unwrap().matches(&e));
        assert!(Glob::new("config/SYSTEM").unwrap().matches(&e), "a relative path pattern floats");
        assert!(Glob::new("**/config/SYSTEM").unwrap().matches(&e));
        assert!(Glob::new("/Windows/System32/config/SYSTEM").unwrap().matches(&e));
        assert!(Glob::new("/Windows/**/SYSTEM").unwrap().matches(&e));
        assert!(!Glob::new("/System32/config/SYSTEM").unwrap().matches(&e), "anchored patterns start at the root");
        assert!(Glob::new("Windows\\System32\\config\\*").unwrap().matches(&e));
        assert!(!Glob::new("*.evtx").unwrap().matches(&e));
        crate::diag::set_quiet(true);
        assert_eq!(Glob::new("  ").unwrap_err().code, code::WALK_PATTERN_INVALID);
        assert_eq!(Glob::new("/").unwrap_err().code, code::WALK_PATTERN_INVALID);
    }

    #[test]
    fn deleted_paths_build_and_parse() {
        assert_eq!(deleted_path("1234", "/Users/bob/x.txt"), "/$DELETED/1234/Users/bob/x.txt");
        assert_eq!(deleted_path("77.v3", "/"), "/$DELETED/77.v3");
        assert_eq!(parse_deleted("/$DELETED/1234/Users/bob/x.txt"), Some(("1234".to_string(), "/Users/bob/x.txt".to_string())));
        assert_eq!(parse_deleted("$deleted/9"), Some(("9".to_string(), "/".to_string())));
        assert_eq!(parse_deleted("/$DELETED"), None);
        assert_eq!(parse_deleted("/Users/$DELETED/1"), None);
        assert!(is_deleted_root("/$DELETED") && is_deleted_root("$DELETED/") && !is_deleted_root("/$DELETED/1") && !is_deleted_root("/"));
        let e = Entry::new(&deleted_path("5", "/a/b.txt"), EntryKind::File);
        assert_eq!(e.name, "b.txt");
        assert!(!e.deleted && !e.recoverable, "flags are the source's to set");
    }

    #[test]
    fn walk_options_default_are_generous() {
        let o = WalkOptions::default();
        assert!(o.max_depth >= 32 && o.max_files >= 1_000_000 && o.skip_dirs.is_empty());
        let s = WalkStats { files: 1, dirs: 2, links: 3, others: 4, ..Default::default() };
        assert_eq!(s.entries(), 10);
    }
}
