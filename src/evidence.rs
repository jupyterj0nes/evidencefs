//! One piece of evidence, whatever it is, as a list of mounts: every readable volume of
//! an image (and every shadow copy and logical volume inside), a folder, a zip, an
//! unpacked tar, or the folder around a single file. Tools walk the mounts the same way.

use std::path::{Path, PathBuf};

use crate::archive::{self, ArchiveKind, TempDir};
use crate::diag;
use crate::error::{Error, Result};
use crate::fs::{self, Entry, FileSystem, FsKind, Glob, WalkOptions, WalkStats, WalkStep};
use crate::source::{self, Image, ImageKind};
use crate::triage::{self, Roots, TriageInfo};
use crate::volume::{self, lvm::LogicalVolume, vss::Snapshot, Volume, VolumeKind};

pub mod code {
    crate::codes! {
        EVIDENCE_NOT_FOUND = 20, "the evidence path does not exist";
        EVIDENCE_KIND = 21, "what the evidence was taken for: image, folder, archive or single file";
        EVIDENCE_VOLUME_SKIPPED = 22, "a volume of the image could not be mounted; the others were, this one is listed without a mount";
        EVIDENCE_NO_MOUNTS = 23, "nothing in the evidence could be mounted; an image with only unsupported or encrypted volumes, or an archive format that is not read";
        EVIDENCE_MOUNTED = 24, "a mount was added: its label, kind and where it came from";
        EVIDENCE_SNAPSHOT_SKIPPED = 25, "a shadow copy could not be mounted; the live volume and the other snapshots were";
        EVIDENCE_NESTED_ARCHIVE = 26, "an archive inside the evidence was copied out and mounted as a nested mount";
        EVIDENCE_NESTED_SKIPPED = 27, "an archive inside the evidence was not opened: nesting limit reached, unsupported format, or it failed to open";
        EVIDENCE_TEMP = 28, "a temporary folder was created for unpacked archives; it is removed when the evidence is closed unless keep_temp was asked";
        EVIDENCE_SINGLE_FILE = 29, "the evidence is a single file; its folder is mounted and the file is the only entry of interest";
    }
}

/// What the evidence turned out to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    Image(ImageKind),
    Folder,
    Archive(ArchiveKind),
    /// One file: a hive, an evtx, a database.
    File,
}

impl EvidenceKind {
    /// Short label.
    pub fn label(&self) -> String {
        match self {
            EvidenceKind::Image(k) => format!("image ({})", k.label()),
            EvidenceKind::Folder => "folder".to_string(),
            EvidenceKind::Archive(k) => format!("archive ({})", k.label()),
            EvidenceKind::File => "file".to_string(),
        }
    }
}

/// Where a mount's bytes come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountSource {
    /// A partition of the image.
    Volume(Volume),
    /// A shadow copy of a partition.
    Snapshot { volume: Volume, snapshot: Snapshot },
    /// A logical volume inside an LVM partition.
    LogicalVolume { volume: Volume, lv: LogicalVolume },
    /// The evidence folder itself.
    Folder(PathBuf),
    /// An archive, read in place (zip) or unpacked (tar).
    Archive { path: PathBuf, kind: ArchiveKind },
    /// An archive found inside another mount, copied out and opened.
    Nested { parent: String, path: String, kind: ArchiveKind },
}

/// A readable tree inside the evidence.
pub struct Mount {
    /// `partition_0`, `partition_0_vss_1`, `partition_1_lvm_vg_root`, `folder`, `zip`,
    /// `zip/uploads/data.zip`: the prefix the tools put before paths (`<label>/Windows/...`).
    pub label: String,
    pub fs: Box<dyn FileSystem>,
    pub source: MountSource,
    /// Operating system roots found inside (filled by [`Evidence::locate_roots`]).
    pub roots: Roots,
}

impl Mount {
    /// `<label>:<path>` or `<label>/<path>`, the way the c00pr tools cite a source file.
    pub fn source_path(&self, entry_path: &str) -> String {
        format!("{}{}", self.label, entry_path)
    }

    /// The file system kind.
    pub fn kind(&self) -> FsKind {
        self.fs.kind()
    }

    /// Is this a shadow copy?
    pub fn is_snapshot(&self) -> bool {
        matches!(self.source, MountSource::Snapshot { .. })
    }

    /// The snapshot, if this mount is one.
    pub fn snapshot(&self) -> Option<&Snapshot> {
        match &self.source {
            MountSource::Snapshot { snapshot, .. } => Some(snapshot),
            _ => None,
        }
    }

    /// One line: label, kind, source.
    pub fn describe(&self) -> String {
        let src = match &self.source {
            MountSource::Volume(v) => v.describe(),
            MountSource::Snapshot { volume, snapshot } => format!("{} {}", volume.describe(), snapshot.tag()),
            MountSource::LogicalVolume { volume, lv } => format!("{} LV {}", volume.describe(), lv.label()),
            MountSource::Folder(p) => p.display().to_string(),
            MountSource::Archive { path, kind } => format!("{} ({})", path.display(), kind.label()),
            MountSource::Nested { parent, path, kind } => format!("{parent}{path} ({})", kind.label()),
        };
        format!("{}: {}{} [{}]", self.label, self.fs.kind().label(), self.fs.label().map(|l| format!(" \"{l}\"")).unwrap_or_default(), src)
    }
}

/// How to open evidence.
#[derive(Clone, Debug)]
pub struct OpenOptions {
    /// Mount the Volume Shadow Copies of NTFS volumes.
    pub snapshots: bool,
    /// Open LVM physical volumes and mount their logical volumes.
    pub lvm: bool,
    /// How many levels of archives inside archives/folders to open (0: none).
    pub nested_archives: usize,
    /// Largest nested archive copied out for opening (default 4 GB).
    pub nested_max_bytes: u64,
    /// Where temporary unpacked data goes (default: the system temp dir).
    pub temp_dir: Option<PathBuf>,
    /// Leave the temporary folder on disk when the evidence is dropped.
    pub keep_temp: bool,
    /// Levels searched for operating system roots in folders and archives.
    pub root_search_depth: usize,
}

impl Default for OpenOptions {
    fn default() -> Self {
        OpenOptions { snapshots: true, lvm: true, nested_archives: 2, nested_max_bytes: 4 << 30, temp_dir: None, keep_temp: false, root_search_depth: 4 }
    }
}

/// One match of [`Evidence::find`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub mount: usize,
    pub entry: Entry,
}

/// A piece of evidence with its mounts.
pub struct Evidence {
    pub path: PathBuf,
    pub kind: EvidenceKind,
    pub image: Option<Image>,
    /// Every partition of the image, mounted or not.
    pub volumes: Vec<Volume>,
    pub mounts: Vec<Mount>,
    pub triage: Option<TriageInfo>,
    /// For a single-file evidence, the entry path inside its mount.
    pub single_file: Option<String>,
    temp: Option<TempDir>,
}

impl std::fmt::Debug for Evidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Evidence({} {}, {} mount(s))", self.kind.label(), self.path.display(), self.mounts.len())
    }
}

impl Evidence {
    /// Opens anything: an image, a folder, an archive, a file.
    pub fn open(path: &Path, opts: &OpenOptions) -> Result<Self> {
        let meta = std::fs::metadata(path).map_err(|e| Error::recorded(code::EVIDENCE_NOT_FOUND, format!("{}: {e}", path.display())))?;
        let mut ev = Evidence { path: path.to_path_buf(), kind: EvidenceKind::Folder, image: None, volumes: Vec::new(), mounts: Vec::new(), triage: None, single_file: None, temp: None };
        if meta.is_dir() {
            ev.kind = EvidenceKind::Folder;
            let fs = fs::folder::FolderFs::open(path)?;
            ev.add_mount("folder", Box::new(fs), MountSource::Folder(path.to_path_buf()));
        } else if source::is_image_file(path) && !source::is_secondary_image_segment(path) || (archive::kind_by_extension(path).is_none() && source::sniff_image(path).is_some()) {
            ev.open_image(opts)?;
        } else if source::is_secondary_image_segment(path) && source::sniff_image(path).is_none() && archive::kind_by_extension(path).is_none() {
            return Err(Error::recorded(source::code::IMAGE_SECONDARY_SEGMENT, path.display().to_string()));
        } else if let Some(kind) = archive::archive_kind(path) {
            ev.open_archive(kind, opts)?;
        } else {
            ev.kind = EvidenceKind::File;
            let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
            let fs = fs::folder::FolderFs::open(&parent)?;
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            ev.single_file = Some(format!("/{name}"));
            diag::info(code::EVIDENCE_SINGLE_FILE, format!("{}: in {}", name, parent.display()));
            ev.add_mount("file", Box::new(fs), MountSource::Folder(parent));
        }
        diag::info(code::EVIDENCE_KIND, format!("{}: {}", path.display(), ev.kind.label()));
        if ev.single_file.is_none() {
            ev.mount_nested_archives(opts);
            ev.detect_triage();
            ev.locate_roots(opts.root_search_depth);
        }
        if ev.mounts.is_empty() {
            diag::warn(code::EVIDENCE_NO_MOUNTS, path.display().to_string());
        }
        Ok(ev)
    }

    fn add_mount(&mut self, label: &str, fs: Box<dyn FileSystem>, source: MountSource) {
        let m = Mount { label: label.to_string(), fs, source, roots: Roots::default() };
        diag::info(code::EVIDENCE_MOUNTED, m.describe());
        self.mounts.push(m);
    }

    fn open_image(&mut self, opts: &OpenOptions) -> Result<()> {
        let image = source::open_image(&self.path)?;
        self.kind = EvidenceKind::Image(image.kind);
        let volumes = volume::list_volumes(&image.reader);
        for v in &volumes {
            let label = v.dir_name();
            let view = v.reader(&image.reader);
            match v.kind {
                VolumeKind::Ntfs => {
                    match fs::ntfs::NtfsFs::open(view.clone(), &label) {
                        Ok(fs) => self.add_mount(&label, Box::new(fs), MountSource::Volume(v.clone())),
                        Err(e) => {
                            diag::warn(code::EVIDENCE_VOLUME_SKIPPED, format!("{label}: {e}"));
                            continue;
                        }
                    }
                    if opts.snapshots {
                        self.mount_snapshots(v, &view);
                    }
                }
                VolumeKind::Ext => match fs::ext::ExtFs::open(view, &label) {
                    Ok(fs) => self.add_mount(&label, Box::new(fs), MountSource::Volume(v.clone())),
                    Err(e) => {
                        diag::warn(code::EVIDENCE_VOLUME_SKIPPED, format!("{label}: {e}"));
                    }
                },
                VolumeKind::Xfs => match fs::xfs::XfsFs::open(view, &label) {
                    Ok(fs) => self.add_mount(&label, Box::new(fs), MountSource::Volume(v.clone())),
                    Err(e) => {
                        diag::warn(code::EVIDENCE_VOLUME_SKIPPED, format!("{label}: {e}"));
                    }
                },
                VolumeKind::Lvm if opts.lvm => match volume::lvm::PhysicalVolume::open(view, &label) {
                    Ok(pv) => {
                        for lv in pv.logical_volumes() {
                            let lv_label = lv.dir_name(v.index);
                            let reader = pv.reader(lv);
                            let mounted: Result<Box<dyn FileSystem>> = match lv.kind {
                                VolumeKind::Ext => fs::ext::ExtFs::open(reader, &lv_label).map(|f| Box::new(f) as Box<dyn FileSystem>),
                                VolumeKind::Xfs => fs::xfs::XfsFs::open(reader, &lv_label).map(|f| Box::new(f) as Box<dyn FileSystem>),
                                VolumeKind::Ntfs => fs::ntfs::NtfsFs::open(reader, &lv_label).map(|f| Box::new(f) as Box<dyn FileSystem>),
                                other => {
                                    diag::info(volume::code::PART_FS_UNSUPPORTED, format!("{lv_label}: {}", other.label()));
                                    continue;
                                }
                            };
                            match mounted {
                                Ok(f) => self.add_mount(&lv_label, f, MountSource::LogicalVolume { volume: v.clone(), lv: lv.clone() }),
                                Err(e) => {
                                    diag::warn(code::EVIDENCE_VOLUME_SKIPPED, format!("{lv_label}: {e}"));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        diag::warn(code::EVIDENCE_VOLUME_SKIPPED, format!("{label}: {e}"));
                    }
                },
                _ => {}
            }
        }
        self.volumes = volumes;
        self.image = Some(image);
        Ok(())
    }

    fn mount_snapshots(&mut self, v: &Volume, view: &source::SharedReader) {
        let label = v.dir_name();
        let snaps = match volume::vss::list_snapshots(view, &label) {
            Ok(s) => s,
            Err(_) => return,
        };
        for s in snaps {
            let slabel = s.dir_name(v.index);
            let reader = match volume::vss::snapshot_reader(view, s.index, &slabel) {
                Ok(r) => r,
                Err(e) => {
                    diag::warn(code::EVIDENCE_SNAPSHOT_SKIPPED, format!("{slabel}: {e}"));
                    continue;
                }
            };
            match fs::ntfs::NtfsFs::open(reader, &slabel) {
                Ok(fs) => self.add_mount(&slabel, Box::new(fs), MountSource::Snapshot { volume: v.clone(), snapshot: s }),
                Err(e) => {
                    diag::warn(code::EVIDENCE_SNAPSHOT_SKIPPED, format!("{slabel}: {e}"));
                }
            }
        }
    }

    fn temp(&mut self, opts: &OpenOptions) -> Result<PathBuf> {
        if self.temp.is_none() {
            let hint = self.path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            let mut t = TempDir::new(opts.temp_dir.as_deref(), &hint)?;
            if opts.keep_temp {
                t.keep();
            }
            diag::info(code::EVIDENCE_TEMP, t.path().display().to_string());
            self.temp = Some(t);
        }
        Ok(self.temp.as_ref().expect("just set").path().to_path_buf())
    }

    fn open_archive(&mut self, kind: ArchiveKind, opts: &OpenOptions) -> Result<()> {
        self.kind = EvidenceKind::Archive(kind);
        let path = self.path.clone();
        match kind {
            ArchiveKind::Zip => {
                let fs = fs::zipfs::ZipFs::open(&path)?;
                self.add_mount("zip", Box::new(fs), MountSource::Archive { path, kind });
            }
            ArchiveKind::Tar | ArchiveKind::TarGz => {
                let temp = self.temp(opts)?;
                let dest = temp.join("tar");
                archive::unpack_tar(&path, &dest, None)?;
                let fs = fs::folder::FolderFs::open(&dest)?;
                self.add_mount("tar", Box::new(fs), MountSource::Archive { path, kind });
            }
            other => return Err(Error::recorded(archive::code::ARCHIVE_UNSUPPORTED, format!("{}: {}", path.display(), other.label()))),
        }
        Ok(())
    }

    /// Finds archives inside the mounts (first levels only) and opens them as nested mounts.
    fn mount_nested_archives(&mut self, opts: &OpenOptions) {
        if opts.nested_archives == 0 {
            return;
        }
        let mut level = 0;
        let mut from = 0;
        while level < opts.nested_archives && from < self.mounts.len() {
            let upto = self.mounts.len();
            let mut candidates: Vec<(usize, Entry)> = Vec::new();
            for (mi, m) in self.mounts.iter().enumerate().skip(from).take(upto - from) {
                // Images are not scanned for archives: that is a tool's decision.
                if matches!(m.source, MountSource::Volume(_) | MountSource::Snapshot { .. } | MountSource::LogicalVolume { .. }) {
                    continue;
                }
                let walk_opts = WalkOptions { max_depth: 3, max_files: 20_000, ..Default::default() };
                fs::walk(m.fs.as_ref(), "/", &walk_opts, &mut |e| {
                    if e.is_file() && archive::kind_by_extension(Path::new(&e.name)).is_some() {
                        candidates.push((mi, e.clone()));
                    }
                    WalkStep::Continue
                });
            }
            from = upto;
            for (mi, e) in candidates {
                let kind = archive::kind_by_extension(Path::new(&e.name)).expect("filtered");
                let parent_label = self.mounts[mi].label.clone();
                if !kind.is_supported() {
                    diag::info(code::EVIDENCE_NESTED_SKIPPED, format!("{parent_label}{}: {}", e.path, kind.label()));
                    continue;
                }
                if e.size > opts.nested_max_bytes {
                    diag::info(code::EVIDENCE_NESTED_SKIPPED, format!("{parent_label}{}: {} bytes", e.path, e.size));
                    continue;
                }
                let temp = match self.temp(opts) {
                    Ok(t) => t,
                    Err(_) => return,
                };
                let safe: String = e.path.trim_start_matches('/').chars().map(|c| if c == '/' || c == '\\' || c == ':' { '_' } else { c }).collect();
                let copy = temp.join(format!("nested{level}_{}_{safe}", mi));
                let copied = match crate::extract::extract_file(self.mounts[mi].fs.as_ref(), &e.path, None, &copy, true, None) {
                    Ok(_) => copy,
                    Err(err) => {
                        diag::info(code::EVIDENCE_NESTED_SKIPPED, format!("{parent_label}{}: {err}", e.path));
                        continue;
                    }
                };
                let label = format!("{parent_label}{}", e.path);
                let mounted: Result<Box<dyn FileSystem>> = match kind {
                    ArchiveKind::Zip => fs::zipfs::ZipFs::open(&copied).map(|f| Box::new(f) as Box<dyn FileSystem>),
                    _ => {
                        let dest = copied.with_extension("unpacked");
                        archive::unpack_tar(&copied, &dest, None).and_then(|_| fs::folder::FolderFs::open(&dest).map(|f| Box::new(f) as Box<dyn FileSystem>))
                    }
                };
                match mounted {
                    Ok(f) => {
                        diag::info(code::EVIDENCE_NESTED_ARCHIVE, label.clone());
                        self.add_mount(&label, f, MountSource::Nested { parent: parent_label, path: e.path.clone(), kind });
                    }
                    Err(err) => {
                        diag::info(code::EVIDENCE_NESTED_SKIPPED, format!("{label}: {err}"));
                    }
                }
            }
            level += 1;
        }
    }

    fn detect_triage(&mut self) {
        if !matches!(self.kind, EvidenceKind::Folder | EvidenceKind::Archive(_)) {
            return;
        }
        let name = self.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        for m in &self.mounts {
            if let Some(info) = triage::inspect(m.fs.as_ref(), &name) {
                self.triage = Some(info);
                return;
            }
        }
    }

    /// Finds the operating system roots in folder and archive mounts (image volumes are
    /// their own roots).
    pub fn locate_roots(&mut self, depth: usize) {
        for m in &mut self.mounts {
            m.roots = match &m.source {
                MountSource::Volume(_) | MountSource::Snapshot { .. } | MountSource::LogicalVolume { .. } => {
                    let fs = m.fs.as_ref();
                    let mut r = Roots::default();
                    if fs.exists("/Windows") || fs.exists("/windows") {
                        r.windows.push("/".to_string());
                    } else if fs.exists("/etc") {
                        r.linux.push("/".to_string());
                    }
                    r
                }
                _ => triage::locate_roots(m.fs.as_ref(), depth),
            };
        }
    }

    /// The host name: from the package name, else from `etc/hostname` of a Linux root.
    pub fn hostname(&self) -> Option<String> {
        if let Some(h) = self.triage.as_ref().and_then(|t| t.hostname.clone()) {
            return Some(h);
        }
        for m in &self.mounts {
            for root in &m.roots.linux {
                if let Some(h) = triage::linux_hostname(m.fs.as_ref(), root) {
                    return Some(h);
                }
            }
        }
        None
    }

    /// Walks every mount; `f` gets the mount index and the entry.
    pub fn walk_all(&self, opts: &WalkOptions, f: &mut dyn FnMut(usize, &Entry) -> WalkStep) -> WalkStats {
        let mut total = WalkStats::default();
        for (i, m) in self.mounts.iter().enumerate() {
            let s = fs::walk(m.fs.as_ref(), "/", opts, &mut |e| f(i, e));
            total.files += s.files;
            total.dirs += s.dirs;
            total.links += s.links;
            total.others += s.others;
            total.bytes += s.bytes;
            total.errors += s.errors;
            total.truncated |= s.truncated;
        }
        total
    }

    /// Every entry of every mount matching any of the patterns.
    pub fn find(&self, patterns: &[&str], opts: &WalkOptions) -> Result<Vec<Found>> {
        let globs: Vec<Glob> = patterns.iter().map(|p| Glob::new(p)).collect::<Result<_>>()?;
        let mut out = Vec::new();
        for (i, m) in self.mounts.iter().enumerate() {
            for e in fs::find(m.fs.as_ref(), "/", &globs, opts) {
                out.push(Found { mount: i, entry: e });
            }
        }
        Ok(out)
    }

    /// A summary: kind, volumes, mounts, triage.
    pub fn describe(&self) -> String {
        let mut s = format!("{}: {}", self.path.display(), self.kind.label());
        if let Some(img) = &self.image {
            s.push_str(&format!(", {} ({} segment(s))", volume::human_size(img.size), img.segments.len()));
        }
        if let Some(t) = &self.triage {
            s.push_str(&format!(", {}", t.kind.label()));
        }
        if let Some(h) = self.hostname() {
            s.push_str(&format!(", host {h}"));
        }
        for v in &self.volumes {
            s.push_str(&format!("\n  {}", v.describe()));
        }
        for m in &self.mounts {
            s.push_str(&format!("\n  mount {}", m.describe()));
            for r in &m.roots.windows {
                s.push_str(&format!(" [windows root {r}]"));
            }
            for r in &m.roots.linux {
                s.push_str(&format!(" [linux root {r}]"));
            }
        }
        s
    }

    /// The temporary folder in use, if any.
    pub fn temp_path(&self) -> Option<&Path> {
        self.temp.as_ref().map(|t| t.path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
    }

    #[test]
    fn folder_evidence_with_nested_zip_and_triage() {
        quiet();
        let d = std::env::temp_dir().join(format!("evidencefs-ev-folder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("C").join("Windows").join("System32").join("config")).unwrap();
        std::fs::write(d.join("C").join("Windows").join("System32").join("config").join("SYSTEM"), b"hive").unwrap();
        std::fs::write(d.join("_kape.cli"), b"x").unwrap();
        let z = crate::fs::zipfs::tests::sample_zip("ev-nested", &[("inner/notes.txt", b"inside")]);
        std::fs::copy(&z, d.join("exports").join("results.zip").with_file_name("results.zip")).ok();
        std::fs::create_dir_all(d.join("exports")).unwrap();
        std::fs::copy(&z, d.join("exports").join("results.zip")).unwrap();
        std::fs::write(d.join("exports").join("bundle.7z"), b"7z\xbc\xaf\x27\x1c").unwrap();
        let ev = Evidence::open(&d, &OpenOptions::default()).unwrap();
        assert_eq!(ev.kind, EvidenceKind::Folder);
        assert_eq!(ev.mounts.len(), 2, "{}", ev.describe());
        assert_eq!(ev.mounts[0].label, "folder");
        assert_eq!(ev.mounts[1].label, "folder/exports/results.zip");
        assert!(matches!(ev.mounts[1].source, MountSource::Nested { .. }));
        assert_eq!(ev.mounts[1].fs.read("/inner/notes.txt", None, 100).unwrap(), b"inside");
        assert_eq!(ev.triage.as_ref().map(|t| t.kind), Some(triage::TriageType::Kape));
        assert_eq!(ev.mounts[0].roots.windows, vec!["/C"]);
        assert!(crate::diag::has(code::EVIDENCE_NESTED_ARCHIVE));
        assert!(crate::diag::has(code::EVIDENCE_NESTED_SKIPPED), "the 7z is noted");
        assert!(ev.temp_path().is_some_and(|p| p.exists()));
        let found = ev.find(&["SYSTEM", "*.txt"], &WalkOptions::default()).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].mount, 0);
        assert_eq!(found[1].mount, 1);
        assert_eq!(ev.mounts[0].source_path("/C/Windows"), "folder/C/Windows");
        let mut n = 0;
        let stats = ev.walk_all(&WalkOptions::default(), &mut |_, _| {
            n += 1;
            WalkStep::Continue
        });
        assert_eq!(stats.entries(), n);
        assert!(stats.files >= 4);
        assert!(ev.describe().contains("KAPE"));
        assert!(format!("{ev:?}").contains("2 mount(s)"));
        let temp = ev.temp_path().unwrap().to_path_buf();
        drop(ev);
        assert!(!temp.exists(), "temp removed on drop");
        // No nesting when asked.
        let ev = Evidence::open(&d, &OpenOptions { nested_archives: 0, ..Default::default() }).unwrap();
        assert_eq!(ev.mounts.len(), 1);
        assert!(ev.temp_path().is_none());
        std::fs::remove_dir_all(&d).ok();
        std::fs::remove_file(&z).ok();
    }

    #[test]
    fn zip_tar_and_single_file_evidence() {
        quiet();
        let d = std::env::temp_dir().join(format!("evidencefs-ev-arch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let z = crate::fs::zipfs::tests::sample_zip("ev-zip", &[("Collection/uploads/auto/C%3A/Windows/System32/config/SYSTEM", b"hive"), ("Collection/client_info.json", b"{}"), ("Collection/collection_context.json", b"{}")]);
        let zpath = d.join("Collection-WS01-2026.zip");
        std::fs::copy(&z, &zpath).unwrap();
        let ev = Evidence::open(&zpath, &OpenOptions::default()).unwrap();
        assert_eq!(ev.kind, EvidenceKind::Archive(ArchiveKind::Zip));
        assert_eq!(ev.mounts[0].label, "zip");
        assert_eq!(ev.triage.as_ref().map(|t| t.kind), Some(triage::TriageType::Velociraptor));
        assert_eq!(ev.hostname().as_deref(), Some("WS01"));
        assert_eq!(ev.mounts[0].roots.windows, vec!["/Collection/uploads/auto/C%3A"]);
        // tar.gz with a Linux root.
        let tgz = crate::archive::tests::sample_tgz(&d, "lnx01-logs.tar.gz");
        let ev = Evidence::open(&tgz, &OpenOptions::default()).unwrap();
        assert_eq!(ev.kind, EvidenceKind::Archive(ArchiveKind::TarGz));
        assert_eq!(ev.mounts[0].label, "tar");
        assert_eq!(ev.mounts[0].fs.read_to_string("/etc/hostname", 100).unwrap(), "lnx01");
        assert_eq!(ev.mounts[0].roots.linux, vec!["/"]);
        assert_eq!(ev.hostname().as_deref(), Some("lnx01"));
        assert_eq!(ev.triage.as_ref().map(|t| t.kind), Some(triage::TriageType::Generic));
        // A single file.
        let hive = d.join("SYSTEM");
        std::fs::write(&hive, b"regf").unwrap();
        let ev = Evidence::open(&hive, &OpenOptions::default()).unwrap();
        assert_eq!(ev.kind, EvidenceKind::File);
        assert_eq!(ev.single_file.as_deref(), Some("/SYSTEM"));
        assert_eq!(ev.mounts[0].label, "file");
        assert_eq!(ev.mounts[0].fs.read("/SYSTEM", None, 10).unwrap(), b"regf");
        // Unsupported archive and missing path.
        std::fs::write(d.join("x.7z"), b"7z\xbc\xaf\x27\x1c").unwrap();
        assert_eq!(Evidence::open(&d.join("x.7z"), &OpenOptions::default()).unwrap_err().code, archive::code::ARCHIVE_UNSUPPORTED);
        assert_eq!(Evidence::open(&d.join("missing"), &OpenOptions::default()).unwrap_err().code, code::EVIDENCE_NOT_FOUND);
        std::fs::write(d.join("disk.E02"), b"junk").unwrap();
        assert_eq!(Evidence::open(&d.join("disk.E02"), &OpenOptions::default()).unwrap_err().code, source::code::IMAGE_SECONDARY_SEGMENT);
        std::fs::remove_dir_all(&d).ok();
        std::fs::remove_file(&z).ok();
    }

    #[test]
    fn image_evidence_lists_volumes_even_when_none_mounts() {
        quiet();
        let d = std::env::temp_dir().join(format!("evidencefs-ev-img-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut img = crate::volume::tests::blank(600);
        crate::volume::tests::mbr_entry(&mut img, 0, 0x07, 64, 300);
        img[64 * 512 + 3..64 * 512 + 11].copy_from_slice(b"-FVE-FS-");
        let p = d.join("locked.raw");
        std::fs::write(&p, &img).unwrap();
        let ev = Evidence::open(&p, &OpenOptions::default()).unwrap();
        assert_eq!(ev.kind, EvidenceKind::Image(ImageKind::Raw));
        assert_eq!(ev.volumes.len(), 1);
        assert_eq!(ev.volumes[0].kind, VolumeKind::BitLocker);
        assert!(ev.mounts.is_empty());
        assert!(crate::diag::has(code::EVIDENCE_NO_MOUNTS));
        assert!(crate::diag::has(volume::code::PART_BITLOCKER));
        assert!(ev.describe().contains("BitLocker"));
        // A fixed VHD with an NTFS signature but no real file system: the volume is listed, the mount fails with a code.
        crate::diag::drain();
        let mut img = crate::volume::tests::blank(600);
        crate::volume::tests::mbr_entry(&mut img, 0, 0x07, 64, 300);
        crate::volume::tests::stamp_ntfs(&mut img, 64 * 512);
        let v = crate::source::vhd::tests::write_fixed_vhd("ev.vhd", &img);
        let ev = Evidence::open(&v, &OpenOptions::default()).unwrap();
        assert_eq!(ev.kind, EvidenceKind::Image(ImageKind::Vhd));
        assert_eq!(ev.volumes[0].kind, VolumeKind::Ntfs);
        assert!(ev.mounts.is_empty());
        assert!(crate::diag::has(code::EVIDENCE_VOLUME_SKIPPED));
        std::fs::remove_file(&v).ok();
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn kinds_and_labels() {
        assert_eq!(EvidenceKind::Image(ImageKind::Ewf).label(), "image (E01)");
        assert_eq!(EvidenceKind::Archive(ArchiveKind::TarGz).label(), "archive (tar.gz)");
        assert_eq!(EvidenceKind::Folder.label(), "folder");
        assert_eq!(EvidenceKind::File.label(), "file");
        let o = OpenOptions::default();
        assert!(o.snapshots && o.lvm && o.nested_archives >= 1 && !o.keep_temp);
    }
}
