//! Tests over the lab evidence under `D:\evidence`. Each one is skipped silently when
//! its file is missing, so the suite is green on any machine and complete on the lab box.

use std::path::Path;

use evidencefs::{Evidence, EvidenceKind, FsKind, OpenOptions, WalkOptions, WalkStep};

fn lab(rel: &str) -> Option<std::path::PathBuf> {
    let p = Path::new(r"D:\evidence").join(rel);
    if p.exists() {
        Some(p)
    } else {
        eprintln!("skipped: {} is not on this machine", p.display());
        None
    }
}

fn quiet() {
    evidencefs::diag::set_quiet(true);
    evidencefs::diag::drain();
}

#[test]
fn carvelab_vhd_mounts_and_walks() {
    quiet();
    let Some(p) = lab(r"mixed-intake\carvelab.vhd") else { return };
    let ev = Evidence::open(&p, &OpenOptions::default()).expect("opens");
    eprintln!("{}", ev.describe());
    assert!(matches!(ev.kind, EvidenceKind::Image(evidencefs::ImageKind::Vhd)));
    assert!(!ev.volumes.is_empty(), "the VHD has a partition table or a whole-disk volume");
    assert!(!ev.mounts.is_empty(), "at least one volume mounts: {}", ev.describe());
    let m = &ev.mounts[0];
    let top = m.fs.read_dir("/").expect("root lists");
    assert!(!top.is_empty());
    let names: Vec<&str> = top.iter().map(|e| e.name.as_str()).collect();
    eprintln!("root: {names:?}");
    // Walk everything, twice, and expect the same result: reliability first.
    let mut a = Vec::new();
    let sa = ev.walk_all(&WalkOptions::default(), &mut |_, e| {
        a.push((e.path.clone(), e.size, e.times));
        WalkStep::Continue
    });
    let mut b = Vec::new();
    let sb = ev.walk_all(&WalkOptions::default(), &mut |_, e| {
        b.push((e.path.clone(), e.size, e.times));
        WalkStep::Continue
    });
    assert_eq!(a, b, "two walks give the same entries");
    assert_eq!(sa, sb);
    eprintln!("{} entries, {} files, {} bytes", sa.entries(), sa.files, sa.bytes);
    assert!(sa.files > 0);
    // Every file's content can be streamed and matches its size (first 200 files).
    let mut checked = 0;
    for (path, size, _) in a.iter().filter(|(p, _, _)| !p.ends_with('/')).take(400) {
        let Ok(meta) = m.fs.metadata(path) else { continue };
        if !meta.is_file() || *size > 32 << 20 {
            continue;
        }
        let mut sink = Vec::new();
        match m.fs.copy_to(path, None, &mut sink, None) {
            Ok(n) => {
                assert_eq!(n, *size, "{path}: bytes streamed equal the size");
                checked += 1;
            }
            Err(e) => eprintln!("{path}: {e}"),
        }
    }
    eprintln!("{checked} files streamed");
    assert!(checked > 0);
    if m.kind() == FsKind::Ntfs {
        // NTFS metafiles are ordinary entries.
        assert!(m.fs.exists("/$MFT"), "$MFT is listed");
        let mft = m.fs.metadata("/$MFT").unwrap();
        assert!(mft.size > 0 && mft.times.created.is_some());
    }
    // The diagnostics are a list of codes, not a wall of text.
    let diags = evidencefs::diag::drain();
    let codes: std::collections::BTreeSet<String> = diags.iter().map(|d| d.code.to_string()).collect();
    eprintln!("codes: {codes:?}");
}

#[test]
fn real_ext4_image_lists_etc_and_reads_hostname() {
    quiet();
    let Some(p) = lab(r"mixed-intake\real_ext4.img") else { return };
    let ev = Evidence::open(&p, &OpenOptions::default()).expect("opens");
    eprintln!("{}", ev.describe());
    assert!(!ev.mounts.is_empty(), "{}", ev.describe());
    let m = ev.mounts.iter().find(|m| m.kind() == FsKind::Ext).expect("an ext mount");
    let top = m.fs.read_dir("/").unwrap();
    let names: Vec<&str> = top.iter().map(|e| e.name.as_str()).collect();
    eprintln!("root: {names:?}");
    assert!(names.iter().any(|n| *n == "etc" || *n == "lost+found" || *n == "home"), "a Linux root: {names:?}");
    if m.fs.exists("/etc/hostname") {
        let h = m.fs.read_to_string("/etc/hostname", 4096).unwrap();
        eprintln!("hostname: {}", h.trim());
        assert!(!h.trim().is_empty());
        assert_eq!(ev.hostname().as_deref(), Some(h.trim()));
    }
    let found = ev.find(&["**/etc/passwd", "*.log"], &WalkOptions::default()).unwrap();
    eprintln!("{} matches", found.len());
    let mut n = 0;
    let stats = ev.walk_all(&WalkOptions { max_files: 50_000, ..Default::default() }, &mut |_, e| {
        if e.kind == evidencefs::EntryKind::Symlink {
            assert!(e.link_target.is_some(), "{}: links carry their target", e.path);
        }
        n += 1;
        WalkStep::Continue
    });
    assert_eq!(stats.entries(), n);
    eprintln!("{} entries", n);
}

#[test]
fn lnx01_tgz_unpacks_as_a_linux_root() {
    quiet();
    let Some(p) = lab(r"mixed-intake\lnx01.tgz") else { return };
    let ev = Evidence::open(&p, &OpenOptions::default()).expect("opens");
    eprintln!("{}", ev.describe());
    assert!(matches!(ev.kind, EvidenceKind::Archive(_)));
    assert_eq!(ev.mounts[0].label, "tar");
    let stats = ev.walk_all(&WalkOptions::default(), &mut |_, _| WalkStep::Continue);
    assert!(stats.files > 0);
    let temp = ev.temp_path().map(|t| t.to_path_buf());
    drop(ev);
    if let Some(t) = temp {
        assert!(!t.exists(), "temp folder removed");
    }
}

#[test]
fn phase_a_zip_is_read_in_place() {
    quiet();
    let Some(p) = lab(r"mixed-intake\phaseA.zip") else { return };
    let ev = Evidence::open(&p, &OpenOptions::default()).expect("opens");
    eprintln!("{}", ev.describe());
    assert_eq!(ev.mounts[0].label, "zip");
    let stats = ev.walk_all(&WalkOptions::default(), &mut |_, _| WalkStep::Continue);
    assert!(stats.files > 0);
    let found = ev.find(&["*.evtx", "*.csv"], &WalkOptions::default()).unwrap();
    eprintln!("{} evtx/csv members", found.len());
    for f in found.iter().take(5) {
        let m = &ev.mounts[f.mount];
        let mut sink = Vec::new();
        let n = m.fs.copy_to(&f.entry.path, None, &mut sink, None).unwrap();
        assert_eq!(n, f.entry.size);
    }
}

#[test]
fn triage_folder_finds_windows_root_and_hives() {
    quiet();
    let Some(p) = lab(r"lab-case\dev-srv01-triage") else { return };
    let ev = Evidence::open(&p, &OpenOptions::default()).expect("opens");
    eprintln!("{}", ev.describe());
    assert_eq!(ev.kind, EvidenceKind::Folder);
    assert_eq!(ev.mounts[0].roots.windows, vec!["/"]);
    assert_eq!(ev.hostname().as_deref(), Some("dev-srv01"));
    let found = ev.find(&["**/config/SYSTEM", "**/config/SOFTWARE", "Users/*/NTUSER.DAT", "Amcache.hve"], &WalkOptions::default()).unwrap();
    let names: Vec<String> = found.iter().map(|f| f.entry.path.clone()).collect();
    eprintln!("{names:?}");
    assert!(names.iter().any(|n| n.ends_with("/config/SYSTEM")));
    assert!(names.iter().any(|n| n.ends_with("/Amcache.hve")));
    assert!(names.iter().filter(|n| n.ends_with("/NTUSER.DAT")).count() >= 3);
}

/// Unpacks a gzipped fixture of a sibling repo into the scratch folder, once.
fn gunzip_to(src: &Path, name: &str) -> Option<std::path::PathBuf> {
    if !src.exists() {
        eprintln!("skipped: {} is not on this machine", src.display());
        return None;
    }
    let dir = std::env::temp_dir().join("evidencefs_lab");
    std::fs::create_dir_all(&dir).ok()?;
    let out = dir.join(name);
    if !out.exists() {
        let f = std::fs::File::open(src).ok()?;
        let mut gz = flate2::read::GzDecoder::new(f);
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut gz, &mut data).ok()?;
        std::fs::write(&out, data).ok()?;
    }
    Some(out)
}

#[test]
fn carvelab_vhd_lists_deleted_files_and_reads_them_back() {
    quiet();
    let Some(p) = lab(r"mixed-intake\carvelab.vhd") else { return };
    let ev = Evidence::open(&p, &OpenOptions::default()).expect("opens");
    let live = &ev.mounts[0];
    assert_eq!(live.kind(), FsKind::Ntfs);
    let mut prog = Vec::new();
    let deleted = live.fs.deleted(Some(&mut |a, b| prog.push((a, b)))).expect("the $MFT scans");
    eprintln!("{} deleted entries on {}", deleted.len(), live.label);
    for e in deleted.iter().take(40) {
        eprintln!("  {} {} {} bytes recoverable={} {}", e.id, e.path, e.size, e.recoverable, e.times.modified.map(|t| t.to_string()).unwrap_or_default());
    }
    assert!(!deleted.is_empty(), "the lab VHD has planted deleted files");
    assert!(prog.last().is_some_and(|(a, b)| a == b && *b > 0));
    assert!(deleted.iter().all(|e| e.deleted && e.path.starts_with("/$DELETED/")));
    assert!(deleted.windows(2).all(|w| w[0].id < w[1].id), "sorted by record number");
    // Each recoverable file streams exactly its size, through the generic trait.
    let mut streamed = 0;
    for e in deleted.iter().filter(|e| e.recoverable && e.size > 0 && e.size < 8 << 20) {
        let meta = live.fs.metadata(&e.path).expect("metadata of a $DELETED path");
        assert_eq!(&meta, e);
        let mut sink = Vec::new();
        let n = live.fs.copy_to(&e.path, None, &mut sink, None).expect("streams");
        assert_eq!(n, e.size, "{}", e.path);
        streamed += 1;
    }
    eprintln!("{streamed} deleted files streamed");
    assert!(streamed > 0);
    // The listing is the same twice and reachable as a directory.
    let again = live.fs.read_dir("/$DELETED").unwrap();
    assert_eq!(again, deleted);
    assert!(live.fs.metadata("/$DELETED").unwrap().is_dir());
    assert_eq!(live.fs.metadata("/$DELETED/999999999").unwrap_err().code, evidencefs::fs::code::FS_DELETED_NOT_FOUND);
    // Evidence-wide: the shadow copy too.
    let all = ev.deleted_all(None);
    assert!(all.len() >= deleted.len());
    assert!(!live.fs.read_dir("/").unwrap().iter().any(|e| e.name == "$DELETED"), "the virtual folder is not in the live root");
}

#[test]
fn carvelab_vhd_carves_known_structures() {
    quiet();
    let Some(p) = lab(r"mixed-intake\carvelab.vhd") else { return };
    let ev = Evidence::open(&p, &OpenOptions::default()).expect("opens");
    let opts = evidencefs::CarveOptions::default();
    let (items, stats) = ev.carve(&opts, None, None).expect("carves");
    eprintln!("{} carved items, {} bytes read", items.len(), stats.bytes_read);
    let mut per: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for it in &items {
        *per.entry(it.kind.name()).or_default() += 1;
    }
    eprintln!("per kind: {per:?}");
    for it in items.iter().take(30) {
        eprintln!("  {}", it.describe());
    }
    assert!(items.iter().any(|c| c.kind == evidencefs::CarveKind::Hive), "an NTFS volume with user profiles has hives");
    let (again, _) = ev.carve(&opts, None, None).unwrap();
    assert_eq!(again, items, "two scans give the same list");
    // Read a few back.
    for it in items.iter().filter(|c| c.size < 4 << 20).take(10) {
        let mut sink = Vec::new();
        let n = ev.carve_read(it, &mut sink, None).expect("reads back");
        assert!(n > 0 && n <= it.size.max(1), "{}: {n} of {}", it.id(), it.size);
    }
}

#[test]
fn rangeforge_mft_files_list_deleted_records() {
    quiet();
    for host in ["dev-srv01", "ptr-dc01", "ptr-srv01"] {
        let Some(p) = lab(&format!(r"rangeforge-20261103\{host}-ntfs\$MFT")) else { continue };
        let total = std::fs::metadata(&p).unwrap().len();
        let f = std::fs::File::open(&p).unwrap();
        let t0 = std::time::Instant::now();
        let scan = evidencefs::fs::mft::scan(std::io::BufReader::with_capacity(8 << 20, f), 1024, total, None);
        let recoverable = scan.deleted.iter().filter(|d| d.recoverable(false)).count();
        let complete = scan.deleted.iter().filter(|d| d.path_complete).count();
        eprintln!("{host}: {} records, {} in use, {} deleted ({complete} with a full path, {recoverable} resident) in {:.1?}", scan.records, scan.in_use, scan.deleted.len(), t0.elapsed());
        for d in scan.deleted.iter().filter(|d| d.path_complete).take(8) {
            eprintln!("  {} {} {} bytes", d.record.number, d.path, d.size());
        }
        assert_eq!(scan.records, total / 1024);
        assert!(scan.in_use > 1000);
        assert!(!scan.deleted.is_empty());
        assert!(complete > 0, "some deleted files still hang from live directories");
        // Resident content of a deleted file comes straight out of the $MFT.
        if let Some(d) = scan.deleted.iter().find(|d| d.recoverable(false) && d.size() > 0) {
            let data = d.record.main_data().unwrap();
            let mut out = Vec::new();
            let n = evidencefs::fs::mft::stream_data(data, 4096, &mut |_, _| unreachable!("resident"), &mut out, None).unwrap();
            assert_eq!(n, d.size());
        }
    }
}

#[test]
fn faramir_ext4_fixture_gives_back_deleted_files_and_previous_versions() {
    quiet();
    let Some(img) = gunzip_to(Path::new(r"D:\c00pr\tools\faramir\tests\fixtures\linux_disk\gpt_ext4.img.gz"), "gpt_ext4.img") else { return };
    let ev = Evidence::open(&img, &OpenOptions::default()).expect("opens");
    eprintln!("{}", ev.describe());
    let m = ev.mounts.iter().find(|m| m.kind() == FsKind::Ext).expect("an ext4 mount");
    let deleted = m.fs.deleted(None).expect("recovery runs");
    for e in &deleted {
        eprintln!("  {} {} {} bytes recoverable={} deleted_at={:?} {}", e.id, e.path, e.size, e.recoverable, e.deleted_at.map(|t| t.to_string()), e.link_target.as_deref().unwrap_or(""));
    }
    let find = |orig: &str| deleted.iter().find(|e| e.path.ends_with(orig)).unwrap_or_else(|| panic!("{orig} not recovered"));
    for orig in ["/etc/cron.d/gone", "/etc/systemd/system/gone.service", "/home/bob/.ssh/authorized_keys2"] {
        let e = find(orig);
        assert!(e.recoverable && e.deleted_at.is_some() && e.size > 0, "{e:?}");
        assert!(e.link_target.is_none(), "a deleted file, not a previous version");
        let text = m.fs.read_to_string(&e.path, 1 << 20).unwrap();
        assert!(text.contains("gpt") && text.len() as u64 == e.size, "{orig}: {text:?}");
        assert!(!m.fs.exists(orig), "{orig} is not in the live tree");
    }
    let crontab = deleted.iter().find(|e| e.path.ends_with("/etc/crontab") && e.link_target.is_some()).expect("previous version of /etc/crontab");
    let old = m.fs.read_to_string(&crontab.path, 1 << 20).unwrap();
    assert!(old.contains("crontab.sh") && !old.contains("crontab_v2"), "{old:?}");
    let live = m.fs.read_to_string("/etc/crontab", 1 << 20).unwrap();
    assert!(live.contains("crontab_v2"));
    let sudo = deleted.iter().find(|e| e.path.ends_with("/etc/sudoers.d/lab") && e.link_target.is_some()).expect("previous version of sudoers");
    let old = m.fs.read_to_string(&sudo.path, 1 << 20).unwrap();
    assert!(old.contains("sudo.sh") && !old.contains("sudo_v2"), "{old:?}");
    assert_eq!(m.fs.read_dir("/$DELETED").unwrap(), deleted);
    let again = m.fs.deleted(None).unwrap();
    assert_eq!(again, deleted);
}

#[test]
fn real_ext4_image_recovery_is_deterministic() {
    quiet();
    let Some(p) = lab(r"mixed-intake\real_ext4.img") else { return };
    let ev = Evidence::open(&p, &OpenOptions::default()).expect("opens");
    let m = ev.mounts.iter().find(|m| m.kind() == FsKind::Ext).expect("ext4");
    let a = m.fs.deleted(None).expect("recovery runs");
    eprintln!("{} recovered entries", a.len());
    for e in a.iter().take(20) {
        eprintln!("  {} {} {} bytes recoverable={}", e.id, e.path, e.size, e.recoverable);
    }
    let b = m.fs.deleted(None).unwrap();
    assert_eq!(a, b);
    for e in a.iter().filter(|e| e.recoverable).take(20) {
        let mut sink = Vec::new();
        let n = m.fs.copy_to(&e.path, None, &mut sink, None).unwrap();
        assert_eq!(n, e.size);
    }
}

#[test]
fn memory_dump_carves_hives_and_event_chunks() {
    quiet();
    let Some(p) = lab(r"mixed-intake\WS99-memory.dmp") else { return };
    let ev = Evidence::open(&p, &OpenOptions::default()).expect("opens");
    assert_eq!(ev.kind, EvidenceKind::File);
    let opts = evidencefs::CarveOptions { kinds: vec![evidencefs::CarveKind::Hive, evidencefs::CarveKind::Evtx, evidencefs::CarveKind::Prefetch], ..Default::default() };
    let t0 = std::time::Instant::now();
    let (items, stats) = ev.carve(&opts, None, None).expect("carves");
    eprintln!("{} items from the memory dump in {:.1?}, {} bytes read", items.len(), t0.elapsed(), stats.bytes_read);
    for it in items.iter().take(20) {
        eprintln!("  {}", it.describe());
    }
    assert_eq!(stats.bytes_read, std::fs::metadata(&p).unwrap().len(), "the whole file is read");
    if stats.bytes_read > 64 << 20 {
        assert!(items.iter().any(|c| c.kind == evidencefs::CarveKind::Hive), "a real Windows memory dump holds hives");
    }
    let (again, _) = ev.carve(&opts, None, None).unwrap();
    assert_eq!(again, items);
}

/// Every file under `dir`, recursively (relative paths).
fn files_under(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p.strip_prefix(dir).unwrap_or(&p).display().to_string());
                }
            }
        }
    }
    out.sort();
    out
}

/// A compressed tar is decompressed into ONE file and read in place: no member is ever
/// written to disk on its own, so an antivirus never sees the evidence's files.
fn compressed_tar_leaves_one_file(rel: &str, expect_hostname: Option<&str>) {
    quiet();
    let Some(p) = lab(rel) else { return };
    let tag: String = rel.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let temp_base = std::env::temp_dir().join(format!("evidencefs-lab-onefile-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_base);
    std::fs::create_dir_all(&temp_base).unwrap();
    let started = std::time::Instant::now();
    let ev = Evidence::open(&p, &OpenOptions { temp_dir: Some(temp_base.clone()), ..Default::default() }).expect("opens");
    let opened = started.elapsed();
    assert_eq!(ev.mounts[0].label, "tar");
    assert_eq!(ev.mounts[0].fs.kind(), FsKind::Tar);
    let files = files_under(&temp_base);
    assert_eq!(files.len(), 1, "only the decompressed tar: {files:?}");
    assert!(files[0].ends_with("tar.tar"), "{files:?}");
    let temp_bytes: u64 = std::fs::metadata(temp_base.join(&files[0])).map(|m| m.len()).unwrap_or(0);
    // Walk and read every file: still nothing else lands in the temp folder.
    let mut read = 0u64;
    let stats = ev.walk_all(&WalkOptions::default(), &mut |mi, e| {
        if e.is_file() {
            let mut sink = std::io::sink();
            read += ev.mounts[mi].fs.copy_to(&e.path, None, &mut sink, None).unwrap_or(0);
        }
        WalkStep::Continue
    });
    assert!(stats.files > 0);
    assert_eq!(files_under(&temp_base).len(), 1, "reading members writes nothing");
    if let Some(h) = expect_hostname {
        assert_eq!(ev.hostname().as_deref().map(|s| s.split('.').next().unwrap_or(s).to_ascii_lowercase()), Some(h.to_string()));
    }
    // Two walks give the same entries (no time comes from the host).
    let snap = |ev: &Evidence| {
        let mut v = Vec::new();
        ev.walk_all(&WalkOptions::default(), &mut |_, e| {
            v.push(format!("{} {} {:?} {:?}", e.path, e.size, e.kind, e.times));
            WalkStep::Continue
        });
        v
    };
    assert_eq!(snap(&ev), snap(&ev));
    eprintln!("{rel}: opened in {opened:?}, {} files, {} dirs, {read} bytes read, temp {temp_bytes} bytes in one file", stats.files, stats.dirs);
    drop(ev);
    assert!(files_under(&temp_base).is_empty(), "temp removed on drop");
    let _ = std::fs::remove_dir_all(&temp_base);
}

#[test]
fn lnx01_tgz_is_read_through_one_decompressed_file() {
    compressed_tar_leaves_one_file(r"mixed-intake\lnx01.tgz", Some("leo-lnx01"));
}

#[test]
fn uac_tarball_is_read_through_one_decompressed_file() {
    compressed_tar_leaves_one_file(r"mixed-intake\uac-leo-lnx01-linux-20261028203103.tar.gz", None);
}

#[test]
fn rangeforge_linux_triage_is_read_through_one_decompressed_file() {
    compressed_tar_leaves_one_file(r"rangeforge-20261110\LEO-LNX01-triage.tgz", None);
}
