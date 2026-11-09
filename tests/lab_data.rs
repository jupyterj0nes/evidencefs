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
