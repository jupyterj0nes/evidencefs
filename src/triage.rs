//! Triage packages: what collector made them (KAPE, Velociraptor, CyLR, UAC, Cortex XDR),
//! the host name their file name carries, and where the operating system roots are inside
//! them (`C/Windows/...`, `uploads/auto/C%3A/Windows/...`, `[root]/etc/...`).

use std::path::Path;

use crate::diag;
use crate::fs::{join, Entry, EntryKind, FileSystem};

pub mod code {
    crate::codes! {
        TRIAGE_DETECTED = 700, "the evidence is a triage package of a known collector; its layout is used to find the operating system roots";
        TRIAGE_HOSTNAME = 701, "the host name was taken from the package name (collectors put it there)";
        TRIAGE_UNKNOWN = 702, "the evidence is a folder or archive of files whose collector is not recognised; the operating system roots are searched by name";
        TRIAGE_WINDOWS_ROOT = 703, "a Windows root (a folder holding Windows/System32/config) was found at this path inside the evidence";
        TRIAGE_LINUX_ROOT = 704, "a Linux root (a folder holding etc/ with passwd or hostname) was found at this path inside the evidence";
        TRIAGE_NO_ROOT = 705, "no Windows or Linux root was found in the first levels of the evidence; files are read where they are, by name";
        TRIAGE_VELOCIRAPTOR_ENCODED = 706, "a Velociraptor folder encodes the drive letter as C%3A; it was decoded";
        TRIAGE_LINUX_HOSTNAME = 707, "the host name was read from etc/hostname inside the evidence";
    }
}

/// The collectors recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TriageType {
    Kape,
    Velociraptor,
    CortexXdr,
    CyLr,
    Uac,
    Generic,
}

impl TriageType {
    /// Short label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Kape => "KAPE",
            Self::Velociraptor => "Velociraptor",
            Self::CortexXdr => "Cortex XDR",
            Self::CyLr => "CyLR",
            Self::Uac => "UAC",
            Self::Generic => "generic triage",
        }
    }
}

/// What was learnt about a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageInfo {
    pub kind: TriageType,
    pub hostname: Option<String>,
}

/// `<LETTER>_<YYYYMMDD>-<HHMMSS>_<user>` or `Extracted_...`: Velociraptor's file names.
fn is_velociraptor_filename(stem: &str) -> bool {
    let without_prefix = stem.strip_prefix("Extracted_").unwrap_or(stem);
    let bytes = without_prefix.as_bytes();
    if bytes.len() < 19 {
        return false;
    }
    if !bytes[0].is_ascii_alphabetic() || bytes[1] != b'_' {
        return false;
    }
    if !bytes[2..10].iter().all(|b| b.is_ascii_digit()) || bytes[10] != b'-' {
        return false;
    }
    if !bytes[11..17].iter().all(|b| b.is_ascii_digit()) || bytes[17] != b'_' {
        return false;
    }
    bytes.len() > 18
}

fn is_velociraptor_path(path: &str) -> bool {
    path.replace('\\', "/").to_lowercase().contains("/velociraptor/")
}

fn norm(n: &str) -> String {
    n.replace('\\', "/").trim_start_matches("./").trim_start_matches('/').to_string()
}

/// Detects the collector from the package's path and its member names (top levels are
/// enough).
pub fn detect(archive_path: &str, entries: &[String]) -> Option<TriageType> {
    let normed: Vec<String> = entries.iter().map(|e| norm(e)).collect();
    let lower: Vec<String> = normed.iter().map(|e| e.to_lowercase()).collect();
    // 1. UAC.
    let has_uac_log = normed.iter().any(|n| n == "uac.log" || n.ends_with("/uac.log"));
    let has_uac_layout = normed.iter().any(|n| n.starts_with("[root]/") || n.contains("/[root]/") || n.starts_with("live_response/") || n == "[root]" || n == "live_response");
    if has_uac_log && has_uac_layout {
        return Some(TriageType::Uac);
    }
    let stem = Path::new(archive_path).file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if stem.starts_with("uac-") {
        return Some(TriageType::Uac);
    }
    // 2. Cortex XDR.
    if lower.iter().any(|n| n == "output/manifest.json") && lower.iter().any(|n| n == "output/cortex-xdr-payload.log") {
        return Some(TriageType::CortexXdr);
    }
    // 3. Velociraptor.
    let has_client_info = normed.iter().any(|n| n == "client_info.json" || n.ends_with("/client_info.json"));
    let has_collection_context = normed.iter().any(|n| n == "collection_context.json" || n.ends_with("/collection_context.json"));
    let has_uploads_json = normed.iter().any(|n| n == "uploads.json" || n.ends_with("/uploads.json"));
    if has_client_info && (has_collection_context || has_uploads_json) {
        return Some(TriageType::Velociraptor);
    }
    let has_metadata = normed.iter().any(|n| n == "metadata.json" || n.ends_with("/metadata.json"));
    let has_data_zip = normed.iter().any(|n| n == "data.zip" || n.ends_with("/data.zip"));
    if has_metadata && has_data_zip {
        return Some(TriageType::Velociraptor);
    }
    if normed.iter().any(|n| n.contains("uploads/auto/") || n.contains("uploads/ntfs/") || n == "uploads") || is_velociraptor_filename(stem) || is_velociraptor_path(archive_path) {
        return Some(TriageType::Velociraptor);
    }
    // 4. KAPE.
    if lower.iter().any(|n| n == "_kape.cli" || n.ends_with("/_kape.cli") || n.ends_with("/kape.log") || n == "kape.log") {
        return Some(TriageType::Kape);
    }
    let kape_layout = lower.iter().filter(|n| n.contains("/windows/system32/winevt/logs/") || n.starts_with("c/windows/system32/winevt/logs/")).count();
    if kape_layout >= 3 {
        return Some(TriageType::Kape);
    }
    // 5. CyLR.
    if lower.iter().any(|n| n.contains("cylr") || n.ends_with(".cylr.log")) {
        return Some(TriageType::CyLr);
    }
    // 6. Generic: a Windows or Linux tree without a collector mark.
    if lower.iter().any(|n| n == "c" || n == "c:" || n.starts_with("c/windows") || n.starts_with("windows/system32") || n == "windows") || lower.iter().any(|n| n == "etc" || n.starts_with("etc/") || n == "var/log" || n.starts_with("var/log/")) {
        return Some(TriageType::Generic);
    }
    None
}

/// Best-effort host name from a package's file name.
pub fn hostname_from_name(archive_path: &str, kind: TriageType) -> Option<String> {
    let stem = Path::new(archive_path).file_stem()?.to_str()?;
    // Strip a second extension (`host.tar.gz` -> `host`).
    let stem = stem.strip_suffix(".tar").unwrap_or(stem);
    match kind {
        TriageType::Uac => {
            // uac-<hostname>-<os>-<timestamp>
            let parts: Vec<&str> = stem.split('-').collect();
            if parts.len() >= 4 && parts[0] == "uac" {
                let host = parts[1..parts.len() - 2].join("-");
                if !host.is_empty() && !host.eq_ignore_ascii_case("unknown") {
                    return Some(host);
                }
            }
            None
        }
        TriageType::CortexXdr => {
            // offline_collector_output_<HOST>_<YYYY-MM-DD>_<HH-MM-SS>
            let rest = stem.strip_prefix("offline_collector_output_")?;
            let bytes = rest.as_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                if b == b'_' && i + 5 < bytes.len() {
                    let next4 = &bytes[i + 1..i + 5];
                    if next4.iter().all(|c| c.is_ascii_digit()) && bytes[i + 5] == b'-' {
                        return Some(rest[..i].to_string());
                    }
                }
            }
            None
        }
        TriageType::Velociraptor => {
            // Collection-<HOST>-<TIMESTAMP>
            let rest = stem.strip_prefix("Collection-")?;
            let bytes = rest.as_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                if b == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                    return Some(rest[..i].to_string());
                }
            }
            None
        }
        TriageType::Kape | TriageType::CyLr | TriageType::Generic => {
            // <hostname>_<YYYYMMDD>_<HHMMSS>, <hostname>-triage, <hostname>-logs
            if let Some((head, tail)) = stem.split_once('_') {
                let tail_starts_with_digits = tail.len() >= 4 && tail.chars().take(4).all(|c| c.is_ascii_digit());
                if tail_starts_with_digits && !head.is_empty() {
                    return Some(head.to_string());
                }
            }
            for suffix in ["-triage", "_triage", "-logs", "-collection", "-kape", "-cylr"] {
                if let Some(head) = stem.to_lowercase().strip_suffix(suffix) {
                    if !head.is_empty() {
                        return Some(stem[..head.len()].to_string());
                    }
                }
            }
            None
        }
    }
}

/// Decodes Velociraptor's percent-encoded drive folders (`C%3A` -> `C:`).
pub fn decode_velociraptor(name: &str) -> String {
    if !name.contains('%') {
        return name.to_string();
    }
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// The operating system roots found inside a file system.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roots {
    /// Folders holding `Windows/System32/config` (the folder that plays `C:\`).
    pub windows: Vec<String>,
    /// Folders holding `etc/passwd` or `etc/hostname` (the folder that plays `/`).
    pub linux: Vec<String>,
}

impl Roots {
    /// Nothing found.
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty() && self.linux.is_empty()
    }
}

fn has_child(fs: &dyn FileSystem, dir: &str, name: &str, want_dir: bool) -> bool {
    match fs.metadata(&join(dir, name)) {
        Ok(e) => e.kind == if want_dir { EntryKind::Dir } else { EntryKind::File } || (!want_dir && e.kind == EntryKind::File),
        Err(_) => {
            // Case-sensitive file systems: look through the listing.
            fs.read_dir(dir).map(|list| list.iter().any(|e| e.name.eq_ignore_ascii_case(name) && (e.kind == EntryKind::Dir) == want_dir)).unwrap_or(false)
        }
    }
}

fn is_windows_root(fs: &dyn FileSystem, dir: &str) -> bool {
    let win = match fs.read_dir(dir) {
        Ok(list) => list.into_iter().find(|e| e.is_dir() && e.name.eq_ignore_ascii_case("Windows")),
        Err(_) => None,
    };
    let Some(win) = win else { return false };
    let sys32 = fs.read_dir(&win.path).ok().and_then(|l| l.into_iter().find(|e| e.is_dir() && e.name.eq_ignore_ascii_case("System32")));
    match sys32 {
        Some(s) => has_child(fs, &s.path, "config", true) || has_child(fs, &s.path, "winevt", true),
        None => false,
    }
}

fn is_linux_root(fs: &dyn FileSystem, dir: &str) -> bool {
    let etc = fs.read_dir(dir).ok().and_then(|l| l.into_iter().find(|e| e.is_dir() && e.name == "etc"));
    match etc {
        Some(e) => has_child(fs, &e.path, "passwd", false) || has_child(fs, &e.path, "hostname", false) || has_child(fs, &e.path, "os-release", false),
        None => false,
    }
}

/// Finds the operating system roots in the first `max_depth` levels (the root itself
/// included). Velociraptor's `uploads/auto/C%3A` and KAPE's `C` both count.
pub fn locate_roots(fs: &dyn FileSystem, max_depth: usize) -> Roots {
    let mut roots = Roots::default();
    let mut frontier: Vec<(String, usize)> = vec![("/".to_string(), 0)];
    while let Some((dir, depth)) = frontier.pop() {
        if is_windows_root(fs, &dir) {
            if dir.contains('%') {
                diag::info(code::TRIAGE_VELOCIRAPTOR_ENCODED, format!("{dir} -> {}", decode_velociraptor(&dir)));
            }
            diag::info(code::TRIAGE_WINDOWS_ROOT, dir.clone());
            roots.windows.push(dir.clone());
            continue;
        }
        if is_linux_root(fs, &dir) {
            diag::info(code::TRIAGE_LINUX_ROOT, dir.clone());
            roots.linux.push(dir.clone());
            continue;
        }
        if depth >= max_depth {
            continue;
        }
        if let Ok(list) = fs.read_dir(&dir) {
            // Only a handful of folders are worth descending into at each level.
            let mut dirs: Vec<Entry> = list.into_iter().filter(|e| e.is_dir()).collect();
            dirs.sort_by(|a, b| a.name.cmp(&b.name));
            for d in dirs.into_iter().rev().take(64) {
                frontier.push((d.path, depth + 1));
            }
        }
    }
    roots.windows.sort();
    roots.linux.sort();
    if roots.is_empty() {
        diag::info(code::TRIAGE_NO_ROOT, format!("within {max_depth} levels"));
    }
    roots
}

/// The host name a Linux root carries in `etc/hostname`.
pub fn linux_hostname(fs: &dyn FileSystem, root: &str) -> Option<String> {
    let text = fs.read_to_string(&join(&join(root, "etc"), "hostname"), 4096).ok()?;
    let host = text.lines().next()?.trim().to_string();
    if host.is_empty() {
        return None;
    }
    diag::info(code::TRIAGE_LINUX_HOSTNAME, host.clone());
    Some(host)
}

/// Detects the collector and host name of a mounted folder or zip from its top entries.
pub fn inspect(fs: &dyn FileSystem, source_name: &str) -> Option<TriageInfo> {
    let mut names: Vec<String> = Vec::new();
    if let Ok(top) = fs.read_dir("/") {
        for e in top {
            names.push(e.path.trim_start_matches('/').to_string());
            if e.is_dir() {
                if let Ok(sub) = fs.read_dir(&e.path) {
                    for s in sub.into_iter().take(200) {
                        names.push(s.path.trim_start_matches('/').to_string());
                        if s.is_dir() && names.len() < 2000 {
                            if let Ok(sub2) = fs.read_dir(&s.path) {
                                for s2 in sub2.into_iter().take(50) {
                                    names.push(s2.path.trim_start_matches('/').to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let kind = detect(source_name, &names);
    match kind {
        Some(kind) => {
            let hostname = hostname_from_name(source_name, kind);
            diag::info(code::TRIAGE_DETECTED, format!("{source_name}: {}{}", kind.label(), hostname.as_deref().map(|h| format!(", host {h}")).unwrap_or_default()));
            if hostname.is_some() {
                diag::info(code::TRIAGE_HOSTNAME, hostname.clone().unwrap_or_default());
            }
            Some(TriageInfo { kind, hostname })
        }
        None => {
            diag::info(code::TRIAGE_UNKNOWN, source_name.to_string());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn velociraptor() {
        let kind = detect("Collection-SRV-DC01-20260406T100000Z.zip", &s(&["client_info.json", "collection_context.json", "uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx"]));
        assert_eq!(kind, Some(TriageType::Velociraptor));
        assert_eq!(hostname_from_name("Collection-SRV-DC01-20260406T100000Z.zip", TriageType::Velociraptor).as_deref(), Some("SRV-DC01"));
        assert_eq!(detect("F_20260406-100000_admin.zip", &s(&["x"])), Some(TriageType::Velociraptor));
        assert_eq!(detect("/data/Velociraptor/foo.zip", &s(&["x"])), Some(TriageType::Velociraptor));
        assert_eq!(detect("x.zip", &s(&["metadata.json", "data.zip"])), Some(TriageType::Velociraptor));
        assert_eq!(decode_velociraptor("C%3A"), "C:");
        assert_eq!(decode_velociraptor("plain"), "plain");
        assert_eq!(decode_velociraptor("bad%zz"), "bad%zz");
    }

    #[test]
    fn kape_cylr_generic() {
        assert_eq!(detect("DESKTOP-ABC123_20260406_183000.zip", &s(&["_kape.cli", "C/Windows/System32/winevt/Logs/Security.evtx"])), Some(TriageType::Kape));
        assert_eq!(hostname_from_name("DESKTOP-ABC123_20260406_183000.zip", TriageType::Kape).as_deref(), Some("DESKTOP-ABC123"));
        let three_logs = s(&["C/Windows/System32/winevt/Logs/a.evtx", "C/Windows/System32/winevt/Logs/b.evtx", "C/Windows/System32/winevt/Logs/c.evtx"]);
        assert_eq!(detect("whatever.zip", &three_logs), Some(TriageType::Kape));
        assert_eq!(detect("host.zip", &s(&["CyLR.log", "C/x"])), Some(TriageType::CyLr));
        assert_eq!(detect("dev-srv01-triage", &s(&["Windows", "Users", "Windows/System32"])), Some(TriageType::Generic));
        assert_eq!(hostname_from_name("dev-srv01-triage", TriageType::Generic).as_deref(), Some("dev-srv01"));
        assert_eq!(hostname_from_name("lnx01-logs.tar.gz", TriageType::Generic).as_deref(), Some("lnx01"));
        assert_eq!(hostname_from_name("random.zip", TriageType::Generic), None);
        assert_eq!(detect("linux.tgz", &s(&["etc/passwd", "var/log/auth.log"])), Some(TriageType::Generic));
        assert_eq!(detect("photos.zip", &s(&["a.jpg", "b.jpg"])), None);
    }

    #[test]
    fn cortex_and_uac() {
        assert_eq!(detect("offline_collector_output_WEBSERV01_2026-04-06_12-00-00.zip", &s(&["output/manifest.json", "output/cortex-xdr-payload.log"])), Some(TriageType::CortexXdr));
        assert_eq!(hostname_from_name("offline_collector_output_WEBSERV01_2026-04-06_12-00-00.zip", TriageType::CortexXdr).as_deref(), Some("WEBSERV01"));
        assert_eq!(detect("uac-ubuntuhost-linux-20260406120000.tar.gz", &s(&["uac.log", "[root]/var/log/syslog"])), Some(TriageType::Uac));
        assert_eq!(hostname_from_name("uac-ubuntuhost-linux-20260406120000.tar.gz", TriageType::Uac).as_deref(), Some("ubuntuhost"));
        assert_eq!(hostname_from_name("uac-unknown-linux-1.tar.gz", TriageType::Uac), None);
        assert_eq!(detect("uac-x.tgz", &s(&["whatever"])), Some(TriageType::Uac));
        assert_eq!(TriageType::Uac.label(), "UAC");
    }

    #[test]
    fn roots_in_a_kape_like_folder() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let d = std::env::temp_dir().join(format!("evidencefs-triage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("C").join("Windows").join("System32").join("config")).unwrap();
        std::fs::create_dir_all(d.join("vr").join("C%3A").join("Windows").join("System32").join("winevt")).unwrap();
        std::fs::create_dir_all(d.join("lnx").join("etc")).unwrap();
        std::fs::write(d.join("lnx").join("etc").join("hostname"), "lnx01\n").unwrap();
        std::fs::write(d.join("_kape.cli"), "x").unwrap();
        let fs = crate::fs::folder::FolderFs::open(&d).unwrap();
        let roots = locate_roots(&fs, 4);
        assert_eq!(roots.windows, vec!["/C", "/vr/C%3A"]);
        assert_eq!(roots.linux, vec!["/lnx"]);
        assert!(crate::diag::has(code::TRIAGE_VELOCIRAPTOR_ENCODED));
        assert_eq!(linux_hostname(&fs, "/lnx").as_deref(), Some("lnx01"));
        assert_eq!(linux_hostname(&fs, "/C"), None);
        let info = inspect(&fs, "HOST01_20260101_120000.zip").unwrap();
        assert_eq!(info.kind, TriageType::Kape);
        assert_eq!(info.hostname.as_deref(), Some("HOST01"));
        let shallow = locate_roots(&fs, 0);
        assert!(shallow.is_empty());
        crate::diag::drain();
        std::fs::remove_dir_all(&d).ok();
    }
}
