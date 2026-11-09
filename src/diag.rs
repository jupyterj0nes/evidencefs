//! Diagnostics: stable codes and the sink that collects them.
//!
//! Every failure, skip or decision the analyst may need to trace carries a code
//! `EF###_NAME`. Each module declares its codes with [`codes!`] in a `pub mod code` block,
//! inside its area's range; [`catalog`] gathers them and a test checks that no number is
//! used twice.
//!
//! | Range   | Area |
//! |---------|------|
//! | 000-049 | images: detection, opening, reading |
//! | 050-099 | EWF (E01 / Ex01) |
//! | 100-149 | VHD / VHDX |
//! | 150-199 | VMDK |
//! | 200-249 | split raw, archives (zip, tar), folders as evidence |
//! | 250-299 | partitions: MBR, GPT, signatures, encryption |
//! | 300-349 | LVM |
//! | 350-399 | Volume Shadow Copies |
//! | 400-449 | NTFS |
//! | 450-499 | ext2/3/4 |
//! | 500-549 | XFS |
//! | 550-599 | plain folders and zip archives as file systems |
//! | 600-649 | walking and finding |
//! | 650-699 | extraction |
//! | 700-749 | triage packages |
//! | 750-799 | timestamps and decoding |
//!
//! The sink is per thread: a worker records into its own while it reads a piece of
//! evidence, drains it when done and hands the list back, so tests and tools see the
//! diagnostics of the work they asked for and nothing else. Errors and warnings are
//! echoed to stderr unless the process is quiet; infos only when it is verbose.

use std::cell::RefCell;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

/// A stable diagnostic code: `EF` + three digits + a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Code {
    /// The number, unique in the crate and below 1000.
    pub id: u16,
    /// The constant's name, `SCREAMING_SNAKE`.
    pub name: &'static str,
    /// What it means and what to do about it.
    pub help: &'static str,
}

impl Code {
    /// `EF###_NAME`.
    pub fn tag(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EF{:03}_{}", self.id, self.name)
    }
}

/// Declares a module's codes and its `CODES` list:
///
/// ```ignore
/// pub mod code {
///     evidencefs::codes! {
///         IMAGE_NOT_FOUND = 1, "the image file does not exist";
///     }
/// }
/// ```
#[macro_export]
macro_rules! codes {
    ($( $konst:ident = $id:literal, $help:literal; )*) => {
        $( #[doc = $help] pub const $konst: $crate::diag::Code = $crate::diag::Code { id: $id, name: stringify!($konst), help: $help }; )*
        /// Every code of this module.
        pub const CODES: &[$crate::diag::Code] = &[$($konst),*];
    };
}

/// How bad a recorded diagnostic is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Something was skipped or decided; nothing was lost.
    Info,
    /// Reading went on in a degraded way (a volume skipped, a file unreadable).
    Warning,
    /// The piece of evidence could not be read at all.
    Error,
}

impl Severity {
    /// `INFO`, `WARN`, `ERROR`.
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Error => "ERROR",
        }
    }
}

/// One recorded diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: Code,
    pub severity: Severity,
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

thread_local! {
    static SINK: RefCell<Vec<Diagnostic>> = const { RefCell::new(Vec::new()) };
}
static QUIET: AtomicBool = AtomicBool::new(false);
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Stop echoing diagnostics to stderr (the sink still collects everything).
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

/// Is stderr echo off?
pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Also echo `Info` diagnostics to stderr.
pub fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

/// Are infos echoed?
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Records a diagnostic in this thread's sink and echoes it when allowed.
pub fn record(code: Code, severity: Severity, message: impl Into<String>) -> Diagnostic {
    let d = Diagnostic { code, severity, message: message.into() };
    if !is_quiet() {
        match severity {
            Severity::Error => eprintln!("[ERROR] {d}"),
            Severity::Warning => eprintln!("[WARN]  {d}"),
            Severity::Info => {
                if is_verbose() {
                    eprintln!("[INFO]  {d}");
                }
            }
        }
    }
    SINK.with(|s| s.borrow_mut().push(d.clone()));
    d
}

/// Records an error-level diagnostic.
pub fn error(code: Code, message: impl Into<String>) -> Diagnostic {
    record(code, Severity::Error, message)
}

/// Records a warning.
pub fn warn(code: Code, message: impl Into<String>) -> Diagnostic {
    record(code, Severity::Warning, message)
}

/// Records an info.
pub fn info(code: Code, message: impl Into<String>) -> Diagnostic {
    record(code, Severity::Info, message)
}

/// Takes everything recorded in this thread so far.
pub fn drain() -> Vec<Diagnostic> {
    SINK.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// A copy of what is recorded in this thread, without clearing it.
pub fn recorded() -> Vec<Diagnostic> {
    SINK.with(|s| s.borrow().clone())
}

/// Puts diagnostics drained on another thread into this one's sink, in order.
pub fn absorb(list: Vec<Diagnostic>) {
    SINK.with(|s| s.borrow_mut().extend(list));
}

/// Has this thread recorded the code?
pub fn has(code: Code) -> bool {
    SINK.with(|s| s.borrow().iter().any(|d| d.code == code))
}

/// Every code of the crate, in number order.
pub fn catalog() -> Vec<Code> {
    let mut all: Vec<Code> = Vec::new();
    all.extend_from_slice(crate::source::code::CODES);
    all.extend_from_slice(crate::source::vhd::code::CODES);
    all.extend_from_slice(crate::source::vmdk::code::CODES);
    all.extend_from_slice(crate::archive::code::CODES);
    all.extend_from_slice(crate::volume::code::CODES);
    all.extend_from_slice(crate::volume::lvm::code::CODES);
    all.extend_from_slice(crate::volume::vss::code::CODES);
    all.extend_from_slice(crate::fs::ntfs::code::CODES);
    all.extend_from_slice(crate::fs::ext::code::CODES);
    all.extend_from_slice(crate::fs::xfs::code::CODES);
    all.extend_from_slice(crate::fs::folder::code::CODES);
    all.extend_from_slice(crate::fs::code::CODES);
    all.extend_from_slice(crate::extract::code::CODES);
    all.extend_from_slice(crate::triage::code::CODES);
    all.extend_from_slice(crate::time::code::CODES);
    all.sort_by_key(|c| c.id);
    all
}

/// The code with this number or `EF###_NAME` tag, if any.
pub fn lookup(what: &str) -> Option<Code> {
    let w = what.trim();
    let num: Option<u16> = w
        .strip_prefix("EF")
        .or_else(|| w.strip_prefix("ef"))
        .map(|rest| rest.split('_').next().unwrap_or(rest))
        .unwrap_or(w)
        .parse()
        .ok();
    catalog().into_iter().find(|c| Some(c.id) == num || c.name.eq_ignore_ascii_case(w))
}

/// A Markdown table of every code, for `docs/codes.md`.
pub fn codes_markdown() -> String {
    let mut s = String::from("# Diagnostic codes\n\nEvery code evidencefs can record, with what it means and what to do about it. The ranges are in `src/diag.rs`.\n\n| Code | Meaning |\n|---|---|\n");
    for c in catalog() {
        s.push_str(&format!("| `{c}` | {} |\n", c.help.replace('|', "\\|")));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_in_range() {
        let all = catalog();
        assert!(all.len() > 80, "the crate declares many codes ({})", all.len());
        let mut seen = std::collections::HashSet::new();
        for c in &all {
            assert!(c.id < 1000, "{c} out of range");
            assert!(seen.insert(c.id), "code {} used twice", c.id);
            assert!(!c.help.is_empty(), "{c} has no help");
            assert!(c.help.len() > 20, "{c} help is too short to help anyone: {}", c.help);
        }
    }

    #[test]
    fn display_is_tag() {
        let c = Code { id: 7, name: "X_Y", help: "something to say about it" };
        assert_eq!(c.to_string(), "EF007_X_Y");
        assert_eq!(c.tag(), "EF007_X_Y");
    }

    #[test]
    fn sink_records_and_drains_per_thread() {
        set_quiet(true);
        drain();
        let c = crate::source::code::IMAGE_NOT_FOUND;
        error(c, "a");
        warn(c, "b");
        assert!(has(c));
        assert_eq!(recorded().len(), 2);
        let other = std::thread::spawn(|| recorded().len()).join().unwrap();
        assert_eq!(other, 0, "another thread has its own sink");
        let list = drain();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].severity, Severity::Error);
        assert_eq!(list[1].severity, Severity::Warning);
        assert!(recorded().is_empty());
        absorb(list);
        assert_eq!(recorded().len(), 2);
        drain();
    }

    #[test]
    fn lookup_accepts_tag_number_and_name() {
        let c = crate::source::code::IMAGE_NOT_FOUND;
        assert_eq!(lookup(&c.to_string()), Some(c));
        assert_eq!(lookup(&c.id.to_string()), Some(c));
        assert_eq!(lookup("EF001"), Some(c));
        assert_eq!(lookup("image_not_found"), Some(c));
        assert_eq!(lookup("EF999"), None);
    }

    #[test]
    fn severity_orders_and_labels() {
        assert!(Severity::Error > Severity::Warning && Severity::Warning > Severity::Info);
        assert_eq!(Severity::Warning.label(), "WARN");
    }

    #[test]
    fn markdown_lists_every_code() {
        let md = codes_markdown();
        for c in catalog() {
            assert!(md.contains(&c.to_string()), "{c} missing from the table");
        }
    }
}
