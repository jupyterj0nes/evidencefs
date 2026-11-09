//! Split raw images: `disk.001`, `disk.002`, ... read as one.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::diag;
use crate::error::{Error, Result};
use crate::source::code;

/// One segment: its path, size and where it starts in the whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub path: PathBuf,
    pub start: u64,
    pub len: u64,
}

/// The numbered segments of a raw image, concatenated.
pub struct SplitRaw {
    segments: Vec<Segment>,
    files: Vec<Option<File>>,
    total: u64,
    pos: u64,
}

impl SplitRaw {
    /// Opens `x.001` and every `x.00N` after it, in order, until the first missing number.
    pub fn open(first: &Path) -> Result<Self> {
        let segments = list_segments(first)?;
        let total = segments.iter().map(|s| s.len).sum();
        let n = segments.len();
        Ok(SplitRaw { segments, files: (0..n).map(|_| None).collect(), total, pos: 0 })
    }

    /// Virtual size: every segment added up.
    pub fn total_size(&self) -> u64 {
        self.total
    }

    /// The files, first first.
    pub fn segments(&self) -> Vec<PathBuf> {
        self.segments.iter().map(|s| s.path.clone()).collect()
    }

    fn segment_at(&self, pos: u64) -> Option<usize> {
        // Binary search on start offsets.
        let idx = self.segments.partition_point(|s| s.start <= pos);
        if idx == 0 {
            return None;
        }
        let s = &self.segments[idx - 1];
        if pos < s.start + s.len {
            Some(idx - 1)
        } else {
            None
        }
    }
}

/// The segments of a split set, starting from the given one.
pub fn list_segments(first: &Path) -> Result<Vec<Segment>> {
    let name = first.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return Err(Error::recorded(code::IMAGE_UNKNOWN_FORMAT, format!("{}: a split raw image is named .001", first.display())));
    };
    let Ok(start_num) = ext.parse::<u32>() else {
        return Err(Error::recorded(code::IMAGE_UNKNOWN_FORMAT, format!("{}: a split raw image is named .001", first.display())));
    };
    let width = ext.len();
    let dir = first.parent().unwrap_or(Path::new("."));
    let mut out = Vec::new();
    let mut offset = 0u64;
    let mut n = start_num;
    loop {
        let candidate = dir.join(format!("{stem}.{n:0width$}"));
        let Ok(meta) = std::fs::metadata(&candidate) else { break };
        out.push(Segment { path: candidate, start: offset, len: meta.len() });
        offset += meta.len();
        n += 1;
        if n > 9999 {
            break;
        }
    }
    if out.is_empty() {
        return Err(Error::recorded(code::IMAGE_NOT_FOUND, first.display().to_string()));
    }
    // A later segment with a gap before it: the set is incomplete.
    let gap_check = dir.join(format!("{stem}.{:0width$}", n + 1));
    if gap_check.exists() {
        diag::warn(code::IMAGE_SEGMENT_GAP, format!("{}: {stem}.{n:0width$} is missing, {} exists", first.display(), gap_check.display()));
    }
    if out.len() > 1 {
        diag::info(code::IMAGE_SEGMENTS_LISTED, format!("{}: {} segments, {} bytes", first.display(), out.len(), offset));
    }
    Ok(out)
}

impl Read for SplitRaw {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.total {
            return Ok(0);
        }
        let Some(i) = self.segment_at(self.pos) else { return Ok(0) };
        let seg = self.segments[i].clone();
        let in_seg = self.pos - seg.start;
        let want = buf.len().min((seg.len - in_seg) as usize);
        if self.files[i].is_none() {
            self.files[i] = Some(File::open(&seg.path)?);
        }
        let f = self.files[i].as_mut().expect("just opened");
        f.seek(SeekFrom::Start(in_seg))?;
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            // The segment is shorter than its metadata said: give zeros instead of hanging.
            buf[..want].fill(0);
            self.pos += want as u64;
            return Ok(want);
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SplitRaw {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.total as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new_pos < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek to a negative position"));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

impl std::fmt::Debug for SplitRaw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SplitRaw({} segments, {} bytes)", self.segments.len(), self.total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("evidencefs-split-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn reads_across_segments_in_order() {
        crate::diag::set_quiet(true);
        let d = dir("ok");
        std::fs::write(d.join("disk.001"), [1u8; 1000]).unwrap();
        std::fs::write(d.join("disk.002"), [2u8; 500]).unwrap();
        std::fs::write(d.join("disk.003"), [3u8; 300]).unwrap();
        std::fs::write(d.join("other.001"), [9u8; 10]).unwrap();
        let mut r = SplitRaw::open(&d.join("disk.001")).unwrap();
        assert_eq!(r.total_size(), 1800);
        assert_eq!(r.segments().len(), 3);
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all.len(), 1800);
        assert_eq!(all[999], 1);
        assert_eq!(all[1000], 2);
        assert_eq!(all[1499], 2);
        assert_eq!(all[1500], 3);
        // A read that straddles a boundary comes back in two pieces, never mixed.
        r.seek(SeekFrom::Start(995)).unwrap();
        let mut b = [0u8; 10];
        let n = r.read(&mut b).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&b[..5], &[1u8; 5]);
        let n = r.read(&mut b).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&b[..], &[2u8; 10]);
        assert_eq!(r.seek(SeekFrom::End(-1)).unwrap(), 1799);
        assert_eq!(r.read(&mut b).unwrap(), 1);
        assert_eq!(r.read(&mut b).unwrap(), 0);
        assert!(r.seek(SeekFrom::Current(-5000)).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn gap_is_reported_and_set_stops_before_it() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let d = dir("gap");
        std::fs::write(d.join("disk.001"), [1u8; 10]).unwrap();
        std::fs::write(d.join("disk.003"), [3u8; 10]).unwrap();
        let r = SplitRaw::open(&d.join("disk.001")).unwrap();
        assert_eq!(r.total_size(), 10);
        assert!(crate::diag::has(code::IMAGE_SEGMENT_GAP));
        crate::diag::drain();
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn can_start_from_a_later_segment_and_refuses_odd_names() {
        crate::diag::set_quiet(true);
        let d = dir("later");
        std::fs::write(d.join("disk.002"), [2u8; 10]).unwrap();
        std::fs::write(d.join("disk.003"), [3u8; 10]).unwrap();
        let r = SplitRaw::open(&d.join("disk.002")).unwrap();
        assert_eq!(r.total_size(), 20);
        assert_eq!(SplitRaw::open(&d.join("disk.raw")).unwrap_err().code, code::IMAGE_UNKNOWN_FORMAT);
        assert_eq!(SplitRaw::open(&d.join("gone.001")).unwrap_err().code, code::IMAGE_NOT_FOUND);
        std::fs::remove_dir_all(&d).ok();
    }
}
