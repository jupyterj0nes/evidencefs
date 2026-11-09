//! XFS volumes through the `rust-fs-xfs` driver (RHEL, Rocky, Alma, Oracle Linux
//! defaults). Symbolic links are described, not followed.

use std::sync::Arc;

use fs_xfs::inode::Inode;
use fs_xfs::Filesystem;

use crate::diag;
use crate::error::{Error, Result};
use crate::fs::{code as fscode, join, normalize, Entry, EntryKind, FileSystem, FsKind, Progress, Sink};
use crate::source::SharedReader;
use crate::time::{Timestamp, Timestamps};

pub mod code {
    crate::codes! {
        XFS_OPEN = 500, "the volume's superblock could not be parsed as XFS; the offset is wrong or the superblock is damaged (XFS keeps a copy in every allocation group)";
        XFS_LOOKUP = 501, "a path could not be resolved; a directory block on the way is damaged";
        XFS_INODE = 502, "an inode could not be read; the inode chunk is damaged or fails its CRC, the entry is listed without times";
        XFS_READ_DIR = 503, "a directory could not be listed; its blocks are damaged";
        XFS_READ = 504, "reading a file's content failed part-way; an extent points outside the volume or the image is truncated";
        XFS_OPENED = 505, "an XFS volume was opened: UUID, block size, size";
        XFS_NAME_UNDECODABLE = 506, "a file name is not UTF-8; it is shown lossily";
        XFS_LINK_TARGET = 507, "a symbolic link's target could not be read; the entry is listed as a link without a target";
        XFS_LOG_REPLAYED = 508, "the XFS log was not clean and the driver replayed it in memory; the volume was not unmounted cleanly, what you read includes the logged operations";
    }
}

/// An XFS volume.
pub struct XfsFs {
    fs: Filesystem,
    uuid: String,
    size: u64,
}

fn ts(t: fs_xfs::inode::Timestamp) -> Option<Timestamp> {
    if t.sec == 0 && t.nsec == 0 {
        None
    } else {
        Some(Timestamp::from_unix(t.sec, t.nsec))
    }
}

fn is_not_found(e: &fs_xfs::Error) -> bool {
    let d = format!("{e:?}");
    d.contains("NotFound") || d.contains("NoEntry") || d.contains("NoSuchFile") || d.contains("ENOENT")
}

impl XfsFs {
    /// Mounts the volume whose first byte is the start of the partition.
    pub fn open(volume: SharedReader, label_for_logs: &str) -> Result<Self> {
        let size = volume.len();
        let device: Arc<dyn fs_core::BlockRead> = Arc::new(volume);
        let fs = Filesystem::mount(device).map_err(|e| Error::recorded(code::XFS_OPEN, format!("{label_for_logs}: {e:?}")))?;
        let sb = fs.superblock();
        let uuid = crate::volume::guid_text(&sb.uuid);
        if fs.was_replayed() {
            diag::info(code::XFS_LOG_REPLAYED, label_for_logs.to_string());
        }
        diag::info(code::XFS_OPENED, format!("{label_for_logs}: uuid {uuid}, block size {}, {}", sb.blocksize, crate::volume::human_size(sb.dblocks * sb.blocksize as u64)));
        Ok(XfsFs { fs, uuid, size })
    }

    /// The file system UUID.
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    fn lookup(&self, path: &str) -> Result<(Inode, Vec<u8>)> {
        let norm = normalize(path);
        let inode = self.fs.lookup_path(&norm).map_err(|e| if is_not_found(&e) { Error::new(fscode::FS_NOT_FOUND, path.to_string()) } else { Error::recorded(code::XFS_LOOKUP, format!("{path}: {e:?}")) })?;
        self.fs.read_inode_raw(inode.ino).map_err(|e| Error::recorded(code::XFS_INODE, format!("{path}: {e:?}")))
    }

    fn entry_of(&self, path: &str, inode: &Inode, raw: &[u8]) -> Entry {
        let kind = if inode.is_dir() {
            EntryKind::Dir
        } else if inode.is_symlink() {
            EntryKind::Symlink
        } else if inode.is_regular_file() {
            EntryKind::File
        } else {
            EntryKind::Other
        };
        let mut e = Entry::new(path, kind);
        e.id = inode.ino;
        e.size = if kind == EntryKind::File { inode.size } else { 0 };
        e.times = Timestamps { created: ts(inode.crtime), modified: ts(inode.mtime), accessed: ts(inode.atime), changed: ts(inode.ctime) };
        if kind == EntryKind::Symlink {
            match self.fs.read_link(inode, raw) {
                Ok(t) => e.link_target = Some(String::from_utf8_lossy(&t).to_string()),
                Err(err) => {
                    diag::info(code::XFS_LINK_TARGET, format!("{path}: {err:?}"));
                }
            }
        }
        e
    }
}

impl FileSystem for XfsFs {
    fn kind(&self) -> FsKind {
        FsKind::Xfs
    }

    fn size(&self) -> Option<u64> {
        Some(self.size)
    }

    fn metadata(&self, path: &str) -> Result<Entry> {
        let (inode, raw) = self.lookup(path)?;
        Ok(self.entry_of(&normalize(path), &inode, &raw))
    }

    fn read_dir(&self, path: &str) -> Result<Vec<Entry>> {
        let norm = normalize(path);
        let (inode, raw) = self.lookup(path)?;
        if !inode.is_dir() {
            return Err(Error::new(fscode::FS_NOT_A_DIR, path.to_string()));
        }
        let entries = self.fs.read_dir(&inode, &raw).map_err(|e| Error::recorded(code::XFS_READ_DIR, format!("{path}: {e:?}")))?;
        let mut out = Vec::new();
        for d in entries {
            let name = match std::str::from_utf8(&d.name) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    let lossy = String::from_utf8_lossy(&d.name).to_string();
                    diag::info(code::XFS_NAME_UNDECODABLE, format!("{norm}: {lossy}"));
                    lossy
                }
            };
            if name == "." || name == ".." {
                continue;
            }
            let child = join(&norm, &name);
            match self.fs.read_inode_raw(d.ino) {
                Ok((i, r)) => out.push(self.entry_of(&child, &i, &r)),
                Err(e) => {
                    diag::warn(code::XFS_INODE, format!("{child}: {e:?}"));
                    let kind = match d.ftype {
                        Some(fs_xfs::inode::FileType::Directory) => EntryKind::Dir,
                        Some(fs_xfs::inode::FileType::Symlink) => EntryKind::Symlink,
                        Some(fs_xfs::inode::FileType::Regular) => EntryKind::File,
                        _ => EntryKind::Other,
                    };
                    let mut e = Entry::new(&child, kind);
                    e.id = d.ino;
                    out.push(e);
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn copy_to(&self, path: &str, stream: Option<&str>, sink: Sink<'_>, progress: Option<Progress<'_>>) -> Result<u64> {
        if stream.is_some_and(|s| !s.is_empty()) {
            return Err(Error::new(fscode::FS_STREAM_NOT_FOUND, path.to_string()));
        }
        let (inode, raw) = self.lookup(path)?;
        if inode.is_symlink() {
            return Err(Error::new(fscode::FS_SYMLINK_NOT_FOLLOWED, path.to_string()));
        }
        if !inode.is_regular_file() {
            return Err(Error::new(fscode::FS_NOT_A_FILE, path.to_string()));
        }
        let total = inode.size;
        let mut done = 0u64;
        let mut buf = vec![0u8; 1 << 20];
        let mut progress = progress;
        while done < total {
            let want = buf.len().min((total - done) as usize);
            let n = match self.fs.read_at(&inode, &raw, done, &mut buf[..want]) {
                Ok(n) => n,
                Err(e) => {
                    diag::warn(code::XFS_READ, format!("{path}: after {done} of {total} bytes: {e:?}"));
                    return Err(Error::new(fscode::FS_READ, format!("{path}: {e:?}")));
                }
            };
            if n == 0 {
                break;
            }
            sink.write_all(&buf[..n]).map_err(|e| Error::recorded(crate::extract::code::EXTRACT_WRITE, format!("{path}: {e}")))?;
            done += n as u64;
            if let Some(p) = progress.as_deref_mut() {
                p(done, total);
            }
        }
        Ok(done)
    }
}

impl std::fmt::Debug for XfsFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "XfsFs(uuid {}, {} bytes)", self.uuid, self.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_is_not_xfs() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let r = SharedReader::from_bytes(vec![0u8; 1 << 20]);
        assert_eq!(XfsFs::open(r, "test").unwrap_err().code, code::XFS_OPEN);
        crate::diag::drain();
    }

    #[test]
    fn zero_timestamps_are_unset() {
        assert_eq!(ts(fs_xfs::inode::Timestamp { sec: 0, nsec: 0 }), None);
        assert_eq!(ts(fs_xfs::inode::Timestamp { sec: 5, nsec: 6 }), Some(Timestamp::from_unix(5, 6)));
    }
}
