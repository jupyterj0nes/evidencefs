//! Volume Shadow Copies of an NTFS volume, each readable as the volume looked when the
//! snapshot was taken.
//!
//! The `vshadow` crate's store reader borrows the volume reader for its whole life, which
//! cannot be boxed into a `'static` [`SharedReader`]. Each snapshot is therefore served by
//! a thread of its own that owns the parsed catalog, the volume handle and the store
//! reader, and answers positioned reads over a channel. The thread ends when the last
//! reader handle is dropped.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use vshadow::VssVolume;

use crate::diag;
use crate::error::{Error, Result};
use crate::source::SharedReader;
use crate::time::Timestamp;

pub mod code {
    crate::codes! {
        VSS_NONE = 350, "the NTFS volume has no Volume Shadow Copy structures (no VSS catalog); there are no snapshots to read";
        VSS_CATALOG_DAMAGED = 351, "the volume has a VSS header but its catalog could not be parsed; the snapshots were deleted, the catalog was overwritten, or the volume is truncated";
        VSS_STORE_INFO = 352, "the metadata of one snapshot could not be read; that snapshot is skipped";
        VSS_STORE_READER = 353, "the block map of one snapshot could not be parsed; that snapshot is skipped, its store area was overwritten";
        VSS_LISTED = 354, "the snapshots of the volume, with their creation times";
        VSS_READER_GONE = 355, "the thread serving a snapshot ended before a read was answered; the snapshot can no longer be read in this process";
        VSS_STORE_EMPTY = 356, "a snapshot has no changed blocks; it reads exactly like the live volume";
    }
}

/// One snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Position in the catalog (0-based), stable for a given volume.
    pub index: usize,
    /// The store GUID in text.
    pub id: String,
    /// When the snapshot was taken (None when the FILETIME is zero).
    pub created: Option<Timestamp>,
    /// VSS sequence number.
    pub sequence: u64,
    /// The volume size the store records.
    pub volume_size: u64,
    /// Number of 16 KB blocks the store keeps (changed since the snapshot).
    pub changed_blocks: Option<usize>,
}

impl Snapshot {
    /// `partition_<n>_vss_<index>`: the folder name the c00pr tools stage a snapshot under.
    pub fn dir_name(&self, partition_index: usize) -> String {
        format!("partition_{partition_index}_vss_{}", self.index)
    }

    /// `vss:<index>:<created>` tag for timelines.
    pub fn tag(&self) -> String {
        format!("vss:{}:{}", self.index, self.created.map(|t| t.to_human()).unwrap_or_else(|| "unknown".into()))
    }

    /// `VSS_INFO.txt` sidecar text, as faramir writes it.
    pub fn info_text(&self, partition_index: usize) -> String {
        format!("store={}\npartition={partition_index}\ncreated={}\nsequence={}\nid={}\n", self.index, self.created.map(|t| format!("{} UTC", t.to_human())).unwrap_or_else(|| "unknown".into()), self.sequence, self.id)
    }
}

/// The snapshots of an NTFS volume (`volume` is the partition's view).
pub fn list_snapshots(volume: &SharedReader, label: &str) -> Result<Vec<Snapshot>> {
    let mut r = volume.clone();
    let vss = match VssVolume::new(&mut r) {
        Ok(v) => v,
        Err(e) => {
            let text = format!("{e:?}");
            if text.contains("Catalog") || text.contains("catalog") {
                return Err(Error::warned(code::VSS_CATALOG_DAMAGED, format!("{label}: {text}")));
            }
            diag::info(code::VSS_NONE, format!("{label}: {text}"));
            return Ok(Vec::new());
        }
    };
    let count = vss.store_count();
    if count == 0 {
        diag::info(code::VSS_NONE, label.to_string());
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for i in 0..count {
        let info = match vss.store_info(i) {
            Ok(x) => x,
            Err(e) => {
                diag::warn(code::VSS_STORE_INFO, format!("{label}: store {i}: {e:?}"));
                continue;
            }
        };
        let changed = vss.store_delta_size(&mut r, i).ok().map(|(n, _)| n);
        if changed == Some(0) {
            diag::info(code::VSS_STORE_EMPTY, format!("{label}: store {i}"));
        }
        out.push(Snapshot { index: i, id: crate::volume::guid_text(&info.store_id), created: Timestamp::from_nt(info.creation_time), sequence: info.sequence, volume_size: info.volume_size, changed_blocks: changed });
    }
    diag::info(code::VSS_LISTED, format!("{label}: {}", out.iter().map(|s| s.tag()).collect::<Vec<_>>().join(", ")));
    Ok(out)
}

enum Request {
    Read { offset: u64, len: usize, reply: Sender<io::Result<Vec<u8>>> },
    Stop,
}

/// The handle every clone of a snapshot reader shares: the request channel.
struct Server {
    tx: Mutex<Sender<Request>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Ok(tx) = self.tx.lock() {
            let _ = tx.send(Request::Stop);
        }
    }
}

/// A positioned reader over one snapshot, served by its thread.
struct SnapshotReader {
    server: Arc<Server>,
    size: u64,
    pos: u64,
}

impl Read for SnapshotReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min((self.size - self.pos) as usize);
        let (reply_tx, reply_rx) = mpsc::channel();
        {
            let tx = self.server.tx.lock().map_err(|_| io::Error::other("snapshot server lock poisoned"))?;
            tx.send(Request::Read { offset: self.pos, len: want, reply: reply_tx }).map_err(|_| {
                diag::warn(code::VSS_READER_GONE, "send");
                io::Error::other("snapshot server gone")
            })?;
        }
        let data = reply_rx.recv().map_err(|_| {
            diag::warn(code::VSS_READER_GONE, "recv");
            io::Error::other("snapshot server gone")
        })??;
        let n = data.len().min(want);
        buf[..n].copy_from_slice(&data[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SnapshotReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?,
            SeekFrom::End(d) => self.size.checked_add_signed(d).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?,
        };
        Ok(self.pos)
    }
}

fn serve(volume: SharedReader, index: usize, rx: Receiver<Request>, ready: Sender<Result<u64>>, label: String) {
    let mut r = volume;
    let vss = match VssVolume::new(&mut r) {
        Ok(v) => v,
        Err(e) => {
            let _ = ready.send(Err(Error::new(code::VSS_CATALOG_DAMAGED, format!("{label}: {e:?}"))));
            return;
        }
    };
    let mut store = match vss.store_reader(&mut r, index) {
        Ok(s) => s,
        Err(e) => {
            let _ = ready.send(Err(Error::new(code::VSS_STORE_READER, format!("{label}: store {index}: {e:?}"))));
            return;
        }
    };
    let size = store.seek(SeekFrom::End(0)).unwrap_or(0);
    if ready.send(Ok(size)).is_err() {
        return;
    }
    while let Ok(req) = rx.recv() {
        match req {
            Request::Stop => break,
            Request::Read { offset, len, reply } => {
                let result = (|| {
                    store.seek(SeekFrom::Start(offset))?;
                    let mut out = vec![0u8; len];
                    let mut got = 0;
                    // The store reader answers up to a 16 KB block boundary per call.
                    while got < len {
                        let n = store.read(&mut out[got..])?;
                        if n == 0 {
                            break;
                        }
                        got += n;
                    }
                    out.truncate(got);
                    Ok(out)
                })();
                let _ = reply.send(result);
            }
        }
    }
}

/// A reader over the volume as it was at snapshot `index`. The thread serving it lives
/// as long as any clone of the returned reader.
pub fn snapshot_reader(volume: &SharedReader, index: usize, label: &str) -> Result<SharedReader> {
    let (tx, rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let vol = volume.clone();
    let lbl = label.to_string();
    std::thread::Builder::new().name(format!("vss-{index}")).spawn(move || serve(vol, index, rx, ready_tx, lbl)).map_err(|e| Error::recorded(code::VSS_STORE_READER, format!("{label}: thread: {e}")))?;
    let size = match ready_rx.recv() {
        Ok(Ok(size)) => size,
        Ok(Err(e)) => {
            diag::warn(e.code, e.msg.clone());
            return Err(e);
        }
        Err(_) => return Err(Error::recorded(code::VSS_READER_GONE, label.to_string())),
    };
    let server = Arc::new(Server { tx: Mutex::new(tx) });
    Ok(SharedReader::with_len(Box::new(SnapshotReader { server, size, pos: 0 }), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_names_and_sidecar() {
        let s = Snapshot { index: 2, id: "abc".into(), created: Timestamp::from_civil(2026, 3, 4, 5, 6, 7), sequence: 9, volume_size: 100, changed_blocks: Some(3) };
        assert_eq!(s.dir_name(0), "partition_0_vss_2");
        assert_eq!(s.tag(), "vss:2:2026-03-04 05:06:07");
        let info = s.info_text(0);
        assert!(info.contains("store=2\n") && info.contains("created=2026-03-04 05:06:07 UTC\n") && info.contains("sequence=9\n") && info.contains("id=abc\n"));
        let unknown = Snapshot { created: None, ..s };
        assert_eq!(unknown.tag(), "vss:2:unknown");
        assert!(unknown.info_text(1).contains("created=unknown\n"));
    }

    #[test]
    fn a_volume_without_vss_lists_nothing() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let mut img = vec![0u8; 1 << 20];
        img[3..11].copy_from_slice(b"NTFS    ");
        let r = SharedReader::from_bytes(img);
        let snaps = list_snapshots(&r, "test").unwrap_or_default();
        assert!(snaps.is_empty());
        assert!(crate::diag::has(code::VSS_NONE) || crate::diag::has(code::VSS_CATALOG_DAMAGED));
        crate::diag::drain();
        // Asking for a reader on a volume with no catalog fails with a code, and the thread ends.
        let e = snapshot_reader(&r, 0, "test").unwrap_err();
        assert!(e.code == code::VSS_CATALOG_DAMAGED || e.code == code::VSS_STORE_READER);
        crate::diag::drain();
    }
}
