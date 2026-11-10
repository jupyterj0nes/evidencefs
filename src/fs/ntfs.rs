//! NTFS volumes through the `ntfs` crate: names looked up with the volume's own `$UpCase`
//! table, `$STANDARD_INFORMATION` times, alternate data streams listed and readable,
//! reparse points described but never followed. The `$`-files (`$MFT`, `$LogFile`,
//! `$Extend/$UsnJrnl`) are ordinary entries: a tool that wants them asks for them.
//!
//! Deleted files come from a scan of the `$MFT` ([`crate::fs::mft`]): every record not
//! in use that still has a name is listed under `/$DELETED/<record>/<path>` with its
//! times, size and streams, and its content is streamed from the old data runs when they
//! are plain (not compressed) and the record has no attribute list.

use std::io::Read;
use std::sync::{Arc, Mutex};

use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::{NtfsFileAttributeFlags, NtfsFileNamespace, NtfsVolumeName};
use ntfs::{Ntfs, NtfsAttributeType, NtfsFile};

use crate::diag;
use crate::error::{Error, Result};
use crate::fs::mft::{self, Deleted};
use crate::fs::{code as fscode, components, deleted_path, is_deleted_root, join, normalize, parse_deleted, Entry, EntryKind, FileSystem, FsKind, Progress, Sink, Stream, DELETED_DIR};
use crate::source::SharedReader;
use crate::time::{Timestamp, Timestamps};

pub mod code {
    crate::codes! {
        NTFS_OPEN = 400, "the volume's boot sector or $MFT could not be parsed as NTFS; the partition offset is wrong, the boot sector is damaged (try the backup at the last sector), or the volume is BitLocker-encrypted";
        NTFS_UPCASE = 401, "the $UpCase table could not be read; case-insensitive lookups fall back to ASCII folding, names with non-ASCII letters may not be found";
        NTFS_ROOT = 402, "the root directory (record 5) could not be read; the $MFT is damaged at its start, nothing can be listed";
        NTFS_INDEX = 403, "a directory's $INDEX_ROOT / $INDEX_ALLOCATION could not be read; the directory is damaged, its content is not listed";
        NTFS_RECORD = 404, "a file record could not be read; the entry was built from the directory index alone ($FILE_NAME times, no alternate data streams)";
        NTFS_ATTRIBUTE = 405, "an attribute of a file record is damaged; the rest of the record was used";
        NTFS_NO_DATA = 406, "the file has no unnamed $DATA attribute; it reads as empty";
        NTFS_COMPRESSED = 407, "the file's data is NTFS-compressed or sparse in a way this reader does not decode; its content cannot be streamed, only its metadata is available";
        NTFS_REPARSE = 408, "the reparse point data could not be decoded; the entry is listed as a link without a target";
        NTFS_OPENED = 409, "an NTFS volume was opened: label, serial number, cluster size and size";
        NTFS_NAME_LOSSY = 410, "a file name has unpaired UTF-16 surrogates; it is shown with replacement characters";
        NTFS_DATA_RUN = 411, "reading a file's data failed part-way (a bad data run or a read past the volume); the bytes read so far are kept";
        NTFS_MFT_STREAM = 412, "the $MFT's own data stream (record 0) could not be opened; deleted files cannot be listed on this volume";
        NTFS_DELETED_LISTED = 413, "the deleted entries of the volume were listed from the $MFT: how many, how many with content still readable";
        NTFS_DELETED_READ = 414, "reading a deleted file's clusters failed; the run points outside the volume or the image is truncated there, the bytes read so far are kept";
        NTFS_DELETED_RECORD = 415, "the $DELETED id is not a record number; use the number shown in the listing (`/$DELETED/1234/...`)";
    }
}

/// An NTFS volume.
pub struct NtfsFs {
    reader: Mutex<SharedReader>,
    ntfs: Ntfs,
    label: Option<String>,
    size: u64,
    /// The deleted records, once scanned.
    deleted: Mutex<Option<Arc<Vec<Deleted>>>>,
}

const DOS_ONLY: Option<NtfsFileNamespace> = Some(NtfsFileNamespace::Dos);

fn nt(t: ntfs::NtfsTime) -> Option<Timestamp> {
    Timestamp::from_nt(t.nt_timestamp())
}

impl NtfsFs {
    /// Opens the volume whose first byte is the boot sector.
    pub fn open(volume: SharedReader, label_for_logs: &str) -> Result<Self> {
        let mut r = volume.clone();
        let mut ntfs = Ntfs::new(&mut r).map_err(|e| Error::recorded(code::NTFS_OPEN, format!("{label_for_logs}: {e}")))?;
        if let Err(e) = ntfs.read_upcase_table(&mut r) {
            diag::warn(code::NTFS_UPCASE, format!("{label_for_logs}: {e}"));
        }
        let size = ntfs.size();
        let mut label = None;
        if let Ok(vol) = ntfs.file(&mut r, 3) {
            let mut it = vol.attributes();
            while let Some(item) = it.next(&mut r) {
                let Ok(item) = item else { break };
                let Ok(attr) = item.to_attribute() else { break };
                if attr.ty().ok() == Some(NtfsAttributeType::VolumeName) {
                    if let Ok(v) = attr.resident_structured_value::<NtfsVolumeName>() {
                        let s = v.name().to_string_lossy();
                        if !s.is_empty() {
                            label = Some(s);
                        }
                    }
                }
            }
        }
        // Make sure the root is readable before promising anything.
        ntfs.root_directory(&mut r).map_err(|e| Error::recorded(code::NTFS_ROOT, format!("{label_for_logs}: {e}")))?;
        diag::info(code::NTFS_OPENED, format!("{label_for_logs}: label {:?}, serial {:016x}, cluster {} bytes, {}", label.as_deref().unwrap_or(""), ntfs.serial_number(), ntfs.cluster_size(), crate::volume::human_size(size)));
        Ok(NtfsFs { reader: Mutex::new(volume), ntfs, label, size, deleted: Mutex::new(None) })
    }

    /// Size of a `FILE` record.
    pub fn record_size(&self) -> u32 {
        self.ntfs.file_record_size()
    }

    /// The deleted records of the volume (scanned once, then cached).
    fn deleted_list(&self, r: &mut SharedReader, progress: Option<Progress<'_>>) -> Result<Arc<Vec<Deleted>>> {
        if let Some(list) = self.deleted.lock().ok().and_then(|g| g.clone()) {
            return Ok(list);
        }
        let mft = self.ntfs.file(r, 0).map_err(|e| Error::recorded(code::NTFS_MFT_STREAM, format!("record 0: {e}")))?;
        let item = match mft.data(r, "") {
            Some(Ok(item)) => item,
            Some(Err(e)) => return Err(Error::recorded(code::NTFS_MFT_STREAM, format!("$DATA: {e}"))),
            None => return Err(Error::recorded(code::NTFS_MFT_STREAM, "no $DATA on record 0")),
        };
        let attr = item.to_attribute().map_err(|e| Error::recorded(code::NTFS_MFT_STREAM, e.to_string()))?;
        let total = attr.value_length();
        let value = attr.value(r).map_err(|e| Error::recorded(code::NTFS_MFT_STREAM, e.to_string()))?;
        let attached = value.attach(r);
        let scan = mft::scan(attached, self.ntfs.file_record_size() as usize, total, progress);
        let recoverable = scan.deleted.iter().filter(|d| d.recoverable(true)).count();
        diag::info(code::NTFS_DELETED_LISTED, format!("{} deleted entries, {recoverable} recoverable, {} records scanned", scan.deleted.len(), scan.records));
        let list = Arc::new(scan.deleted);
        if let Ok(mut g) = self.deleted.lock() {
            *g = Some(list.clone());
        }
        Ok(list)
    }

    /// The entry of a deleted record.
    fn deleted_entry(&self, d: &Deleted) -> Entry {
        let kind = if d.record.is_dir { EntryKind::Dir } else { EntryKind::File };
        let mut e = Entry::new(&deleted_path(&d.record.number.to_string(), &d.path), kind);
        e.id = d.record.number;
        e.size = if d.record.is_dir { 0 } else { d.size() };
        e.times = d.times();
        e.deleted = true;
        e.recoverable = d.recoverable(true);
        for s in &d.record.data {
            if !s.name.is_empty() && !e.streams.iter().any(|x| x.name == s.name) {
                e.streams.push(Stream { name: s.name.clone(), size: s.size });
            }
        }
        e.streams.sort_by(|a, b| a.name.cmp(&b.name));
        e
    }

    /// Finds a deleted record by the id in a `$DELETED` path.
    fn find_deleted<'a>(&self, list: &'a [Deleted], id: &str, path: &str) -> Result<&'a Deleted> {
        let n: u64 = id.parse().map_err(|_| Error::new(code::NTFS_DELETED_RECORD, path.to_string()))?;
        list.binary_search_by_key(&n, |d| d.record.number).map(|i| &list[i]).map_err(|_| Error::new(fscode::FS_DELETED_NOT_FOUND, path.to_string()))
    }

    /// The `$DELETED` folder itself.
    fn deleted_root_entry(&self) -> Entry {
        let mut e = Entry::new(&format!("/{DELETED_DIR}"), EntryKind::Dir);
        e.deleted = true;
        e
    }

    /// Volume serial number.
    pub fn serial_number(&self) -> u64 {
        self.ntfs.serial_number()
    }

    /// Bytes per cluster.
    pub fn cluster_size(&self) -> u32 {
        self.ntfs.cluster_size()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, SharedReader>> {
        self.reader.lock().map_err(|_| Error::recorded(crate::source::code::READER_LOCK_POISONED, "ntfs"))
    }

    /// Walks the path from the root, one index lookup per component.
    fn navigate<'n>(&'n self, r: &mut SharedReader, path: &str) -> Result<NtfsFile<'n>> {
        let norm = normalize(path);
        let mut current = self.ntfs.root_directory(r).map_err(|e| Error::recorded(code::NTFS_ROOT, e.to_string()))?;
        for component in components(&norm) {
            if !current.is_directory() {
                return Err(Error::new(fscode::FS_NOT_A_DIR, path.to_string()));
            }
            let index = current.directory_index(r).map_err(|e| Error::recorded(code::NTFS_INDEX, format!("{path}: {e}")))?;
            let mut finder = index.finder();
            let next = match NtfsFileNameIndex::find(&mut finder, &self.ntfs, r, component) {
                Some(Ok(entry)) => entry.file_reference().to_file(&self.ntfs, r).map_err(|e| Error::recorded(code::NTFS_RECORD, format!("{path}: {e}")))?,
                Some(Err(e)) => return Err(Error::recorded(code::NTFS_INDEX, format!("{path}: {e}"))),
                None => return Err(Error::new(fscode::FS_NOT_FOUND, path.to_string())),
            };
            current = next;
        }
        Ok(current)
    }

    /// Builds an entry from a file record (and the name the directory gave it).
    fn entry_of(&self, r: &mut SharedReader, file: &NtfsFile<'_>, path: &str) -> Entry {
        let is_dir = file.is_directory();
        let mut e = Entry::new(path, if is_dir { EntryKind::Dir } else { EntryKind::File });
        e.id = file.file_record_number();
        let mut reparse = false;
        match file.info() {
            Ok(si) => {
                e.times = Timestamps { created: nt(si.creation_time()), modified: nt(si.modification_time()), accessed: nt(si.access_time()), changed: nt(si.mft_record_modification_time()) };
                reparse = si.file_attributes().contains(NtfsFileAttributeFlags::REPARSE_POINT);
            }
            Err(err) => {
                diag::warn(code::NTFS_ATTRIBUTE, format!("{path}: $STANDARD_INFORMATION: {err}"));
            }
        }
        // Data streams and the reparse target.
        let mut it = file.attributes();
        let mut unnamed_size: Option<u64> = None;
        let mut reparse_target: Option<String> = None;
        while let Some(item) = it.next(r) {
            let item = match item {
                Ok(i) => i,
                Err(err) => {
                    diag::warn(code::NTFS_ATTRIBUTE, format!("{path}: {err}"));
                    break;
                }
            };
            let attr = match item.to_attribute() {
                Ok(a) => a,
                Err(err) => {
                    diag::warn(code::NTFS_ATTRIBUTE, format!("{path}: {err}"));
                    break;
                }
            };
            match attr.ty() {
                Ok(NtfsAttributeType::Data) => {
                    let name = attr.name().map(|n| n.to_string_lossy()).unwrap_or_default();
                    if name.is_empty() {
                        if unnamed_size.is_none() {
                            unnamed_size = Some(attr.value_length());
                        }
                    } else if !e.streams.iter().any(|s| s.name == name) {
                        e.streams.push(Stream { name, size: attr.value_length() });
                    }
                }
                Ok(NtfsAttributeType::ReparsePoint) if reparse => {
                    if let Ok(value) = attr.value(r) {
                        let len = value.len();
                        if len <= 64 * 1024 {
                            let mut data = Vec::with_capacity(len as usize);
                            let mut attached = value.attach(r);
                            if attached.read_to_end(&mut data).is_ok() {
                                reparse_target = decode_reparse(&data);
                            }
                        }
                    }
                    if reparse_target.is_none() {
                        diag::info(code::NTFS_REPARSE, path.to_string());
                    }
                }
                _ => {}
            }
        }
        if reparse {
            e.kind = EntryKind::Symlink;
            e.link_target = reparse_target;
        }
        e.size = if is_dir { 0 } else { unnamed_size.unwrap_or(0) };
        e.streams.sort_by(|a, b| a.name.cmp(&b.name));
        e
    }
}

/// The substitute name of a symbolic link or junction reparse buffer.
pub fn decode_reparse(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (sub_off, sub_len, body) = match tag {
        0xA000_000C => {
            // Symlink: offsets, lengths, flags, then the path buffer.
            if data.len() < 20 {
                return None;
            }
            (u16::from_le_bytes([data[8], data[9]]) as usize, u16::from_le_bytes([data[10], data[11]]) as usize, &data[20..])
        }
        0xA000_0003 => {
            // Mount point / junction: no flags field.
            if data.len() < 16 {
                return None;
            }
            (u16::from_le_bytes([data[8], data[9]]) as usize, u16::from_le_bytes([data[10], data[11]]) as usize, &data[16..])
        }
        _ => return Some(format!("reparse tag {tag:#010x}")),
    };
    let slice = body.get(sub_off..sub_off + sub_len)?;
    let units: Vec<u16> = slice.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let s = String::from_utf16_lossy(&units);
    Some(s.strip_prefix("\\??\\").unwrap_or(&s).to_string())
}

impl FileSystem for NtfsFs {
    fn kind(&self) -> FsKind {
        FsKind::Ntfs
    }

    fn label(&self) -> Option<String> {
        self.label.clone()
    }

    fn size(&self) -> Option<u64> {
        Some(self.size)
    }

    fn supports_deleted(&self) -> bool {
        true
    }

    fn deleted(&self, progress: Option<Progress<'_>>) -> Result<Vec<Entry>> {
        self.deleted_entries(progress)
    }

    fn metadata(&self, path: &str) -> Result<Entry> {
        if is_deleted_root(path) {
            return Ok(self.deleted_root_entry());
        }
        let mut guard = self.lock()?;
        let r: &mut SharedReader = &mut guard;
        if let Some((id, _)) = parse_deleted(path) {
            let list = self.deleted_list(r, None)?;
            let d = self.find_deleted(&list, &id, path)?;
            return Ok(self.deleted_entry(d));
        }
        let file = self.navigate(r, path)?;
        Ok(self.entry_of(r, &file, &normalize(path)))
    }

    fn read_dir(&self, path: &str) -> Result<Vec<Entry>> {
        let mut guard = self.lock()?;
        let r: &mut SharedReader = &mut guard;
        if is_deleted_root(path) {
            let list = self.deleted_list(r, None)?;
            return Ok(list.iter().map(|d| self.deleted_entry(d)).collect());
        }
        if let Some((id, _)) = parse_deleted(path) {
            let list = self.deleted_list(r, None)?;
            let d = self.find_deleted(&list, &id, path)?;
            if !d.record.is_dir {
                return Err(Error::new(fscode::FS_NOT_A_DIR, path.to_string()));
            }
            // The children of a deleted directory are deleted entries of their own.
            let prefix = format!("{}/", d.path.trim_end_matches('/'));
            return Ok(list.iter().filter(|c| c.path.starts_with(&prefix) && !c.path[prefix.len()..].contains('/')).map(|c| self.deleted_entry(c)).collect());
        }
        let dir = self.navigate(r, path)?;
        if !dir.is_directory() {
            return Err(Error::new(fscode::FS_NOT_A_DIR, path.to_string()));
        }
        let norm = normalize(path);
        let index = dir.directory_index(r).map_err(|e| Error::recorded(code::NTFS_INDEX, format!("{path}: {e}")))?;
        let mut out = Vec::new();
        let mut entries = index.entries();
        while let Some(entry) = entries.next(r) {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    diag::warn(code::NTFS_INDEX, format!("{path}: {e}"));
                    break;
                }
            };
            let Some(Ok(key)) = entry.key() else { continue };
            if Some(key.namespace()) == DOS_ONLY {
                continue;
            }
            let name = key.name().to_string_lossy();
            if name == "." || name.is_empty() {
                continue;
            }
            if name.contains('\u{FFFD}') {
                diag::info(code::NTFS_NAME_LOSSY, format!("{norm}: {name}"));
            }
            let child_path = join(&norm, &name);
            match entry.file_reference().to_file(&self.ntfs, r) {
                Ok(file) => out.push(self.entry_of(r, &file, &child_path)),
                Err(e) => {
                    diag::warn(code::NTFS_RECORD, format!("{child_path}: {e}"));
                    let mut en = Entry::new(&child_path, if key.is_directory() { EntryKind::Dir } else { EntryKind::File });
                    en.size = if key.is_directory() { 0 } else { key.data_size() };
                    en.times = Timestamps { created: nt(key.creation_time()), modified: nt(key.modification_time()), accessed: nt(key.access_time()), changed: nt(key.mft_record_modification_time()) };
                    en.id = entry.file_reference().file_record_number();
                    out.push(en);
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out.dedup_by(|a, b| a.path == b.path);
        Ok(out)
    }

    fn copy_to(&self, path: &str, stream: Option<&str>, sink: Sink<'_>, progress: Option<Progress<'_>>) -> Result<u64> {
        let mut guard = self.lock()?;
        let r: &mut SharedReader = &mut guard;
        if let Some((id, _)) = parse_deleted(path) {
            let list = self.deleted_list(r, None)?;
            let d = self.find_deleted(&list, &id, path)?;
            if d.record.is_dir {
                return Err(Error::new(fscode::FS_NOT_A_FILE, path.to_string()));
            }
            let stream_name = stream.unwrap_or("");
            let data = match d.record.data.iter().find(|x| x.name.eq_ignore_ascii_case(stream_name)) {
                Some(x) => x,
                None if stream_name.is_empty() => return Err(Error::new(fscode::FS_DELETED_UNRECOVERABLE, format!("{path}: no $DATA left in the record"))),
                None => return Err(Error::new(fscode::FS_STREAM_NOT_FOUND, format!("{path}:{stream_name}"))),
            };
            if d.record.has_attribute_list || !data.is_plain() || (data.resident.is_none() && data.runs.is_empty() && data.size > 0) {
                return Err(Error::new(fscode::FS_DELETED_UNRECOVERABLE, path.to_string()));
            }
            let cs = self.ntfs.cluster_size() as u64;
            let volume = r.clone();
            let mut read_clusters = |lcn: u64, count: u64| -> std::io::Result<Vec<u8>> {
                let mut buf = vec![0u8; (count * cs) as usize];
                volume.read_at(lcn * cs, &mut buf)?;
                Ok(buf)
            };
            return match mft::stream_data(data, cs, &mut read_clusters, sink, progress) {
                Ok(n) => Ok(n),
                Err(e) => {
                    diag::warn(code::NTFS_DELETED_READ, format!("{path}: {e}"));
                    Err(Error::new(fscode::FS_READ, format!("{path}: {e}")))
                }
            };
        }
        let file = self.navigate(r, path)?;
        if file.is_directory() {
            return Err(Error::new(fscode::FS_NOT_A_FILE, path.to_string()));
        }
        let stream_name = stream.unwrap_or("");
        let item = match file.data(r, stream_name) {
            Some(Ok(item)) => item,
            Some(Err(e)) => return Err(Error::recorded(code::NTFS_ATTRIBUTE, format!("{path}: {e}"))),
            None => {
                if stream_name.is_empty() {
                    diag::info(code::NTFS_NO_DATA, path.to_string());
                    return Ok(0);
                }
                return Err(Error::new(fscode::FS_STREAM_NOT_FOUND, format!("{path}:{stream_name}")));
            }
        };
        let attr = item.to_attribute().map_err(|e| Error::recorded(code::NTFS_ATTRIBUTE, format!("{path}: {e}")))?;
        let total = attr.value_length();
        let value = attr.value(r).map_err(|e| {
            let text = e.to_string();
            if text.to_lowercase().contains("compress") || text.to_lowercase().contains("sparse") {
                Error::recorded(code::NTFS_COMPRESSED, format!("{path}: {text}"))
            } else {
                Error::recorded(code::NTFS_ATTRIBUTE, format!("{path}: {text}"))
            }
        })?;
        let mut attached = value.attach(r);
        let mut done = 0u64;
        let mut buf = vec![0u8; 1 << 20];
        let mut progress = progress;
        loop {
            let n = match attached.read(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    let text = e.to_string();
                    if text.to_lowercase().contains("compress") {
                        return Err(Error::recorded(code::NTFS_COMPRESSED, format!("{path}: {text}")));
                    }
                    diag::warn(code::NTFS_DATA_RUN, format!("{path}: after {done} of {total} bytes: {text}"));
                    return Err(Error::new(fscode::FS_READ, format!("{path}: {text}")));
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

impl NtfsFs {
    /// The deleted entries, scanning the `$MFT` the first time.
    pub fn deleted_entries(&self, progress: Option<Progress<'_>>) -> Result<Vec<Entry>> {
        let mut guard = self.lock()?;
        let r: &mut SharedReader = &mut guard;
        let list = self.deleted_list(r, progress)?;
        Ok(list.iter().map(|d| self.deleted_entry(d)).collect())
    }

    /// The raw deleted records, for tools that want the runs and names themselves.
    pub fn deleted_records(&self, progress: Option<Progress<'_>>) -> Result<Arc<Vec<Deleted>>> {
        let mut guard = self.lock()?;
        let r: &mut SharedReader = &mut guard;
        self.deleted_list(r, progress)
    }
}

impl std::fmt::Debug for NtfsFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NtfsFs(label {:?}, serial {:016x}, {} bytes)", self.label, self.ntfs.serial_number(), self.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn reparse_symlink_and_junction_decode() {
        // Symlink to C:\Target with the \??\ prefix in the substitute name.
        let sub = utf16("\\??\\C:\\Target");
        let print = utf16("C:\\Target");
        let mut d = Vec::new();
        d.extend_from_slice(&0xA000_000Cu32.to_le_bytes());
        d.extend_from_slice(&((12 + sub.len() + print.len()) as u16).to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes()); // sub off
        d.extend_from_slice(&(sub.len() as u16).to_le_bytes());
        d.extend_from_slice(&(sub.len() as u16).to_le_bytes()); // print off
        d.extend_from_slice(&(print.len() as u16).to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes()); // flags
        d.extend_from_slice(&sub);
        d.extend_from_slice(&print);
        assert_eq!(decode_reparse(&d).as_deref(), Some("C:\\Target"));
        // Junction: no flags.
        let sub = utf16("\\??\\D:\\Mount");
        let mut j = Vec::new();
        j.extend_from_slice(&0xA000_0003u32.to_le_bytes());
        j.extend_from_slice(&((8 + sub.len()) as u16).to_le_bytes());
        j.extend_from_slice(&0u16.to_le_bytes());
        j.extend_from_slice(&0u16.to_le_bytes());
        j.extend_from_slice(&(sub.len() as u16).to_le_bytes());
        j.extend_from_slice(&(sub.len() as u16).to_le_bytes());
        j.extend_from_slice(&0u16.to_le_bytes());
        j.extend_from_slice(&sub);
        assert_eq!(decode_reparse(&j).as_deref(), Some("D:\\Mount"));
        // Other tags are named; junk is None.
        let mut o = vec![0u8; 16];
        o[..4].copy_from_slice(&0x8000_0017u32.to_le_bytes());
        assert_eq!(decode_reparse(&o).as_deref(), Some("reparse tag 0x80000017"));
        assert_eq!(decode_reparse(&[1, 2, 3]), None);
        let mut short = Vec::new();
        short.extend_from_slice(&0xA000_000Cu32.to_le_bytes());
        short.extend_from_slice(&[0u8; 8]);
        assert_eq!(decode_reparse(&short), None);
    }

    #[test]
    fn garbage_is_not_ntfs() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let r = SharedReader::from_bytes(vec![0u8; 1 << 20]);
        assert_eq!(NtfsFs::open(r, "test").unwrap_err().code, code::NTFS_OPEN);
        assert!(crate::diag::has(code::NTFS_OPEN));
        crate::diag::drain();
    }
}
