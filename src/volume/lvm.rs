//! LVM2 physical volumes: the logical volumes inside, each read in place through the
//! `lvm2` crate's extent map. Striped, mirrored and thin layouts fail at read time and
//! are reported.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use crate::diag;
use crate::error::{Error, Result};
use crate::source::SharedReader;
use crate::volume::VolumeKind;

pub mod code {
    crate::codes! {
        LVM_OPEN = 300, "the LVM2 metadata of the physical volume could not be parsed; the PV is damaged, or it is only one PV of a volume group that spans several disks";
        LVM_NO_LVS = 301, "the volume group has no logical volumes; nothing to read";
        LVM_LV_UNREADABLE = 302, "a logical volume could not be opened through the extent map; its segments are not on this physical volume or use a layout the lvm2 crate does not resolve";
        LVM_LAYOUT_UNSUPPORTED = 303, "a logical volume is striped, mirrored, thin or spans another physical volume; only linear volumes on this PV are read, give the other PVs or dump the LV from a live system";
        LVM_LISTED = 304, "the logical volumes of the volume group, with their sizes and what they hold";
        LVM_LV_READ = 305, "a read inside a logical volume failed; the extent it maps to is beyond the image or unreadable";
    }
}

/// One logical volume of a physical volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalVolume {
    pub vg: String,
    pub name: String,
    pub size: u64,
    pub kind: VolumeKind,
}

impl LogicalVolume {
    /// `partition_<n>_lvm_<vg>_<lv>`: the folder name the c00pr tools stage an LV under.
    pub fn dir_name(&self, partition_index: usize) -> String {
        format!("partition_{partition_index}_lvm_{}_{}", sanitize(&self.vg), sanitize(&self.name))
    }

    /// `vg/lv`.
    pub fn label(&self) -> String {
        format!("{}/{}", self.vg, self.name)
    }
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect()
}

/// An open physical volume.
pub struct PhysicalVolume {
    lvm: Arc<lvm2::Lvm2>,
    pv: SharedReader,
    lvs: Vec<LogicalVolume>,
}

impl PhysicalVolume {
    /// Parses the LVM2 metadata of the volume `pv` (a partition view).
    pub fn open(pv: SharedReader, label: &str) -> Result<Self> {
        let lvm = lvm2::Lvm2::open(pv.clone()).map_err(|e| Error::recorded(code::LVM_OPEN, format!("{label}: {e:?}")))?;
        let lvm = Arc::new(lvm);
        let mut lvs = Vec::new();
        for lv in lvm.lvs() {
            let size = lv.size_in_extents() * lvm.extent_size();
            let name = lv.name().to_string();
            let kind = match lvm.open_lv_by_name(&name, pv.clone()) {
                Some(mut open) => {
                    let mut magic = [0u8; 2];
                    let ext = open.seek(SeekFrom::Start(0x438)).is_ok() && open.read_exact(&mut magic).is_ok() && u16::from_le_bytes(magic) == 0xEF53;
                    if ext {
                        VolumeKind::Ext
                    } else {
                        let mut head = [0u8; 11];
                        if open.seek(SeekFrom::Start(0)).is_ok() && open.read_exact(&mut head).is_ok() {
                            if &head[..4] == b"XFSB" {
                                VolumeKind::Xfs
                            } else if &head[3..11] == b"NTFS    " {
                                VolumeKind::Ntfs
                            } else {
                                let mut swap = [0u8; 10];
                                if open.seek(SeekFrom::Start(4096 - 10)).is_ok() && open.read_exact(&mut swap).is_ok() && &swap == b"SWAPSPACE2" {
                                    VolumeKind::Swap
                                } else {
                                    VolumeKind::Unknown
                                }
                            }
                        } else {
                            VolumeKind::Unknown
                        }
                    }
                }
                None => {
                    diag::warn(code::LVM_LV_UNREADABLE, format!("{label}: {}/{name}", lvm.vg_name()));
                    VolumeKind::Unknown
                }
            };
            lvs.push(LogicalVolume { vg: lvm.vg_name().to_string(), name, size, kind });
        }
        lvs.sort_by(|a, b| a.name.cmp(&b.name));
        if lvs.is_empty() {
            diag::warn(code::LVM_NO_LVS, format!("{label}: {}", lvm.vg_name()));
        } else {
            diag::info(code::LVM_LISTED, format!("{label}: {}", lvs.iter().map(|l| format!("{} {} ({})", l.label(), l.kind.label(), crate::volume::human_size(l.size))).collect::<Vec<_>>().join(", ")));
        }
        Ok(PhysicalVolume { lvm, pv, lvs })
    }

    /// The volume group's name.
    pub fn vg_name(&self) -> &str {
        self.lvm.vg_name()
    }

    /// The logical volumes, by name.
    pub fn logical_volumes(&self) -> &[LogicalVolume] {
        &self.lvs
    }

    /// A reader over one logical volume.
    pub fn reader(&self, lv: &LogicalVolume) -> SharedReader {
        let r = LvReader { lvm: Arc::clone(&self.lvm), name: lv.name.clone(), pv: self.pv.clone(), size: lv.size, pos: 0 };
        SharedReader::with_len(Box::new(r), lv.size)
    }
}

/// Linear logical volume read in place: every access re-resolves the extent map through
/// the `lvm2` crate (cheap, no I/O) and reads from the shared image.
struct LvReader {
    lvm: Arc<lvm2::Lvm2>,
    name: String,
    pv: SharedReader,
    size: u64,
    pos: u64,
}

impl Read for LvReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min((self.size - self.pos) as usize);
        let mut lv = self.lvm.open_lv_by_name(&self.name, self.pv.clone()).ok_or_else(|| {
            diag::warn(code::LVM_LV_UNREADABLE, self.name.clone());
            io::Error::other(format!("LV {} vanished", self.name))
        })?;
        lv.seek(SeekFrom::Start(self.pos)).inspect_err(|e| {
            let text = e.to_string();
            if text.contains("not linear") || text.contains("stripe") || text.contains("not on this PV") || text.contains("no suitable segment") {
                diag::warn(code::LVM_LAYOUT_UNSUPPORTED, format!("{}: {text}", self.name));
            } else {
                diag::warn(code::LVM_LV_READ, format!("{}: {text}", self.name));
            }
        })?;
        let n = lv.read(&mut buf[..want])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for LvReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?,
            SeekFrom::End(d) => self.size.checked_add_signed(d).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?,
        };
        Ok(self.pos)
    }
}

impl std::fmt::Debug for PhysicalVolume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PhysicalVolume(vg {}, {} LVs)", self.lvm.vg_name(), self.lvs.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sanitised_for_folders() {
        let lv = LogicalVolume { vg: "ubuntu-vg".into(), name: "root/odd name".into(), size: 10, kind: VolumeKind::Ext };
        assert_eq!(lv.dir_name(2), "partition_2_lvm_ubuntu-vg_root_odd_name");
        assert_eq!(lv.label(), "ubuntu-vg/root/odd name");
    }

    #[test]
    fn garbage_is_not_an_lvm_pv() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let r = SharedReader::from_bytes(vec![0u8; 1 << 20]);
        let e = PhysicalVolume::open(r, "test").unwrap_err();
        assert_eq!(e.code, code::LVM_OPEN);
        assert!(crate::diag::has(code::LVM_OPEN));
        crate::diag::drain();
    }
}
