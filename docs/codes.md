# Diagnostic codes

Every code evidencefs can record, with what it means and what to do about it. The ranges are in `src/diag.rs`.

| Code | Meaning |
|---|---|
| `EF001_IMAGE_NOT_FOUND` | the image path does not exist or cannot be read; check the path and that the first segment (E01, .001, the VMDK descriptor) is the one given |
| `EF002_IMAGE_UNKNOWN_FORMAT` | the file is not a disk image this crate knows (EWF, raw, split raw, VHD, VHDX, VMDK) by extension or by signature; if it is a raw dump with another extension, rename it to .raw or .dd |
| `EF003_IMAGE_SECONDARY_SEGMENT` | the file is a later segment of an image set (E02, .002, -s002.vmdk, -flat.vmdk); it was skipped because the first segment carries the whole set |
| `EF004_IMAGE_OPEN` | the image exists but could not be opened; another process may hold it, or the permissions deny reading |
| `EF005_IMAGE_READ` | a read inside the image failed; the file is truncated or the medium is failing, the bytes past that point are unreadable |
| `EF006_IMAGE_EMPTY` | the image has zero bytes; nothing to read |
| `EF007_IMAGE_BY_SIGNATURE` | the extension did not say what the image is, the first bytes did; the format was taken from the signature |
| `EF008_IMAGE_DEVICE_UNSUPPORTED` | a raw device path (\\.\PhysicalDrive0, /dev/sdb) was given; live devices are not read by this crate yet, acquire an image first |
| `EF009_IMAGE_SIZE_UNKNOWN` | the reader could not tell the size of the image; seeking to the end failed, the file is a pipe or a device |
| `EF010_READER_LOCK_POISONED` | a thread panicked while holding the shared reader; the image is still readable, the operation that panicked is lost |
| `EF011_IMAGE_SEGMENTS_LISTED` | the segments of a multi-part image were found next to the first one; this is the list that was opened |
| `EF012_IMAGE_SEGMENT_GAP` | the numbered segments of an image set have a gap (for example .001 and .003 without .002); the set is incomplete, reads past the gap return zeros |
| `EF100_VHD_OPEN` | the VHD file could not be opened; check the path and permissions |
| `EF101_VHD_TOO_SMALL` | the file is smaller than a VHD footer (512 bytes); it is not a VHD or it is truncated |
| `EF102_VHD_NO_FOOTER` | no 'conectix' footer at the end nor at the start of the file; the file is not a VHD or its last sector is missing |
| `EF103_VHD_FOOTER_FROM_START` | the footer at the end was missing or damaged, the copy at the start of the file was used; the disk was probably truncated after the last block, the data read is what remains |
| `EF104_VHD_DYNAMIC_HEADER` | the dynamic disk header ('cxsparse') could not be read or has the wrong signature; the footer's data offset points nowhere useful |
| `EF105_VHD_BLOCK_SIZE` | the dynamic disk header declares an invalid block size (zero or not a multiple of 512); the header is damaged |
| `EF106_VHD_BAT_TOO_BIG` | the block allocation table would be larger than the file itself; the header is damaged |
| `EF107_VHD_BAT_READ` | the block allocation table could not be read in full; the file is truncated |
| `EF108_VHD_DIFFERENCING` | the VHD is a differencing disk (it has a parent); merge it with its parent first (qemu-img convert, Hyper-V 'Merge') or give the merged disk |
| `EF109_VHD_UNKNOWN_TYPE` | the footer declares a disk type that is not fixed (2), dynamic (3) or differencing (4); the footer is damaged |
| `EF110_VHD_BLOCK_PAST_END` | a BAT entry points past the end of the file; that block reads as zeros, the disk was truncated or the BAT is damaged |
| `EF120_VHDX_OPEN` | the VHDX file could not be opened; check the path and permissions |
| `EF121_VHDX_NOT` | no 'vhdxfile' identifier at offset 0; the file is not a VHDX |
| `EF122_VHDX_REGION_TABLE` | neither region table (at 192 KB and 256 KB) is readable; the VHDX is truncated or damaged |
| `EF123_VHDX_NO_BAT` | the region table names no BAT region; the VHDX is damaged |
| `EF124_VHDX_NO_METADATA` | the region table names no metadata region; the VHDX is damaged |
| `EF125_VHDX_METADATA_SIG` | the metadata table has no 'metadata' signature; the VHDX is damaged |
| `EF126_VHDX_DIFFERENCING` | the VHDX has a parent (differencing disk); merge it with its parent first or give the merged disk |
| `EF127_VHDX_METADATA_MISSING` | the metadata carries no block size or no virtual disk size; the VHDX is damaged |
| `EF128_VHDX_METADATA_DAMAGED` | the metadata values are out of the range the format allows (block size, sector size or virtual size); the VHDX is damaged |
| `EF129_VHDX_PARTIAL_BLOCK` | a BAT entry is 'partially present', which only differencing disks have; the disk has a parent |
| `EF130_VHDX_BAT_READ` | the BAT could not be read in full; the file is truncated |
| `EF131_VHDX_LOG_PENDING` | the VHDX log region is not applied by this reader; a disk that was not cleanly detached may show stale sectors, mount it read-only in Hyper-V to replay the log if that matters |
| `EF150_VMDK_OPEN` | the VMDK file could not be opened; check the path and permissions |
| `EF151_VMDK_READ_HEADER` | the first bytes of the VMDK could not be read; the file is empty or unreadable |
| `EF152_VMDK_EXTENT_MISSING` | the descriptor names an extent file that is not next to it; only the descriptor was collected, the data file (-flat.vmdk, -sNNN.vmdk) is needed |
| `EF153_VMDK_EXTENT_FILEPART` | the extent file was found only as an incomplete upload (`<name>.filepart`) and was used as it is; the disk is incomplete past the uploaded bytes |
| `EF154_VMDK_EXTENT_TYPE` | the descriptor has an extent of a type this reader does not know (not FLAT, VMFS, SPARSE, VMFSSPARSE or ZERO) |
| `EF155_VMDK_NO_EXTENTS` | the descriptor has no RW/RDONLY/NOACCESS extent lines; it is not a VMDK descriptor or it is truncated |
| `EF156_VMDK_EXTENT_LINE` | an extent line of the descriptor is malformed (not `ACCESS SECTORS TYPE "FILE" [OFFSET]`); the descriptor is damaged |
| `EF157_VMDK_SPARSE_MAGIC` | a sparse extent has no KDMV magic; the file named as SPARSE is not one |
| `EF158_VMDK_SPARSE_DAMAGED` | a sparse extent header has values VMware never writes (grain size, table size or capacity); the header is damaged |
| `EF159_VMDK_GD_AT_END_UNCOMPRESSED` | the grain directory is marked as 'at end of file' but the extent is not streamOptimized; an unsupported layout |
| `EF160_VMDK_FOOTER_MISSING` | a streamOptimized VMDK has no valid footer; it was truncated during export or upload, the bytes beyond what was written cannot be read |
| `EF161_VMDK_GD_DOES_NOT_FIT` | the grain directory would lie beyond the end of the extent file; the extent is truncated or damaged |
| `EF162_VMDK_GRAIN_READ` | a grain could not be read or decompressed; that grain reads as zeros, the extent is damaged there |
| `EF163_VMDK_HAS_PARENT` | the VMDK is a snapshot delta (parentFileNameHint / parentCID set); give the base disk or merge the snapshot chain first (vmware-vdiskmanager -r, qemu-img convert) |
| `EF164_VMDK_RAW_FALLBACK` | the file has neither a sparse header nor a descriptor; it was read as a flat extent of its own size |
| `EF200_ARCHIVE_UNSUPPORTED` | the archive format (7z, RAR, xz, bz2) is not read by this crate; unpack it with 7-Zip or bsdtar and give the folder |
| `EF201_ARCHIVE_OPEN` | the archive could not be opened; the file is truncated, not an archive, or locked |
| `EF202_ARCHIVE_ENTRY_UNSAFE` | a member path climbs out of the destination ('..', absolute, drive letter) or is a device link; it was skipped |
| `EF203_ARCHIVE_ENTRY_ERROR` | a member could not be unpacked; the archive is damaged there, the rest went on |
| `EF204_ARCHIVE_UNPACKED` | an archive was unpacked into a temporary folder: members, bytes, destination |
| `EF205_ARCHIVE_NESTED` | an archive inside the evidence was found and opened as a nested mount |
| `EF206_ARCHIVE_NESTED_LIMIT` | an archive is nested deeper than the limit; it was listed as a file, not opened |
| `EF207_ARCHIVE_TEMP_DIR` | the temporary folder for unpacking could not be created; check the temp location and free space |
| `EF208_ARCHIVE_GZIP` | the gzip stream is damaged or truncated; the members unpacked before the damage are kept |
| `EF209_ARCHIVE_EMPTY` | the archive has no members |
| `EF210_ARCHIVE_BY_SIGNATURE` | the extension did not say what the archive is, the first bytes did |
| `EF211_ARCHIVE_TEMP_CLEANUP` | the temporary folder could not be removed when the evidence was closed; remove it by hand |
| `EF212_ARCHIVE_TAR_SPARSE` | a tar member is sparse or of a type (device, fifo) that is not unpacked; it was skipped |
| `EF213_ARCHIVE_SYMLINK_SKIPPED` | a tar member is a symbolic or hard link; links are not recreated, the member was skipped and noted |
| `EF250_PART_NO_TABLE` | the image has no MBR signature (55 AA) at the end of its first sector; it was read as a single volume starting at offset 0 |
| `EF251_PART_PROTECTIVE_MBR_ONLY` | the MBR marks the disk as GPT (type EE) but no GPT header was found at LBA 1 nor at the last LBA; the partition table is gone, the volumes were searched at common offsets |
| `EF252_PART_GPT_HEADER_BAD` | the GPT header is present but its fields are out of range (entry count, entry size, entry LBA); the entries were not read |
| `EF253_PART_GPT_BACKUP_USED` | the primary GPT header at LBA 1 was damaged or missing, the backup header at the last LBA was used instead |
| `EF254_PART_GPT_ENTRY_PAST_END` | a GPT entry starts or ends beyond the image; it was skipped, the image is truncated or the entry is damaged |
| `EF255_PART_MBR_EXTENDED` | the MBR has an extended partition; its EBR chain was followed and the logical partitions were added |
| `EF256_PART_EBR_LOOP` | the EBR chain of an extended partition loops or runs past 128 links; the chain was cut there |
| `EF257_PART_MBR_ENTRY_PAST_END` | an MBR entry starts beyond the image; it was skipped, the image is truncated or the entry is damaged |
| `EF258_PART_OVERLAP` | two partitions overlap; both were kept, the table is damaged or hand-edited |
| `EF259_PART_FALLBACK_OFFSET` | no partition table gave a readable volume; a file system signature was found at a common offset (0, 63 sectors, 1 MB, 2048 sectors) and that volume was added |
| `EF260_PART_BITLOCKER` | the volume is BitLocker-encrypted (-FVE-FS- signature); it cannot be read without the recovery key, decrypt it first (dislocker, manage-bde) and give the decrypted image |
| `EF261_PART_LUKS` | the volume is LUKS-encrypted; it cannot be read without the passphrase, open it with cryptsetup and image the mapped device |
| `EF262_PART_FS_UNSUPPORTED` | the volume holds a file system this crate does not read yet (btrfs, F2FS, APFS, HFS+, exFAT, FAT, ReFS, swap); it is listed but not walked |
| `EF263_PART_FS_UNKNOWN` | the volume holds no file system signature this crate knows; it is listed as unknown and not walked, it may be empty, encrypted with another product, or a raw data partition |
| `EF264_PART_NONE_READABLE` | no volume of the image can be read (no NTFS, ext, XFS or LVM); the image holds only unsupported, encrypted or empty volumes |
| `EF265_PART_LISTED` | the partitions of the image, with their kinds, as the table and the signatures gave them |
| `EF266_PART_SECTOR_4K` | the GPT header was found at offset 4096, so the disk uses 4 KB sectors; LBAs were converted with that size |
| `EF300_LVM_OPEN` | the LVM2 metadata of the physical volume could not be parsed; the PV is damaged, or it is only one PV of a volume group that spans several disks |
| `EF301_LVM_NO_LVS` | the volume group has no logical volumes; nothing to read |
| `EF302_LVM_LV_UNREADABLE` | a logical volume could not be opened through the extent map; its segments are not on this physical volume or use a layout the lvm2 crate does not resolve |
| `EF303_LVM_LAYOUT_UNSUPPORTED` | a logical volume is striped, mirrored, thin or spans another physical volume; only linear volumes on this PV are read, give the other PVs or dump the LV from a live system |
| `EF304_LVM_LISTED` | the logical volumes of the volume group, with their sizes and what they hold |
| `EF305_LVM_LV_READ` | a read inside a logical volume failed; the extent it maps to is beyond the image or unreadable |
| `EF350_VSS_NONE` | the NTFS volume has no Volume Shadow Copy structures (no VSS catalog); there are no snapshots to read |
| `EF351_VSS_CATALOG_DAMAGED` | the volume has a VSS header but its catalog could not be parsed; the snapshots were deleted, the catalog was overwritten, or the volume is truncated |
| `EF352_VSS_STORE_INFO` | the metadata of one snapshot could not be read; that snapshot is skipped |
| `EF353_VSS_STORE_READER` | the block map of one snapshot could not be parsed; that snapshot is skipped, its store area was overwritten |
| `EF354_VSS_LISTED` | the snapshots of the volume, with their creation times |
| `EF355_VSS_READER_GONE` | the thread serving a snapshot ended before a read was answered; the snapshot can no longer be read in this process |
| `EF356_VSS_STORE_EMPTY` | a snapshot has no changed blocks; it reads exactly like the live volume |
| `EF400_NTFS_OPEN` | the volume's boot sector or $MFT could not be parsed as NTFS; the partition offset is wrong, the boot sector is damaged (try the backup at the last sector), or the volume is BitLocker-encrypted |
| `EF401_NTFS_UPCASE` | the $UpCase table could not be read; case-insensitive lookups fall back to ASCII folding, names with non-ASCII letters may not be found |
| `EF402_NTFS_ROOT` | the root directory (record 5) could not be read; the $MFT is damaged at its start, nothing can be listed |
| `EF403_NTFS_INDEX` | a directory's $INDEX_ROOT / $INDEX_ALLOCATION could not be read; the directory is damaged, its content is not listed |
| `EF404_NTFS_RECORD` | a file record could not be read; the entry was built from the directory index alone ($FILE_NAME times, no alternate data streams) |
| `EF405_NTFS_ATTRIBUTE` | an attribute of a file record is damaged; the rest of the record was used |
| `EF406_NTFS_NO_DATA` | the file has no unnamed $DATA attribute; it reads as empty |
| `EF407_NTFS_COMPRESSED` | the file's data is NTFS-compressed or sparse in a way this reader does not decode; its content cannot be streamed, only its metadata is available |
| `EF408_NTFS_REPARSE` | the reparse point data could not be decoded; the entry is listed as a link without a target |
| `EF409_NTFS_OPENED` | an NTFS volume was opened: label, serial number, cluster size and size |
| `EF410_NTFS_NAME_LOSSY` | a file name has unpaired UTF-16 surrogates; it is shown with replacement characters |
| `EF411_NTFS_DATA_RUN` | reading a file's data failed part-way (a bad data run or a read past the volume); the bytes read so far are kept |
| `EF412_NTFS_MFT_STREAM` | the $MFT's own data stream (record 0) could not be opened; deleted files cannot be listed on this volume |
| `EF413_NTFS_DELETED_LISTED` | the deleted entries of the volume were listed from the $MFT: how many, how many with content still readable |
| `EF414_NTFS_DELETED_READ` | reading a deleted file's clusters failed; the run points outside the volume or the image is truncated there, the bytes read so far are kept |
| `EF415_NTFS_DELETED_RECORD` | the $DELETED id is not a record number; use the number shown in the listing (`/$DELETED/1234/...`) |
| `EF430_MFT_RECORD_SIZE` | the $MFT record size is not 1024 or 4096 bytes; the volume's boot sector is unusual or the file given is not an $MFT, nothing was parsed |
| `EF431_MFT_BAD_FIXUP` | a FILE record's update sequence does not match its sectors; the record is torn (half-written) and was skipped |
| `EF432_MFT_BAD_HEADER` | a record has no FILE signature or an impossible header; it is unused space or damage and was skipped |
| `EF433_MFT_ATTRIBUTE_TRUNCATED` | an attribute runs past the end of its record; the attributes before it were kept |
| `EF434_MFT_NAME_TOO_LONG` | a $FILE_NAME attribute claims more than 255 characters; the name was ignored |
| `EF435_MFT_RUNLIST_BAD` | a data run list is malformed (a run points before cluster 0 or past the end); the runs decoded so far were kept and the file is marked not recoverable |
| `EF436_MFT_ATTRIBUTE_LIST` | a deleted record has an $ATTRIBUTE_LIST: its attributes live in other records this reader does not chase, so its content may be incomplete and is marked not recoverable |
| `EF437_MFT_SCANNED` | the $MFT was scanned: records, in use, deleted with a name, bytes |
| `EF438_MFT_PARENT_REUSED` | the parent directory of a deleted file has been reused since (its sequence number moved on); the path is rebuilt under $OrphanFiles |
| `EF439_MFT_READ` | reading the $MFT stream failed part-way; the records read so far were kept |
| `EF440_MFT_COMPRESSED` | a deleted file's data is compressed, encrypted or sparse in a way this reader does not decode; its metadata is listed, its content is not recoverable |
| `EF441_MFT_EXTENSION_RECORD` | a record is an extension of another (its base reference is set); it carries no name of its own and was folded into the count |
| `EF442_MFT_TOO_MANY` | more deleted records than the limit were found; the list was cut |
| `EF450_EXT_OPEN` | the volume's superblock or group descriptors could not be parsed as ext2/3/4; the offset is wrong, the superblock is damaged (ext keeps backups at block group 1, 3, 5...), or the feature set is one the driver refuses |
| `EF451_EXT_READ_DIR` | a directory could not be listed; its blocks are damaged or the image is truncated there |
| `EF452_EXT_METADATA` | an inode could not be read; the inode table is damaged there, the entry is listed without times |
| `EF453_EXT_READ` | reading a file's content failed part-way; an extent points outside the volume or the image is truncated |
| `EF454_EXT_OPENED` | an ext volume was opened: label, UUID |
| `EF455_EXT_NAME_UNDECODABLE` | a file name is not UTF-8; it is shown lossily |
| `EF456_EXT_LINK_TARGET` | a symbolic link's target could not be read; the entry is listed as a link without a target |
| `EF457_EXT_PATH` | a path is not valid for ext4-view (empty component, NUL byte); it was refused |
| `EF458_EXT_RECOVER_GEOMETRY` | the superblock could not be parsed for recovery (bad magic, impossible geometry); the live tree still works, deleted files cannot be listed |
| `EF459_EXT_JOURNAL_INODE` | the journal inode is unreadable or is not a file (an external journal, or ext2 without one); only directory slack is searched for deleted names |
| `EF460_EXT_JOURNAL_SUPERBLOCK` | the journal file does not start with a jbd2 superblock; the journal was skipped |
| `EF461_EXT_JOURNAL_BLOCK_SIZE` | the journal's block size differs from the file system's; the journal was skipped |
| `EF462_EXT_JOURNAL_SCANNED` | the journal area was walked: blocks, descriptors, commits, revokes, block copies found |
| `EF463_EXT_LIVE_TREE_TRUNCATED` | the live directory tree has more directories than the limit; names under the directories not walked cannot be matched |
| `EF464_EXT_DELETED_FOUND` | deleted files and previous versions were found: how many of each, how many with content still readable |
| `EF465_EXT_BLOCKS_REUSED` | a deleted file's blocks are allocated again, so its old content is gone; the entry is listed without content |
| `EF466_EXT_RECOVER_READ` | reading a recovered file's blocks failed part-way; the bytes read so far were kept |
| `EF467_EXT_TOO_MANY_GROUPS` | the superblock declares more block groups than the limit; the volume is refused for recovery |
| `EF468_EXT_JOURNAL_TRUNCATED` | the journal is longer than the block limit; the part beyond was not read |
| `EF469_EXT_RECOVER_NOT_REGULAR` | the inode of a deleted name is not a regular file in its journal copy (a directory, a device); only regular files are recovered |
| `EF500_XFS_OPEN` | the volume's superblock could not be parsed as XFS; the offset is wrong or the superblock is damaged (XFS keeps a copy in every allocation group) |
| `EF501_XFS_LOOKUP` | a path could not be resolved; a directory block on the way is damaged |
| `EF502_XFS_INODE` | an inode could not be read; the inode chunk is damaged or fails its CRC, the entry is listed without times |
| `EF503_XFS_READ_DIR` | a directory could not be listed; its blocks are damaged |
| `EF504_XFS_READ` | reading a file's content failed part-way; an extent points outside the volume or the image is truncated |
| `EF505_XFS_OPENED` | an XFS volume was opened: UUID, block size, size |
| `EF506_XFS_NAME_UNDECODABLE` | a file name is not UTF-8; it is shown lossily |
| `EF507_XFS_LINK_TARGET` | a symbolic link's target could not be read; the entry is listed as a link without a target |
| `EF508_XFS_LOG_REPLAYED` | the XFS log was not clean and the driver replayed it in memory; the volume was not unmounted cleanly, what you read includes the logged operations |
| `EF550_FOLDER_NOT_FOUND` | the folder given as evidence does not exist or is not a directory |
| `EF551_FOLDER_METADATA` | the metadata of an entry in the folder could not be read; permissions, a dangling link, or a path too long for the operating system |
| `EF552_FOLDER_READ` | a file in the folder could not be opened or read; it is locked by another process or the permissions deny it |
| `EF553_FOLDER_LISTED` | the folder was opened as a file system |
| `EF554_FOLDER_TIMES_MISSING` | the operating system gave no creation or change time for an entry; those columns are empty for it |
| `EF600_FS_NOT_FOUND` | the path does not exist in this file system; check the spelling (NTFS and zip lookups ignore case, ext and XFS do not) and that the volume is the right one |
| `EF601_FS_NOT_A_DIR` | the path exists but is a file, and a directory listing was asked; use metadata() or read() on it |
| `EF602_FS_NOT_A_FILE` | the path exists but is a directory or a link, and its content was asked; list it instead |
| `EF603_FS_READ` | reading the content failed part-way; the file system structures for this file are damaged or the image is truncated, the bytes read so far are kept |
| `EF604_FS_SYMLINK_NOT_FOLLOWED` | the path is a symbolic link or a reparse point; links are listed with their target but never followed, open the target yourself if it is inside the evidence |
| `EF605_WALK_DEPTH_LIMIT` | a directory is deeper than the walk's depth limit; its content was not listed, raise max_depth if it matters |
| `EF606_WALK_FILE_LIMIT` | the walk reached its file limit and stopped; raise max_files or walk a subtree |
| `EF607_WALK_DIR_UNREADABLE` | a directory could not be listed; its index is damaged or the image is truncated there, the walk went on with the rest |
| `EF608_WALK_NAME_UNDECODABLE` | a file name is not valid Unicode; it is shown with replacement characters, the bytes are not recoverable through this API |
| `EF609_FS_FILE_TOO_LARGE` | the file is larger than the limit given to read(); use copy_to() to stream it, or raise the limit |
| `EF610_FS_STREAM_NOT_FOUND` | the file has no alternate data stream of that name; list the entry's streams to see which exist |
| `EF611_WALK_PATTERN_INVALID` | a search pattern is empty or malformed; patterns are globs such as *.evtx, **/config/SYSTEM or Users/*/NTUSER.DAT |
| `EF612_FS_OPENED` | a file system was opened; its kind, label and size |
| `EF613_FS_PATH_ESCAPES` | a path tries to climb above the root with '..'; it was refused |
| `EF614_WALK_STOPPED` | the caller stopped the walk before the end |
| `EF615_FS_DELETED_UNSUPPORTED` | this file system keeps no trace of deleted files that the reader can list (folders, zips, XFS); NTFS and ext volumes do, open the image instead of a copied tree |
| `EF616_FS_DELETED_NOT_FOUND` | no deleted entry has that record or inode number under $DELETED; list $DELETED to see the ones there are |
| `EF617_FS_DELETED_UNRECOVERABLE` | the deleted entry's metadata is listed but its content cannot be read back: a directory, clusters reused or unknown, compressed data, or a bare $MFT without the volume |
| `EF618_FS_DELETED_LISTED` | the deleted entries of a file system were listed: how many, how many recoverable |
| `EF650_EXTRACT_DEST_CREATE` | the destination folder could not be created; check the path, permissions and free space |
| `EF651_EXTRACT_WRITE` | writing the copy failed; the disk is full, the path is too long, or the file is locked |
| `EF652_EXTRACT_READ` | reading the source failed part-way; the copy is incomplete and was removed |
| `EF653_EXTRACT_TIMES` | the original times could not be set on the copy; the content is intact, the file carries the host's times |
| `EF654_EXTRACT_NAME_CHANGED` | the original name has characters or a form the host file system refuses; the copy carries a sanitised name (the original is in the manifest) |
| `EF655_EXTRACT_SKIPPED_LARGE` | a file above the size limit was not copied; raise max_bytes or copy it alone |
| `EF656_EXTRACT_DONE` | an extraction finished: files, bytes, errors |
| `EF657_EXTRACT_STREAM` | an alternate data stream was written as its own file, named `<file>__<stream>` |
| `EF658_EXTRACT_LINK_SKIPPED` | a symbolic link or reparse point was not copied; its target is noted |
| `EF659_EXTRACT_LONG_PATH` | a destination path is longer than 240 characters; the Windows long-path prefix was used |
| `EF660_EXTRACT_EXISTS` | the destination file already exists and overwrite was not asked; it was left as it was |
| `EF700_TRIAGE_DETECTED` | the evidence is a triage package of a known collector; its layout is used to find the operating system roots |
| `EF701_TRIAGE_HOSTNAME` | the host name was taken from the package name (collectors put it there) |
| `EF702_TRIAGE_UNKNOWN` | the evidence is a folder or archive of files whose collector is not recognised; the operating system roots are searched by name |
| `EF703_TRIAGE_WINDOWS_ROOT` | a Windows root (a folder holding Windows/System32/config) was found at this path inside the evidence |
| `EF704_TRIAGE_LINUX_ROOT` | a Linux root (a folder holding etc/ with passwd or hostname) was found at this path inside the evidence |
| `EF705_TRIAGE_NO_ROOT` | no Windows or Linux root was found in the first levels of the evidence; files are read where they are, by name |
| `EF706_TRIAGE_VELOCIRAPTOR_ENCODED` | a Velociraptor folder encodes the drive letter as C%3A; it was decoded |
| `EF707_TRIAGE_LINUX_HOSTNAME` | the host name was read from etc/hostname inside the evidence |
| `EF750_TIME_OUT_OF_RANGE` | a timestamp is before year 1601 or after year 9999 and was clamped; the on-disk value was damaged or never set, read the raw value when it matters |
| `EF751_TIME_UNSET` | a timestamp field is zero (never set); the column is left empty rather than shown as the epoch |
| `EF850_CARVE_EMPTY` | the source has no bytes to scan |
| `EF851_CARVE_NO_KINDS` | no carve kind was selected; pick at least one of hive, evtx, prefetch, lnk, sqlite, pe, pdf, zip, jpeg, png |
| `EF852_CARVE_STARTED` | a carve scan started: source size, kinds, threads |
| `EF853_CARVE_FOUND` | a carve scan finished: items per kind, bytes read, read errors |
| `EF854_CARVE_CANCELLED` | the carve scan was cancelled by the caller; the items found so far are kept |
| `EF855_CARVE_READ_ERROR` | a block of the source could not be read during the scan; the window was skipped and the scan went on |
| `EF856_CARVE_LIMIT` | the scan found more items than the limit and stopped listing new ones |
| `EF857_CARVE_OVERSIZE` | a structure declares a size above the per-item limit; it was cut to the limit and marked incomplete |
| `EF858_CARVE_HIVE_TRUNCATED` | a carved hive's bins end before its declared size (overwritten or fragmented); the verified prefix is what reads back |
| `EF859_CARVE_EVTX_RUN` | a run of consecutive event log chunks was carved as one .evtx with a rebuilt file header |
| `EF860_CARVE_INVALID_ID` | a $CARVED id is not <kind>_<offset in hex>; use the id shown in the listing |
| `EF861_CARVE_NOT_FOUND` | no carved item has that id in this scan's results; run the scan again with the kind included |
| `EF862_CARVE_UNSUPPORTED_SOURCE` | carving needs an image, a volume or a single file; a folder or an archive has no unallocated space to scan |
| `EF863_CARVE_KIND_UNKNOWN` | a carve kind name was not recognised; the known kinds are hive, evtx, prefetch, lnk, sqlite, pe, pdf, zip, jpeg, png |
| `EF864_CARVE_READ` | reading a carved item back failed part-way; the bytes read so far are kept |
