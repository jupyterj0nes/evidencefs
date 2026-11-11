# evidencefs

One reader for forensic evidence, in pure Rust. A disk image (E01, raw, split raw,
VHD/VHDX, VMDK), a mounted volume, a Volume Shadow Copy, a triage package (KAPE,
Velociraptor, CyLR, UAC, Cortex XDR), a zip or tar archive, or a single file comes in; one
list of **mounts** comes out, each a read-only file system walked, searched and extracted
the same way, with the original timestamps and stable diagnostic codes for everything that
was skipped or decided along the way.

It is the shared evidence layer of [agentc00pr](https://github.com/jupyterj0nes/agentc00pr),
[hivedump](https://github.com/jupyterj0nes/hivedump), [webfoot](https://github.com/jupyterj0nes/webfoot)
and [exfilter](https://github.com/jupyterj0nes/exfilter), and the common home of the image
reading that [masstin](https://github.com/jupyterj0nes/masstin), [faramir](https://github.com/jupyterj0nes/faramir),
[caarea](https://github.com/jupyterj0nes/caarea) and [allymacb](https://github.com/jupyterj0nes/allymacb)
each carry today (the VHD, VHDX and VMDK readers and the partition walk are ported from
faramir and masstin).

```rust
use evidencefs::{Evidence, OpenOptions, WalkOptions, WalkStep};

let ev = Evidence::open("disk.E01".as_ref(), &OpenOptions::default())?;
println!("{}", ev.describe());
// disk.E01: image (E01), 59.9 GB (3 segment(s)), host WS01
//   partition 0: NTFS at 0x100000 (99.0 MB, gpt, "System Reserved")
//   partition 1: NTFS at 0x6500000 (59.8 GB, gpt, "Basic data partition")
//   mount partition_1: NTFS "OS" [...] [windows root /]
//   mount partition_1_vss_0: NTFS "OS" [... vss:0:2026-10-29 01:57:43] [windows root /]

for found in ev.find(&["**/config/SYSTEM", "Users/*/NTUSER.DAT", "*.evtx"], &WalkOptions::default())? {
    let mount = &ev.mounts[found.mount];
    let mut out = Vec::new();
    mount.fs.copy_to(&found.entry.path, None, &mut out, None)?;
    println!("{} {} bytes {}", mount.source_path(&found.entry.path), out.len(), found.entry.times.macb());
}
```

## What it reads

| Layer | Formats | Notes |
|---|---|---|
| Images | EWF (E01/Ex01/L01, segments found by name), raw (`.dd/.raw/.img/.bin`), split raw (`.001`...), VHD fixed and dynamic, VHDX fixed and dynamic, VMDK (descriptor, monolithic sparse and flat, split, streamOptimized) | The format is decided by extension, then by signature when the extension lies. Differencing VHD/VHDX and VMDK snapshot deltas are refused with a code that says to merge them. |
| Partitions | MBR with extended partition chains, GPT (primary or backup header, 512 or 4 KB sectors), whole-image volumes, common offsets when the table is gone | Every volume is sniffed by signature: NTFS, BitLocker, ext2/3/4, XFS, btrfs, F2FS, swap, LVM2, LUKS, FAT, exFAT, ReFS, APFS, HFS+. Encrypted and unsupported volumes are listed, never silently dropped. |
| Containers | LVM2 physical volumes (linear logical volumes read in place), Volume Shadow Copies (every store of an NTFS volume, each mounted as the volume looked at snapshot time) | Striped or thin LVs are reported. The VSS reader comes from [vshadow](https://github.com/jupyterj0nes/vshadow-rs). |
| File systems | NTFS (`$UpCase` lookups, `$STANDARD_INFORMATION` times, alternate data streams, reparse points described), ext2/3/4, XFS, FAT12/16/32 (the EFI system partition, USB sticks, SD cards: long names, created/modified/accessed times as the entry keeps them, deleted entries with their long name and their content when the clusters are still free), exFAT (SDXC cards, USB sticks and external disks: names of any length, times to 10 ms in UTC when the entry records its offset, contiguous files and FAT chains, bytes past the valid data length read as zeros, deleted entry sets read back when the allocation bitmap says their clusters are free), a plain folder, a zip read in place | Symbolic links are listed with their target and never followed. The `$`-metafiles are ordinary entries. |
| Archives | zip and tar read in place; tar.gz / tgz, tar.bz2 and tar.xz decompressed once, streaming, into a single temporary `.tar` that is read in place and removed with the `Evidence`. No member is ever written to disk on its own (an archive of attacker tooling does not land on the analyst's disk file by file, where an antivirus would quarantine members in the middle of a run). Long names (GNU, PAX), PAX fractional times, hard links (read as their target), symbolic links (listed, never followed), GNU sparse members (holes expanded) | Archives inside folders and archives are opened as nested mounts, two levels deep by default. 7z and RAR are recognised and refused with a code. |
| Triage | KAPE, Velociraptor (`C%3A` decoded), CyLR, UAC, Cortex XDR, generic Windows or Linux trees | The collector and the host name from the package name, the Windows and Linux roots inside (`C/Windows/System32/config`, `etc/hostname`). |
| Deleted files | NTFS: every `$MFT` record not in use that still has a name (path rebuilt through the parent chain, `$OrphanFiles` when it breaks; times, size, alternate streams; content streamed from the old data runs when they are plain). ext3/ext4: names in journal copies of directory blocks and in directory slack that are gone from the live tree, plus previous versions of live files (replaced by rename or rewritten in place) whose old blocks are still free; deletion time from `dtime`. | Listed under the virtual `/$DELETED/<record or inode>/<original path>`, which `metadata`, `copy_to` and `read` accept like any path; `Entry.deleted`, `Entry.recoverable`, `Entry.deleted_at`. A bare `$MFT` file scans too (`fs::mft::scan`), with resident content recoverable. The scan runs one thread per core and the list is the same every time. |
| Carving | Registry hives, event log chunks (consecutive chunks rebuilt into one `.evtx`), Prefetch (`SCCA` and compressed `MAM`), shell links, SQLite databases, PE executables, PDF, zip (docx, xlsx, jar), JPEG, PNG | Over the whole image or a single file (a memory dump), sector-aligned signatures validated by walking the structure to its real end; one thread per range, results merged by offset so two scans give the same list; `Carved { kind, offset, size, label, complete }`, id `<kind>_<offset hex>`, `carve::read` streams it. Built on [blockcarve](https://github.com/jupyterj0nes/blockcarve). |

## The API in one screen

- `Evidence::open(path, &OpenOptions)` → `Evidence { kind, image, volumes, mounts, triage, single_file }`; `describe()`, `hostname()`, `walk_all()`, `find(&globs)`, `temp_path()`.
- `Mount { label, fs: Box<dyn FileSystem>, source, roots }`; `source_path(path)` gives `partition_0_vss_1/Windows/...`, the prefix the c00pr timelines put in `source_file`.
- `trait FileSystem`: `metadata(path)`, `read_dir(path)` (sorted), `copy_to(path, stream, sink, progress)` (streams any size), `read(path, stream, limit)`, `read_to_string`, `exists`, `kind`, `label`, `size`.
- `Entry { path, name, kind, size, times: Timestamps { created, modified, accessed, changed }, id, streams, link_target, deleted, recoverable, deleted_at }`; `Timestamp` prints as `YYYY-MM-DDTHH:MM:SS.ffffffZ` and converts from FILETIME, Unix, WebKit, Firefox and Cocoa epochs.
- `FileSystem::supports_deleted()` / `deleted(progress)`: the deleted entries, each addressable as `/$DELETED/<id>/<path>`; `Evidence::deleted(mount, progress)`, `Evidence::deleted_all(progress)`; `fs::mft::scan` for a bare `$MFT`, `fs::extjournal::recover` for an ext volume.
- `Evidence::carve(&CarveOptions { kinds, threads, max_size, max_items, step }, progress, cancel)` → `(Vec<Carved>, CarveStats)`; `Evidence::carve_read(&item, sink, progress)`; `carve::parse_kinds("hive,evtx,all")`, `Carved::id()` / `parse_id`, `file_name()`.
- `fs::walk(fs, root, &WalkOptions, |entry| WalkStep::{Continue, SkipDir, Stop})` pre-order, names in order, depth and count limits; `fs::find` with `Glob` (`*.evtx`, `**/config/SYSTEM`, `Users/*/NTUSER.DAT`, case-insensitive).
- `extract::extract_file` / `extract_tree`: copies with the original times, Windows-safe names, long-path prefix, alternate data streams as `<name>__<stream>`, progress, a manifest of renamed entries.
- `source::open_image`, `SharedReader` (one image, many consumers, views per partition), `volume::list_volumes`, `volume::vss::list_snapshots`, `volume::lvm::PhysicalVolume`: the layers underneath, usable alone.

Paths are always `/`-separated with a leading `/`, whatever the source used; NTFS, FAT, exFAT, zip and folder lookups ignore case, ext and XFS do not. FAT keeps local time without a zone: its times are given as if UTC (`EF809`). exFAT entries usually carry their UTC offset and are converted; those that do not are given as if UTC (`EF830`).

## Diagnostics

Every failure, skip and decision carries a stable code `EF###_NAME` with a help text that says what it means and what to do; [docs/codes.md](docs/codes.md) lists all of them by range (images 000-199, archives 200-249, partitions 250-299, LVM 300-349, VSS 350-399, NTFS 400-449 with `$MFT` records and deleted files at 430-449, ext 450-499 with journal recovery at 458-499, XFS 500-549, folders and zips 550-599, walking 600-649, extraction 650-699, triage 700-749, time 750-799, FAT 800-819 and exFAT 820-849, carving 850-899). Codes are recorded in a per-thread sink (`diag::drain()`, `diag::has(code)`), echoed to stderr unless `diag::set_quiet(true)`, and the tools print them with `--codes` / `--explain`.

## Tests

`cargo test --release` runs the unit tests over synthetic images (MBR and GPT tables, EBR chains, VHD/VHDX/VMDK layouts built byte by byte, synthetic `$MFT` records with resident and non-resident data, ext4 directory blocks and journal tags, a 4 MB image with one planted file of every carve kind and three decoys, zips, tars with escaping members) and, when `D:\evidence` is present, the lab data: a VHD with an NTFS volume, planted deleted files and a shadow copy, the `$MFT` files of the RangeForge hosts, an ext4 image, faramir's ext4 fixture with known deleted files and previous versions, a Windows memory dump for carving, a tgz and a zip triage, a KAPE-style folder. Two walks, two deleted listings and two carve scans of the same evidence must give the same result.

## Status

0.1: everything above works and is tested; not yet: APFS/HFS+, btrfs, XFS deleted files, NTFS `$LogFile`/`$UsnJrnl` history, live devices, differencing disks. `#![forbid(unsafe_code)]`.

## License

AGPL-3.0-only.
