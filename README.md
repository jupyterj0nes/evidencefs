# evidencefs

One reader for forensic evidence, in pure Rust. A disk image (E01, raw, VHD/VHDX, VMDK), a
mounted volume, a Volume Shadow Copy, a triage package (KAPE, Velociraptor) or an archive comes
in; one tree of files with their metadata comes out, read the same way by every tool.

It is the shared evidence layer of [agentc00pr](https://github.com/jupyterj0nes/agentc00pr),
[hivedump](https://github.com/jupyterj0nes/hivedump), [webfoot](https://github.com/jupyterj0nes/webfoot)
and [exfilter](https://github.com/jupyterj0nes/exfilter), and the common home of the image reading
that [masstin](https://github.com/jupyterj0nes/masstin), [faramir](https://github.com/jupyterj0nes/faramir),
[caarea](https://github.com/jupyterj0nes/caarea) and [allymacb](https://github.com/jupyterj0nes/allymacb)
each carry today.

## Status

Skeleton. The API and the first readers are being laid down; nothing here is usable yet.

## Planned

- `Source`: anything addressed by offset (a file, a raw device, an EWF segment set, a VHD/VHDX,
  a VMDK), guarded against stalls the way [blockcarve](https://github.com/jupyterj0nes/blockcarve) does.
- `Volume`: partition tables (MBR, GPT), LVM, Volume Shadow Copies via
  [vshadow](https://github.com/jupyterj0nes/vshadow-rs).
- `FileSystem`: NTFS (with alternate data streams and the `$MFT` resident data), ext4, XFS,
  FAT; a triage package or a plain folder as a file system too.
- `Walk`: one iterator over everything, with the path, the timestamps, the size and a reader
  for each file; a `find` by name, extension, path pattern or signature.
- `Extract`: copy a file or a subtree out, preserving names and timestamps, with a progress
  callback.

## License

AGPL-3.0-only.
