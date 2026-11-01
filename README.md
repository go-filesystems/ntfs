<p align="center"><img src="https://raw.githubusercontent.com/go-filesystems/brand/main/social/go-filesystems-ntfs.png" alt="go-filesystems/ntfs" width="720"></p>

# ntfs package

[![Go Reference](https://pkg.go.dev/badge/github.com/go-filesystems/ntfs.svg)](https://pkg.go.dev/github.com/go-filesystems/ntfs)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![CI](https://github.com/go-filesystems/ntfs/actions/workflows/ci.yml/badge.svg)](https://github.com/go-filesystems/ntfs/actions/workflows/ci.yml)

This package provides a minimal NTFS driver that implements the
`filesystem.Filesystem` interface.

Implementation details:

- The driver stores a small header region at the start of the image and
	places file blobs after that header. All operations (read/write/mkdir/rename)
	operate inside the image file rather than on the host filesystem.
- This is a lightweight, test-oriented implementation and does not attempt to
	implement the full NTFS on-disk format. Use a real NTFS implementation for
	full compatibility or integration tests.

`Open` sniffs the boot sector: genuine NTFS volumes are handed to a read-only
on-disk reader (`real_ntfs.go` / `real_ntfs_features.go`) that parses real
structures straight off disk; the custom `NTFSIMG1` blob format keeps using the
legacy read/write code path.

## Support summary — NTFSIMG1 (in-image mock, read/write)

| Feature | Status | Notes |
|---|---:|---|
| Open / Close | ✅ | Minimal in-image implementation |
| ReadFile / WriteFile | ✅ | Blob storage model inside image |
| MkDir / Delete / Rename | ✅ | Implemented (recursive delete supported) |
| Symlink (create) | ✅ | NTFSIMG1 in-image driver |
| ReadLink (read target) | ✅ | NTFSIMG1 metadata |
| Free-list reuse | ✅ | In-image free-list and reuse implemented |
| Volume label | ✅ | `Label` / `SetLabel` (filesystem.Labeller) |
| Grow / Shrink / Resize | ✅ | `FS.Grow` / `FS.Shrink` / `FS.Resize` resize the NTFSIMG1 image in place; NOT real on-disk NTFS resize (real reader returns an error) |
| Compaction | ✅ | `FS.Compact` relocates blobs to remove fragmentation and rebuilds the free-list; `FS.FragmentationStats` / `FS.Layout` report usage and layout |

## Support summary — real on-disk NTFS (read-only)

| Feature | Status | Notes |
|---|---:|---|
| Boot sector / $MFT / FILE records | ✅ | USA fixup, attribute walk, fragmented $MFT runlist |
| Resident / non-resident $DATA | ✅ | Data-run (runlist) decoding |
| Directory listing | ✅ | `$INDEX_ROOT` + `$INDEX_ALLOCATION` (INDX) |
| LZNT1 compression | ✅ | Per-compression-unit decode; validated byte-exact vs ntfs-3g |
| Sparse files | ✅ | Sparse runs read back as zeroes |
| Named data streams (ADS) | ✅ | `StreamReader`: `ListStreams` / `ReadStream` |
| Symlinks / junctions | ✅ | `$REPARSE_POINT` (`IO_REPARSE_TAG_SYMLINK` / `IO_REPARSE_TAG_MOUNT_POINT`) and ntfs-3g `IntxLNK`; `ReadLink` |
| `$ATTRIBUTE_LIST` (spanning records) | ✅ | Extension records stitched; split runlists merged by VCN |
| Volume label | ✅ | `Label` reads `$VOLUME_NAME` |
| Write path | ⚠️ No | Read-only reader; mutating methods return an error |
| EFS-encrypted data | ⚠️ No | Not decodable without the user's keys (clear error) |

Named streams are read through the package's `StreamReader` capability:

```go
if sr, ok := fs.(ntfs.StreamReader); ok {
	names, _ := sr.ListStreams("/notes.txt")     // e.g. ["", "author"]
	author, _ := sr.ReadStream("/notes.txt", "author")
	_ = author
}
```

Notes on current capabilities:

- Path normalization: paths are normalized and stored with a leading `/`.
- Parent directories: `WriteFile` will create any missing parent directories.
- Directory rename: renaming a directory updates all nested entries.
- Deletion: `DeleteDir` removes a directory and its contents recursively.

## Untrusted input

An image is attacker-controlled data. Every allocation a value in the image can
size is bounded before it happens, and a hostile image gets an error, not an
out-of-memory kill:

- a data run must lie inside the image (the last byte of every allocated span
  is read before the buffer is made), and metadata attributes
  (`$INDEX_ALLOCATION`, `$ATTRIBUTE_LIST`, `$REPARSE_POINT`) may not be sparse;
- a compressed stream is sized by its runlist, not by the `realSize` claim, and
  a compression unit is at most 64 KiB (Linux ntfs3: 16 clusters of at most
  4096 bytes);
- index entries must be at least 0x10 bytes with the key inside the entry
  (Linux ntfs3 `hdr_find_e`), so overlapping keys cannot multiply the output;
- `ReadLink` does not read a file larger than a path to look for the
  `IntxLNK` marker;
- sparse `$DATA` legitimately reads back bigger than the image, so it has a
  ceiling: `DefaultMaxDataSize` (1 GiB), lowered with `SetMaxDataSize` on the
  `DataLimiter` that `Open` returns. A read over it fails with an error that
  wraps `ntfs.ErrTooLarge` before anything is allocated.

```go
if l, ok := fsys.(ntfs.DataLimiter); ok {
    l.SetMaxDataSize(64 << 20)
}
```

`FuzzRealNTFS` and `FuzzOpen` drive the read surface; the regression tests are
in `bombs_test.go`.

## Limitations

- The NTFSIMG1 in-image driver does not implement NTFS metadata (ACLs,
	journaling, or real on-disk structures); the real on-disk reader above is
	read-only and does not decode EFS-encrypted data.
- `Grow`/`Shrink`/`Resize` and `Compact` operate on the NTFSIMG1 image format
	only; the real on-disk NTFS reader is read-only and returns an error for
	all of them (resizing a real NTFS volume would require manipulating the
	MFT, `$Bitmap`, and runlists — a separate, much larger project).

## Free-list, reuse, and compaction

- The driver maintains an in-image free-list of blob extents freed by delete
	operations and reuses those extents for subsequent writes when a
	suitably-sized extent is available. Contiguous free extents are coalesced
	to reduce fragmentation.
- `FS.Compact()` relocates blobs to remove fragmentation and rebuilds the
	free-list as a single tail extent; `FS.FragmentationStats()` reports file
	count, bytes used, free-extent count, total free bytes, and largest free
	extent; `FS.Layout()` returns the current per-file blob layout.

## Future improvements

- Add more NTFS metadata (timestamps, inodes, ACLs) for better compatibility.

## Implements

This package implements the `filesystem.Filesystem` interface from the
`github.com/go-filesystems/interface` module. Tools that accept the
`filesystem.Filesystem` abstraction can operate on NTFS images created or
opened by this package.

Example:

```go
import (
	filesystem "github.com/go-filesystems/interface"
	fsnt "github.com/go-filesystems/ntfs"
)

f, _ := fsnt.Open("ntfs.img", -1)
defer f.Close()
var fs filesystem.Filesystem = f
_, _ = fs.Stat("/")
```
