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

## Support summary

| Feature | Status | Notes |
|---|---:|---|
| Open / Close | ✅ | Minimal in-image implementation |
| ReadFile / WriteFile | ✅ | Blob storage model inside image |
| MkDir / Delete / Rename | ✅ | Implemented (recursive delete supported) |
| Symlink (create) | ✅ | NTFSIMG1 in-image driver |
| ReadLink (read target) | ✅ | Both drivers: NTFSIMG1 metadata, and real NTFS symlinks/junctions via `$REPARSE_POINT` (`IO_REPARSE_TAG_SYMLINK` / `IO_REPARSE_TAG_MOUNT_POINT`) |
| Free-list reuse | ✅ | In-image free-list and reuse implemented |
| Volume label | ✅ | `Label` / `SetLabel` (filesystem.Labeller) |

Notes on current capabilities:

- Path normalization: paths are normalized and stored with a leading `/`.
- Parent directories: `WriteFile` will create any missing parent directories.
- Directory rename: renaming a directory updates all nested entries.
- Deletion: `DeleteDir` removes a directory and its contents recursively.

## Limitations

- The driver does not implement NTFS metadata (ACLs, alternate data streams,
	journaling, or real on-disk structures).
- Storage compaction / reuse is not implemented; deleted blobs leave gaps in
	the image file.

## Free-list and reuse

- The driver now maintains an in-image free-list of blob extents freed by
	delete operations and reuses those extents for subsequent writes when a
	suitably-sized extent is available. Contiguous free extents are coalesced
	to reduce fragmentation.

## Future improvements

- Implement compaction to defragment storage and reduce image growth.
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
