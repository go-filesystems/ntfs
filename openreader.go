// SPDX-License-Identifier: BSD-3-Clause

package filesystem_ntfs

import (
	"errors"
	"fmt"
	"io"

	filesystem "github.com/go-filesystems/interface"
)

// OpenReader opens the NTFS volume that starts at offset zero of r.
//
// It exists so this driver fits the one shape the rest of go-filesystems
// agrees on: github.com/go-filesystems/detect's Opener is
// func(io.ReaderAt, int64) (filesystem.Filesystem, error), and until now this
// driver could only be opened from a PATH. A caller with an image already open
// -- a partition inside a disk image, a section of a larger file, an image in
// memory -- had to write it to a temporary file first, and detect.Register
// could not be given this driver at all.
//
// There is no partition index: r is expected to begin at the filesystem, which
// is what detect has just established by reading the magic there. Open remains
// the way to look through a partition table.
//
// WRITES need an io.WriterAt. A reader that is only a reader gives a
// filesystem that serves every read and refuses every write with
// ErrReadOnlyReader -- rather than one that accepts a write and loses it.
//
// The richer FS interface this package's Open returns is still there: a
// caller that wants Layout, Compact or the fragmentation statistics can assert
// for it. What is returned here is filesystem.Filesystem because that is what
// detect.Opener is, and fitting it is the point.
//
// The reader is NOT closed by Close: the caller opened it and still owns it.
// That is the same division as iso9660, squashfs, hfsplus and ufs, whose
// reader-based constructors have always worked this way.
func OpenReader(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
	if r == nil {
		return nil, errors.New("ntfs: OpenReader needs a reader")
	}
	if size <= 0 {
		return nil, fmt.Errorf("ntfs: an image of %d bytes is not one", size)
	}
	return openAt(readOnlyOrWritable(r))
}

// ErrReadOnlyReader is what a write gets when the filesystem was opened over
// something that can only be read.
var ErrReadOnlyReader = errors.New("ntfs: this filesystem was opened over a reader that cannot be written")

// readOnlyOrWritable adapts whatever the caller passed to what the filesystem
// needs, taking the write side when the reader happens to have one.
func readOnlyOrWritable(r io.ReaderAt) diskRW {
	if w, ok := r.(io.WriterAt); ok {
		return readWriteAt{r, w}
	}
	return readerAt{r}
}

// readerAt is a reader that refuses to be written and does not close what it
// did not open.
type readerAt struct{ r io.ReaderAt }

func (a readerAt) ReadAt(p []byte, off int64) (int, error) { return a.r.ReadAt(p, off) }
func (a readerAt) WriteAt([]byte, int64) (int, error)      { return 0, ErrReadOnlyReader }
func (a readerAt) Close() error                            { return nil }

// readWriteAt is the same, for a reader that can also be written.
type readWriteAt struct {
	r io.ReaderAt
	w io.WriterAt
}

func (a readWriteAt) ReadAt(p []byte, off int64) (int, error)  { return a.r.ReadAt(p, off) }
func (a readWriteAt) WriteAt(p []byte, off int64) (int, error) { return a.w.WriteAt(p, off) }
func (a readWriteAt) Close() error                             { return nil }
