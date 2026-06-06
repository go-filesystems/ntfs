package filesystem_ntfs

import (
	"errors"
	"fmt"
	"os"
)

// Resize APIs target the NTFSIMG1 image format implemented by this
// driver — NOT the real NTFS on-disk format. Real-NTFS resize would
// have to manipulate the MFT, $Bitmap, $LogFile, runlists and partition
// metadata, which is a separate, much larger project. The methods here
// only resize the simple "16 KiB header + content blob" layout that
// this package actually implements.
//
// Grow extends the underlying image file and exposes the new tail as
// free space in the allocator. Shrink truncates the image after
// verifying that no live file blob extends past the new size. Resize
// dispatches to Grow or Shrink depending on the current image size.

// ErrShrinkTooSmall is returned by Shrink and Resize when the requested
// new size is smaller than the highest byte currently occupied by a
// live file blob. Callers must Compact or delete files before
// retrying.
var ErrShrinkTooSmall = errors.New("ntfs: shrink target smaller than highest used offset")

// imageSize reports the current size of the backing file. It works
// for the *os.File path used by Open as well as the in-test fault
// wrapper because both expose the underlying *os.File via a Stat-like
// path; we only need it on the *os.File path so we type-assert.
func (fs *ntfsFS) imageSize() (int64, error) {
	if f, ok := fs.f.(*os.File); ok {
		st, err := f.Stat()
		if err != nil {
			return 0, err
		}
		return st.Size(), nil
	}
	return 0, fmt.Errorf("ntfs: backing store does not support sizing")
}

// truncateImage truncates the backing file to newSize. Like
// imageSize, this only works on the *os.File backed driver.
func (fs *ntfsFS) truncateImage(newSize int64) error {
	if f, ok := fs.f.(*os.File); ok {
		return f.Truncate(newSize)
	}
	return fmt.Errorf("ntfs: backing store does not support truncate")
}

// highestUsedOffset returns the largest (Offset + Size) across all
// non-directory entries in the index. Directories have Size 0 and do
// not occupy content bytes. The returned value is measured from the
// start of the content region (i.e. it is content-relative, NOT
// file-absolute).
func (fs *ntfsFS) highestUsedOffset() uint64 {
	var max uint64
	for _, e := range fs.index {
		if e.IsDir {
			continue
		}
		if end := e.Offset + e.Size; end > max {
			max = end
		}
	}
	return max
}

// Grow extends the image to newSizeBytes (which must be strictly
// larger than the current image size) and registers the new tail
// bytes as a single free extent. Subsequent allocations can reuse
// that space via the existing best-fit allocator.
func (fs *ntfsFS) Grow(newSizeBytes int64) error {
	if newSizeBytes <= 0 {
		return fmt.Errorf("ntfs: Grow: newSizeBytes must be positive (got %d)", newSizeBytes)
	}
	cur, err := fs.imageSize()
	if err != nil {
		return fmt.Errorf("ntfs: Grow: %w", err)
	}
	if newSizeBytes <= cur {
		return fmt.Errorf("ntfs: Grow: newSizeBytes %d <= current size %d", newSizeBytes, cur)
	}
	// Extend the backing file. The new region is zero-filled by the
	// OS, which matches what the allocator expects for unused
	// content bytes.
	if err := fs.truncateImage(newSizeBytes); err != nil {
		return fmt.Errorf("ntfs: Grow: truncate: %w", err)
	}
	// The content region grew by (newSize - cur) bytes. The header
	// is fixed-size and lives at [0, headerSize), so the content
	// region capacity is (imageSize - headerSize). Convert the old
	// and new caps into content-relative offsets and add a free
	// extent covering [oldCap, newCap).
	if cur < headerSize {
		// Pathological tiny pre-existing image: just make sure we
		// start the content area at 0 after grow. mergeFreeList
		// below will dedupe with anything else already in flight.
		cur = headerSize
	}
	oldCap := uint64(cur - headerSize)
	newCap := uint64(newSizeBytes - headerSize)
	if newCap > oldCap {
		fs.freeList = append(fs.freeList, fileEntry{Offset: oldCap, Size: newCap - oldCap})
		fs.mergeFreeList()
	}
	return fs.saveIndex()
}

// Shrink truncates the image down to newSizeBytes. Returns
// ErrShrinkTooSmall (wrapped) if any live file blob extends past the
// new content capacity. Free-list extents that overlap the dropped
// region are trimmed; extents fully past the new tail are discarded.
func (fs *ntfsFS) Shrink(newSizeBytes int64) error {
	if newSizeBytes <= 0 {
		return fmt.Errorf("ntfs: Shrink: newSizeBytes must be positive (got %d)", newSizeBytes)
	}
	if newSizeBytes < int64(headerSize) {
		return fmt.Errorf("ntfs: Shrink: newSizeBytes %d smaller than header %d", newSizeBytes, headerSize)
	}
	cur, err := fs.imageSize()
	if err != nil {
		return fmt.Errorf("ntfs: Shrink: %w", err)
	}
	if newSizeBytes >= cur {
		return fmt.Errorf("ntfs: Shrink: newSizeBytes %d >= current size %d", newSizeBytes, cur)
	}
	newCap := uint64(newSizeBytes - headerSize)
	used := fs.highestUsedOffset()
	if used > newCap {
		return fmt.Errorf("%w: highest used offset %d > new capacity %d", ErrShrinkTooSmall, used, newCap)
	}
	// Trim the free-list to the new capacity. Any extent fully past
	// newCap is dropped; an extent that straddles newCap is clipped.
	trimmed := fs.freeList[:0]
	for _, fe := range fs.freeList {
		if fe.Offset >= newCap {
			continue
		}
		end := fe.Offset + fe.Size
		if end > newCap {
			fe.Size = newCap - fe.Offset
		}
		if fe.Size > 0 {
			trimmed = append(trimmed, fe)
		}
	}
	fs.freeList = trimmed
	// Persist the new (possibly trimmed) free-list BEFORE truncating
	// so the on-disk header never refers to bytes past the truncate
	// point.
	if err := fs.saveIndex(); err != nil {
		return fmt.Errorf("ntfs: Shrink: save index: %w", err)
	}
	if err := fs.truncateImage(newSizeBytes); err != nil {
		return fmt.Errorf("ntfs: Shrink: truncate: %w", err)
	}
	return nil
}

// Resize dispatches to Grow or Shrink based on the comparison of
// newSizeBytes against the current image size. A no-op (equal sizes)
// returns nil.
func (fs *ntfsFS) Resize(newSizeBytes int64) error {
	if newSizeBytes <= 0 {
		return fmt.Errorf("ntfs: Resize: newSizeBytes must be positive (got %d)", newSizeBytes)
	}
	cur, err := fs.imageSize()
	if err != nil {
		return fmt.Errorf("ntfs: Resize: %w", err)
	}
	switch {
	case newSizeBytes == cur:
		return nil
	case newSizeBytes > cur:
		return fs.Grow(newSizeBytes)
	default:
		return fs.Shrink(newSizeBytes)
	}
}

// GrowTo satisfies the filesystem.Grower optional interface by
// delegating to Grow. Drivers that want a generic resize entrypoint
// can type-assert through Grower without depending on this concrete
// package.
func (fs *ntfsFS) GrowTo(newSizeBytes int64) error { return fs.Grow(newSizeBytes) }
