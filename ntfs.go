package filesystem_ntfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

const (
	headerMagic = "NTFSIMG1"
	headerSize  = 16 * 1024 // fixed header region inside the image
	metaMagic   = "NTFSMETA1"
	labelMagic  = "NTFSLABL" // optional volume-label block in the header
)

type fileEntry struct {
	Offset uint64
	Size   uint64
	IsDir  bool
}

// metaEntry stores extra NTFS-like metadata for a path.
type metaEntry struct {
	Inode      uint64
	Mode       uint32
	UID        uint32
	GID        uint32
	Atime      int64
	Mtime      int64
	Ctime      int64
	IsSymlink  bool
	LinkTarget string
	ACL        []byte
}

// FS implements a tiny in-image NTFS-like driver using a header and blob
// storage inside the image file. It is intentionally minimal and intended for
// testing; it does not implement the real NTFS on-disk structures.
type diskRW interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
}

type ntfsFS struct {
	f          diskRW
	partOffset int64
	index      map[string]fileEntry
	freeList   []fileEntry
	meta       map[string]metaEntry
	nextInode  uint64
	label      string
}

var (
	_ filesystem.Filesystem = (*ntfsFS)(nil)
	_ filesystem.Symlinker  = (*ntfsFS)(nil)
	_ filesystem.Labeller   = (*ntfsFS)(nil)
)

// FS is the public interface returned by Open. It extends
// filesystem.Filesystem with NTFS-specific operations
// (fragmentation analysis, compaction and NTFSIMG1 image resize).
// Callers that only need the generic interface can use it directly;
// callers that want the extras type-assert (or accept *FS via Open's
// return type).
//
// NOTE: Grow / Shrink / Resize operate on the NTFSIMG1 image format
// this driver implements, NOT on real NTFS. Resizing a real NTFS
// volume would require manipulating the MFT, $Bitmap and runlists and
// is a separate, much larger project.
type FS interface {
	filesystem.Filesystem
	FragmentationStats() (files int, used uint64, freeExtents int, totalFree uint64, largestFree uint64)
	Layout() []FileLayout
	Compact() error
	Symlink(target, linkPath string) error
	Label() string
	SetLabel(label string) error
	Grow(newSizeBytes int64) error
	Shrink(newSizeBytes int64) error
	Resize(newSizeBytes int64) error
}

var _ FS = (*ntfsFS)(nil)

// Open opens the image file and loads the in-image index. The driver stores a
// fixed-size header at the start of the partition and places file blobs after
// that header. partIndex is currently ignored (assumed single-image usage).
func Open(imagePath string, partIndex int) (FS, error) {
	f0, err := os.OpenFile(imagePath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("ntfs: open %s: %w", imagePath, err)
	}
	// underlying *os.File implements ReaderAt/WriterAt/Closer
	f := diskRW(f0)
	// Route genuine NTFS volumes (OEM id "NTFS    " + 0xAA55 boot
	// signature) to the read-only real-NTFS reader; the legacy NTFSIMG1
	// mock format keeps the original code path below.
	if looksLikeRealNTFS(f, 0) {
		rfs, err := openRealNTFS(f, 0)
		if err != nil {
			f.Close()
			return nil, err
		}
		return rfs, nil
	}
	fs := &ntfsFS{f: f, partOffset: 0, index: map[string]fileEntry{}}
	if err := fs.loadIndex(); err != nil {
		f.Close()
		return nil, err
	}
	return fs, nil
}

func (fs *ntfsFS) Close() error { return fs.f.Close() }

func (fs *ntfsFS) contentStart() int64 { return fs.partOffset + headerSize }

func (fs *ntfsFS) loadIndex() error {
	buf := make([]byte, headerSize)
	if _, err := fs.f.ReadAt(buf, fs.partOffset); err != nil && err != io.EOF {
		return err
	}
	if !bytes.HasPrefix(buf, []byte(headerMagic)) {
		// initialize empty header
		fs.index = map[string]fileEntry{}
		// ensure root exists
		fs.index["/"] = fileEntry{Offset: 0, Size: 0, IsDir: true}
		fs.meta = map[string]metaEntry{}
		return fs.saveIndex()
	}
	r := bytes.NewReader(buf[len(headerMagic):])
	var cnt uint32
	if err := binary.Read(r, binary.LittleEndian, &cnt); err != nil {
		return err
	}
	idx := make(map[string]fileEntry, cnt)
	for i := 0; i < int(cnt); i++ {
		var nl uint16
		if err := binary.Read(r, binary.LittleEndian, &nl); err != nil {
			return err
		}
		name := make([]byte, nl)
		if _, err := io.ReadFull(r, name); err != nil {
			return err
		}
		var d uint8
		if err := binary.Read(r, binary.LittleEndian, &d); err != nil {
			return err
		}
		var off uint64
		var sz uint64
		if err := binary.Read(r, binary.LittleEndian, &off); err != nil {
			return err
		}
		if err := binary.Read(r, binary.LittleEndian, &sz); err != nil {
			return err
		}
		idx[string(name)] = fileEntry{Offset: off, Size: sz, IsDir: d == 1}
	}
	// normalize keys and ensure root exists
	norm := make(map[string]fileEntry, len(idx))
	for k, v := range idx {
		nk := normalizePath(k)
		norm[nk] = v
	}
	if _, ok := norm["/"]; !ok {
		norm["/"] = fileEntry{Offset: 0, Size: 0, IsDir: true}
	}
	fs.index = norm
	// attempt to read free-list (backwards-compatible: older images may not have it)
	var freeCount uint32
	if err := binary.Read(r, binary.LittleEndian, &freeCount); err == nil {
		fl := make([]fileEntry, 0, freeCount)
		for i := 0; i < int(freeCount); i++ {
			var off uint64
			var sz uint64
			if err := binary.Read(r, binary.LittleEndian, &off); err != nil {
				break
			}
			if err := binary.Read(r, binary.LittleEndian, &sz); err != nil {
				break
			}
			fl = append(fl, fileEntry{Offset: off, Size: sz})
		}
		fs.freeList = fl
	} else {
		fs.freeList = nil
	}

	// optional metadata block appended somewhere in the header region
	fs.meta = map[string]metaEntry{}
	if mi := bytes.Index(buf, []byte(metaMagic)); mi != -1 {
		mr := bytes.NewReader(buf[mi+len(metaMagic):])
		var metaCount uint32
		if err := binary.Read(mr, binary.LittleEndian, &metaCount); err == nil {
			for i := 0; i < int(metaCount); i++ {
				var nl uint16
				if err := binary.Read(mr, binary.LittleEndian, &nl); err != nil {
					break
				}
				name := make([]byte, nl)
				if _, err := io.ReadFull(mr, name); err != nil {
					break
				}
				var me metaEntry
				if err := binary.Read(mr, binary.LittleEndian, &me.Inode); err != nil {
					break
				}
				if err := binary.Read(mr, binary.LittleEndian, &me.Mode); err != nil {
					break
				}
				if err := binary.Read(mr, binary.LittleEndian, &me.UID); err != nil {
					break
				}
				if err := binary.Read(mr, binary.LittleEndian, &me.GID); err != nil {
					break
				}
				if err := binary.Read(mr, binary.LittleEndian, &me.Atime); err != nil {
					break
				}
				if err := binary.Read(mr, binary.LittleEndian, &me.Mtime); err != nil {
					break
				}
				if err := binary.Read(mr, binary.LittleEndian, &me.Ctime); err != nil {
					break
				}
				var sy uint8
				if err := binary.Read(mr, binary.LittleEndian, &sy); err != nil {
					break
				}
				me.IsSymlink = sy == 1
				var linkLen uint16
				if err := binary.Read(mr, binary.LittleEndian, &linkLen); err != nil {
					break
				}
				if linkLen > 0 {
					lnk := make([]byte, linkLen)
					if _, err := io.ReadFull(mr, lnk); err != nil {
						break
					}
					me.LinkTarget = string(lnk)
				}
				var aclLen uint32
				if err := binary.Read(mr, binary.LittleEndian, &aclLen); err != nil {
					break
				}
				if aclLen > 0 {
					acl := make([]byte, aclLen)
					if _, err := io.ReadFull(mr, acl); err != nil {
						break
					}
					me.ACL = acl
				}
				fs.meta[string(name)] = me
			}
		}
	}

	// ensure every index entry has metadata
	for k := range fs.index {
		if _, ok := fs.meta[k]; !ok {
			fs.ensureMetaForPath(k)
		}
	}

	// optional volume-label block, anywhere in the header region. Layout:
	// labelMagic + uint16 length + label bytes.
	if li := bytes.Index(buf, []byte(labelMagic)); li != -1 {
		lr := bytes.NewReader(buf[li+len(labelMagic):])
		var ll uint16
		if err := binary.Read(lr, binary.LittleEndian, &ll); err == nil && ll > 0 {
			lb := make([]byte, ll)
			if _, err := io.ReadFull(lr, lb); err == nil {
				fs.label = string(lb)
			}
		}
	}
	return nil
}

func (fs *ntfsFS) saveIndex() error {
	var buf bytes.Buffer
	buf.Write([]byte(headerMagic))
	// ensure root exists before saving
	if _, ok := fs.index["/"]; !ok {
		fs.index["/"] = fileEntry{Offset: 0, Size: 0, IsDir: true}
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint32(len(fs.index))); err != nil {
		return err
	}
	// sorted keys for deterministic layout
	keys := make([]string, 0, len(fs.index))
	for k := range fs.index {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(k) > 0xFFFF {
			return fmt.Errorf("ntfs: filename too long")
		}
		if err := binary.Write(&buf, binary.LittleEndian, uint16(len(k))); err != nil {
			return err
		}
		buf.WriteString(k)
		var d uint8 = 0
		if fs.index[k].IsDir {
			d = 1
		}
		if err := binary.Write(&buf, binary.LittleEndian, d); err != nil {
			return err
		}
		if err := binary.Write(&buf, binary.LittleEndian, fs.index[k].Offset); err != nil {
			return err
		}
		if err := binary.Write(&buf, binary.LittleEndian, fs.index[k].Size); err != nil {
			return err
		}
	}
	// write free-list for reuse of freed blobs
	if err := binary.Write(&buf, binary.LittleEndian, uint32(len(fs.freeList))); err != nil {
		return err
	}
	for _, fe := range fs.freeList {
		if err := binary.Write(&buf, binary.LittleEndian, fe.Offset); err != nil {
			return err
		}
		if err := binary.Write(&buf, binary.LittleEndian, fe.Size); err != nil {
			return err
		}
	}
	// ensure meta map exists and create defaults for entries
	if fs.meta == nil {
		fs.meta = map[string]metaEntry{}
	}
	for k, v := range fs.index {
		if _, ok := fs.meta[k]; !ok {
			fs.ensureMetaForPath(k)
		}
		// keep the mode/size/inode up to date for files: ensure the
		// regular-file type bits (S_IFREG = 0o100000) are set while
		// preserving any custom permission bits the caller installed.
		me := fs.meta[k]
		if !v.IsDir {
			me.Mode = (me.Mode &^ 0o170000) | 0o100000
		}
		fs.meta[k] = me
	}

	// write metadata block (optional) at the end of header region
	var metaBuf bytes.Buffer
	metaBuf.Write([]byte(metaMagic))
	if err := binary.Write(&metaBuf, binary.LittleEndian, uint32(len(fs.meta))); err != nil {
		return err
	}
	// deterministic order
	metaKeys := make([]string, 0, len(fs.meta))
	for k := range fs.meta {
		metaKeys = append(metaKeys, k)
	}
	sort.Strings(metaKeys)
	for _, k := range metaKeys {
		me := fs.meta[k]
		if len(k) > 0xFFFF {
			return fmt.Errorf("ntfs: metadata name too long")
		}
		if err := binary.Write(&metaBuf, binary.LittleEndian, uint16(len(k))); err != nil {
			return err
		}
		metaBuf.WriteString(k)
		if err := binary.Write(&metaBuf, binary.LittleEndian, me.Inode); err != nil {
			return err
		}
		if err := binary.Write(&metaBuf, binary.LittleEndian, me.Mode); err != nil {
			return err
		}
		if err := binary.Write(&metaBuf, binary.LittleEndian, me.UID); err != nil {
			return err
		}
		if err := binary.Write(&metaBuf, binary.LittleEndian, me.GID); err != nil {
			return err
		}
		if err := binary.Write(&metaBuf, binary.LittleEndian, me.Atime); err != nil {
			return err
		}
		if err := binary.Write(&metaBuf, binary.LittleEndian, me.Mtime); err != nil {
			return err
		}
		if err := binary.Write(&metaBuf, binary.LittleEndian, me.Ctime); err != nil {
			return err
		}
		var sy uint8 = 0
		if me.IsSymlink {
			sy = 1
		}
		if err := binary.Write(&metaBuf, binary.LittleEndian, sy); err != nil {
			return err
		}
		if len(me.LinkTarget) > 0xFFFF {
			return fmt.Errorf("ntfs: link target too long")
		}
		if err := binary.Write(&metaBuf, binary.LittleEndian, uint16(len(me.LinkTarget))); err != nil {
			return err
		}
		if len(me.LinkTarget) > 0 {
			metaBuf.WriteString(me.LinkTarget)
		}
		if err := binary.Write(&metaBuf, binary.LittleEndian, uint32(len(me.ACL))); err != nil {
			return err
		}
		if len(me.ACL) > 0 {
			metaBuf.Write(me.ACL)
		}
	}

	// optional label block (omitted when empty)
	var labelBuf bytes.Buffer
	if fs.label != "" {
		labelBuf.Write([]byte(labelMagic))
		if err := binary.Write(&labelBuf, binary.LittleEndian, uint16(len(fs.label))); err != nil {
			return err
		}
		labelBuf.WriteString(fs.label)
	}

	// final header must fit in headerSize
	totalLen := buf.Len() + metaBuf.Len() + labelBuf.Len()
	if totalLen > headerSize {
		return fmt.Errorf("ntfs: header overflow with metadata+label: %d > %d", totalLen, headerSize)
	}
	if buf.Len() > headerSize {
		return fmt.Errorf("ntfs: header overflow: %d > %d", buf.Len(), headerSize)
	}
	// write header region (pad to headerSize)
	out := make([]byte, headerSize)
	copy(out, buf.Bytes())
	metaStart := len(buf.Bytes())
	copy(out[metaStart:], metaBuf.Bytes())
	labelStart := metaStart + len(metaBuf.Bytes())
	copy(out[labelStart:], labelBuf.Bytes())
	if _, err := fs.f.WriteAt(out, fs.partOffset); err != nil {
		return err
	}
	return nil
}

func (fs *ntfsFS) ListDir(p string) ([]filesystem.DirEntry, error) {
	// normalize
	p = normalizePath(p)
	prefix := ""
	if p == "/" {
		prefix = "/"
	} else {
		prefix = p + "/"
	}
	entriesMap := map[string]uint8{}
	for name := range fs.index {
		if name == p {
			// the exact directory exists
			continue
		}
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		rest := strings.TrimPrefix(name, prefix)
		parts := strings.SplitN(rest, "/", 2)
		if len(parts[0]) == 0 {
			continue
		}
		// mark as file(8) or dir(2)
		if len(parts) == 1 {
			entriesMap[parts[0]] = 8
		} else {
			entriesMap[parts[0]] = 2
		}
	}
	out := make([]filesystem.DirEntry, 0, len(entriesMap))
	for n, ft := range entriesMap {
		full := prefix
		if full == "/" {
			full = "/" + n
		} else {
			full = full + n
		}
		inode := uint64(0)
		if me, ok := fs.meta[full]; ok {
			inode = me.Inode
		}
		out = append(out, filesystem.NewDirEntry(inode, n, ft))
	}
	return out, nil
}

// ensureMetaForPath creates default metadata for path when missing.
func (fs *ntfsFS) ensureMetaForPath(p string) {
	if fs.meta == nil {
		fs.meta = map[string]metaEntry{}
	}
	if _, ok := fs.meta[p]; ok {
		return
	}
	me := metaEntry{}
	me.Inode = fs.getNextInode()
	if e, ok := fs.index[p]; ok && e.IsDir {
		me.Mode = 0o040755
	} else {
		me.Mode = 0o100644
	}
	now := time.Now().Unix()
	me.Atime = now
	me.Mtime = now
	me.Ctime = now
	fs.meta[p] = me
}

// getNextInode returns a monotonically-increasing inode number.
func (fs *ntfsFS) getNextInode() uint64 {
	if fs.nextInode == 0 {
		var max uint64 = 1
		for _, m := range fs.meta {
			if m.Inode > max {
				max = m.Inode
			}
		}
		fs.nextInode = max + 1
	}
	v := fs.nextInode
	fs.nextInode++
	return v
}

// Compact performs in-image compaction: it relocates blobs to remove
// fragmentation and rebuilds the free-list. It reads each file into memory
// then rewrites it sequentially. Not suitable for huge files but adequate for
// test images.
func (fs *ntfsFS) Compact() error {
	// collect files (skip directories)
	keys := make([]string, 0)
	for k, v := range fs.index {
		if !v.IsDir {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var nextOff uint64 = 0
	for _, k := range keys {
		e := fs.index[k]
		if e.Offset == nextOff {
			nextOff = e.Offset + e.Size
			continue
		}
		if e.Size > 0 {
			// read into memory then write to new location
			buf := make([]byte, e.Size)
			if _, err := fs.f.ReadAt(buf, fs.contentStart()+int64(e.Offset)); err != nil && err != io.EOF {
				return err
			}
			if _, err := fs.f.WriteAt(buf, fs.contentStart()+int64(nextOff)); err != nil {
				return err
			}
		}
		e.Offset = nextOff
		fs.index[k] = e
		nextOff += e.Size
	}
	// rebuild free list as single tail extent if any
	var maxEnd uint64
	for _, v := range fs.index {
		if v.Offset+v.Size > maxEnd {
			maxEnd = v.Offset + v.Size
		}
	}
	fs.freeList = nil
	if maxEnd > nextOff {
		fs.freeList = append(fs.freeList, fileEntry{Offset: nextOff, Size: maxEnd - nextOff})
	}
	return fs.saveIndex()
}

// FragmentationStats returns basic fragmentation and usage metrics for the
// filesystem: number of files, total used bytes, number of free extents,
// total free bytes and largest free extent.
func (fs *ntfsFS) FragmentationStats() (files int, used uint64, freeExtents int, totalFree uint64, largestFree uint64) {
	for _, v := range fs.index {
		if v.IsDir {
			continue
		}
		files++
		used += v.Size
	}
	freeExtents = len(fs.freeList)
	for _, fe := range fs.freeList {
		totalFree += fe.Size
		if fe.Size > largestFree {
			largestFree = fe.Size
		}
	}
	return
}

// FileLayout describes a stored file blob location inside the image.
type FileLayout struct {
	Path   string
	Offset uint64
	Size   uint64
}

// Layout returns a sorted list of file blob locations (by offset).
func (fs *ntfsFS) Layout() []FileLayout {
	out := make([]FileLayout, 0, len(fs.index))
	for p, e := range fs.index {
		if e.IsDir {
			continue
		}
		out = append(out, FileLayout{Path: p, Offset: e.Offset, Size: e.Size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}

// Format creates a fresh NTFS-like image at path with the given size.
type FormatConfig struct{ Label string }

func Format(path string, sizeBytes int64, cfg FormatConfig) (filesystem.Filesystem, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(sizeBytes); err != nil {
		f.Close()
		return nil, err
	}
	f.Close()
	fs, err := Open(path, 0)
	if err != nil {
		return nil, err
	}
	if cfg.Label != "" {
		// Persist the label declared in FormatConfig — Open just
		// initialized an empty header.
		l, ok := fs.(filesystem.Labeller)
		if !ok {
			fs.Close()
			return nil, fmt.Errorf("ntfs: driver does not satisfy filesystem.Labeller")
		}
		if err := l.SetLabel(cfg.Label); err != nil {
			fs.Close()
			return nil, fmt.Errorf("ntfs: seed label: %w", err)
		}
	}
	return fs, nil
}

// Symlink creates a symbolic link at linkPath pointing to target.
func (fs *ntfsFS) Symlink(target, linkPath string) error {
	p := normalizePath(linkPath)
	if err := fs.ensureParentDirs(p); err != nil {
		return err
	}
	fs.index[p] = fileEntry{Offset: 0, Size: 0, IsDir: false}
	fs.ensureMetaForPath(p)
	me := fs.meta[p]
	me.IsSymlink = true
	me.LinkTarget = target
	me.Mtime = time.Now().Unix()
	fs.meta[p] = me
	return fs.saveIndex()
}

// GetMetadata returns the NTFS-specific metadata for path.
func (fs *ntfsFS) GetMetadata(p string) (metaEntry, error) {
	p = normalizePath(p)
	if me, ok := fs.meta[p]; ok {
		return me, nil
	}
	return metaEntry{}, fmt.Errorf("ntfs: %q not found", p)
}

func (fs *ntfsFS) ReadFile(p string) ([]byte, error) {
	p = normalizePath(p)
	if e, ok := fs.index[p]; ok && !e.IsDir {
		b := make([]byte, e.Size)
		if _, err := fs.f.ReadAt(b, fs.contentStart()+int64(e.Offset)); err != nil && err != io.EOF {
			return nil, err
		}
		return b, nil
	}
	return nil, fmt.Errorf("ntfs: %q not found", p)
}

func (fs *ntfsFS) Stat(p string) (filesystem.Stat, error) {
	p = normalizePath(p)
	if e, ok := fs.index[p]; ok {
		// ensure metadata exists
		fs.ensureMetaForPath(p)
		me := fs.meta[p]
		if e.IsDir {
			mode := uint16(0o040755)
			if me.Mode != 0 {
				mode = uint16(me.Mode)
			}
			return filesystem.NewStat(mode, 0, me.Inode), nil
		}
		mode := uint16(0o100644)
		if me.Mode != 0 {
			mode = uint16(me.Mode)
		}
		return filesystem.NewStat(mode, e.Size, me.Inode), nil
	}
	return nil, fmt.Errorf("ntfs: %q not found", p)
}

func (fs *ntfsFS) WriteFile(p string, data []byte, perm os.FileMode) error {
	p = normalizePath(p)
	// ensure parent directories exist
	if err := fs.ensureParentDirs(p); err != nil {
		return err
	}
	// if file exists, attempt in-place overwrite when possible
	if old, ok := fs.index[p]; ok {
		if old.IsDir {
			return fmt.Errorf("ntfs: %q is a directory", p)
		}
		if uint64(len(data)) <= old.Size {
			if len(data) > 0 {
				if _, err := fs.f.WriteAt(data, fs.contentStart()+int64(old.Offset)); err != nil {
					return err
				}
			}
			old.Size = uint64(len(data))
			fs.index[p] = old
			return fs.saveIndex()
		}
	}
	// try to allocate from free-list first
	need := uint64(len(data))
	var off uint64
	var allocated bool
	if need > 0 && len(fs.freeList) > 0 {
		// best-fit: find smallest free extent >= need
		bestIdx := -1
		for i, fe := range fs.freeList {
			if fe.Size >= need {
				if bestIdx == -1 || fs.freeList[i].Size < fs.freeList[bestIdx].Size {
					bestIdx = i
				}
			}
		}
		if bestIdx != -1 {
			fe := fs.freeList[bestIdx]
			off = fe.Offset
			if fe.Size == need {
				// exact fit, remove entry
				fs.freeList = append(fs.freeList[:bestIdx], fs.freeList[bestIdx+1:]...)
			} else {
				// allocate from start of free extent
				fs.freeList[bestIdx].Offset = fe.Offset + need
				fs.freeList[bestIdx].Size = fe.Size - need
			}
			allocated = true
		}
	}
	if !allocated {
		// allocate at end of the live region. The live region is
		// the max of any indexed file's tail AND any free-list
		// extent's tail: a free extent that lies past the highest
		// indexed file would otherwise be silently overwritten by
		// the new allocation, and a later best-fit allocation from
		// that same free extent would then collide with us. By
		// taking the max across both sets we guarantee the new
		// allocation lands beyond every byte the allocator might
		// hand out later.
		var end uint64 = 0
		for _, v := range fs.index {
			if v.Offset+v.Size > end {
				end = v.Offset + v.Size
			}
		}
		for _, fe := range fs.freeList {
			if fe.Offset+fe.Size > end {
				end = fe.Offset + fe.Size
			}
		}
		off = end
	}
	if len(data) > 0 {
		if _, err := fs.f.WriteAt(data, fs.contentStart()+int64(off)); err != nil {
			return err
		}
	}
	fs.index[p] = fileEntry{Offset: off, Size: uint64(len(data)), IsDir: false}
	// update metadata
	fs.ensureMetaForPath(p)
	me := fs.meta[p]
	me.Mode = uint32(perm)
	me.Mtime = time.Now().Unix()
	me.Ctime = me.Mtime
	me.Atime = me.Mtime
	fs.meta[p] = me
	return fs.saveIndex()
}

func (fs *ntfsFS) ReadLink(p string) (string, error) {
	p = normalizePath(p)
	if me, ok := fs.meta[p]; ok && me.IsSymlink {
		return me.LinkTarget, nil
	}
	return "", errors.New("not a symlink")
}

func (fs *ntfsFS) MkDir(p string, perm os.FileMode) error {
	p = normalizePath(p)
	if p == "/" {
		return nil
	}
	parent := path.Dir(p)
	if parent == "." || parent == "" {
		parent = "/"
	}
	if err := fs.ensureParentDirs(parent); err != nil {
		return err
	}
	if e, ok := fs.index[p]; ok {
		if e.IsDir {
			return nil
		}
		return fmt.Errorf("ntfs: %q exists and is not a directory", p)
	}
	fs.index[p] = fileEntry{Offset: 0, Size: 0, IsDir: true}
	fs.ensureMetaForPath(p)
	me := fs.meta[p]
	me.Mode = uint32(perm)
	me.Mtime = time.Now().Unix()
	me.Ctime = me.Mtime
	me.Atime = me.Mtime
	fs.meta[p] = me
	return fs.saveIndex()
}

func (fs *ntfsFS) DeleteFile(p string) error {
	p = normalizePath(p)
	e, ok := fs.index[p]
	if !ok {
		return fmt.Errorf("ntfs: %q not found", p)
	}
	if e.Offset > 0 && e.Size > 0 {
		fs.freeList = append(fs.freeList, fileEntry{Offset: e.Offset, Size: e.Size})
		fs.mergeFreeList()
	}
	delete(fs.index, p)
	delete(fs.meta, p)
	return fs.saveIndex()
}

func (fs *ntfsFS) DeleteDir(p string) error {
	p = normalizePath(p)
	// delete all entries with prefix p/
	prefix := p
	if prefix == "/" {
		// delete everything
		fs.index = map[string]fileEntry{}
		fs.meta = map[string]metaEntry{}
		return fs.saveIndex()
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix = prefix + "/"
	}
	for k := range fs.index {
		if k == p || strings.HasPrefix(k, prefix) {
			if e := fs.index[k]; e.Offset > 0 && e.Size > 0 {
				fs.freeList = append(fs.freeList, fileEntry{Offset: e.Offset, Size: e.Size})
			}
			delete(fs.index, k)
			delete(fs.meta, k)
		}
	}
	fs.mergeFreeList()
	return fs.saveIndex()
}

func (fs *ntfsFS) Rename(oldPath, newPath string) error {
	oldPath = normalizePath(oldPath)
	newPath = normalizePath(newPath)
	e, ok := fs.index[oldPath]
	if !ok {
		return fmt.Errorf("ntfs: %q not found", oldPath)
	}
	// prevent moving directory into itself
	if e.IsDir && (newPath == oldPath || strings.HasPrefix(newPath+"/", oldPath+"/")) {
		return fmt.Errorf("ntfs: invalid rename target %q -> %q", oldPath, newPath)
	}
	// ensure parent of newPath exists
	parent := path.Dir(newPath)
	if parent == "." || parent == "" {
		parent = "/"
	}
	if err := fs.ensureParentDirs(parent); err != nil {
		return err
	}

	if e.IsDir {
		// perform recursive rename of all entries under oldPath
		updates := map[string]fileEntry{}
		deletes := []string{}
		for k, v := range fs.index {
			if k == oldPath || strings.HasPrefix(k, oldPath+"/") {
				var nk string
				if k == oldPath {
					nk = newPath
				} else {
					nk = newPath + strings.TrimPrefix(k, oldPath)
				}
				updates[nk] = v
				deletes = append(deletes, k)
			}
		}
		for _, d := range deletes {
			delete(fs.index, d)
		}
		for nk, v := range updates {
			fs.index[nk] = v
		}
		return fs.saveIndex()
	}

	// file rename
	if _, exists := fs.index[newPath]; exists {
		delete(fs.index, newPath)
	}
	fs.index[newPath] = e
	delete(fs.index, oldPath)
	return fs.saveIndex()
}

// mergeFreeList coalesces contiguous or overlapping free extents.
func (fs *ntfsFS) mergeFreeList() {
	if len(fs.freeList) <= 1 {
		return
	}
	sort.Slice(fs.freeList, func(i, j int) bool { return fs.freeList[i].Offset < fs.freeList[j].Offset })
	out := make([]fileEntry, 0, len(fs.freeList))
	cur := fs.freeList[0]
	for _, e := range fs.freeList[1:] {
		curEnd := cur.Offset + cur.Size
		if e.Offset <= curEnd { // overlapping or adjacent
			end := curEnd
			if e.Offset+e.Size > end {
				end = e.Offset + e.Size
			}
			cur.Size = end - cur.Offset
		} else {
			out = append(out, cur)
			cur = e
		}
	}
	out = append(out, cur)
	fs.freeList = out
}

// normalizePath returns a canonical absolute path with a leading '/'.
func normalizePath(p string) string {
	if p == "" || p == "." {
		return "/"
	}
	p = path.Clean(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// ensureParentDirs creates any missing parent directories for path p.
func (fs *ntfsFS) ensureParentDirs(p string) error {
	p = normalizePath(p)
	if p == "/" {
		return nil
	}
	parent := path.Dir(p)
	if parent == "." || parent == "" {
		parent = "/"
	}
	if parent != "/" {
		if err := fs.ensureParentDirs(parent); err != nil {
			return err
		}
	}
	if _, ok := fs.index[parent]; !ok {
		fs.index[parent] = fileEntry{Offset: 0, Size: 0, IsDir: true}
	}
	return nil
}
