// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) the go-filesystems/ntfs authors

package filesystem_ntfs

// Memory-bomb regression tests. Every input-driven allocation is bounded
// before it happens: each test hands the reader a few hundred bytes that claim
// gigabytes, and asserts both that the read is refused and that it allocated
// less than bombBudget doing so (runtime.MemStats.TotalAlloc before/after).

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"testing"
)

const bombBudget = 1 << 20

// totalAlloc reports the bytes the heap handed out while f ran.
func totalAlloc(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

func bombReader() *realNTFS {
	return &realNTFS{
		f:    nopReaderAt(make([]byte, 64*1024)),
		boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 1},
	}
}

// A sparse hole in a directory index is meaningless (ntfs-3g and Linux ntfs3
// both read index blocks from allocated clusters), so metadata attributes
// refuse sparse runs outright rather than materialising the zeros.
func TestBomb_SparseIndexAllocationRefused(t *testing.T) {
	r := bombReader()
	a := attribute{
		typeCode: attrIndexAllocation, nonResident: true, realSize: 1 << 30,
		runs: []dataRun{{lengthClusters: 1 << 21, sparse: true, startCluster: -1}},
	}
	var err error
	n := totalAlloc(func() { _, err = r.readAttrData(&a) })
	if err == nil {
		t.Error("1 GiB sparse $INDEX_ALLOCATION was materialised")
	}
	if n >= bombBudget {
		t.Errorf("allocated %d bytes before refusing", n)
	}
}

// A data run must lie inside the image: a 1 GiB run at cluster 8 of a 64 KiB
// image is a lie, and the buffer for it must not be allocated.
func TestBomb_RunPastEndOfImageRefused(t *testing.T) {
	r := bombReader()
	a := attribute{
		typeCode: attrData, nonResident: true, realSize: 1 << 30,
		runs: []dataRun{{lengthClusters: 1 << 21, startCluster: 8}},
	}
	var err error
	n := totalAlloc(func() { _, err = r.readAttrData(&a) })
	if err == nil {
		t.Error("run past the end of the image was read")
	}
	if n >= bombBudget {
		t.Errorf("allocated %d bytes before refusing", n)
	}
}

// A run that straddles the end of the image is refused too, and one that ends
// exactly on the last byte is read.
func TestBomb_RunBackingIsExact(t *testing.T) {
	r := bombReader() // 64 KiB image, 512-byte clusters: 128 clusters
	ok := []dataRun{{lengthClusters: 4, startCluster: 124}}
	if b, err := r.readRuns(ok, 4*512); err != nil || len(b) != 4*512 {
		t.Fatalf("run ending on the last byte: len=%d err=%v", len(b), err)
	}
	over := []dataRun{{lengthClusters: 5, startCluster: 124}}
	if _, err := r.readRuns(over, 5*512); err == nil {
		t.Error("run one cluster past the end was read")
	}
}

// Sparse data is the one place the volume legitimately reads back bigger than
// it is, so $DATA is allowed but ceilinged: at the ceiling passes, one over is
// refused with ErrTooLarge before the buffer exists.
func TestBomb_SparseDataCeiling(t *testing.T) {
	r := bombReader()
	r.SetMaxDataSize(1 << 20)
	mk := func(size uint64) *attribute {
		return &attribute{
			typeCode: attrData, nonResident: true, realSize: size,
			runs: []dataRun{{lengthClusters: 1 << 21, sparse: true, startCluster: -1}},
		}
	}
	if b, err := r.readAttrData(mk(1 << 20)); err != nil || len(b) != 1<<20 {
		t.Fatalf("at the ceiling: len=%d err=%v", len(b), err)
	}
	var err error
	n := totalAlloc(func() { _, err = r.readAttrData(mk(1<<20 + 1)) })
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("one over the ceiling: err=%v, want ErrTooLarge", err)
	}
	if n >= bombBudget {
		t.Errorf("allocated %d bytes before refusing", n)
	}
	r.SetMaxDataSize(0)
	if r.dataLimit() != DefaultMaxDataSize {
		t.Errorf("SetMaxDataSize(0) did not restore the default")
	}
}

// realSize says 1 GiB, the runlist says nothing: the buffer is sized by what
// the runlist can back, not by the claim.
func TestBomb_CompressedSizeBoundedByRunlist(t *testing.T) {
	r := bombReader()
	var b []byte
	var err error
	n := totalAlloc(func() { b, err = r.readCompressedRuns(nil, 1<<30, 4) })
	if n >= bombBudget {
		t.Errorf("allocated %d bytes for an empty runlist (err=%v, len=%d)", n, err, len(b))
	}
}

// compUnit 20 with 512-byte clusters is a 512 MiB "unit": the LZNT1 output
// buffer was sized by it. A unit is at most 64 KiB.
func TestBomb_CompressionUnitCapped(t *testing.T) {
	r := bombReader()
	runs := []dataRun{
		{lengthClusters: 1, startCluster: 1},
		{lengthClusters: 1<<20 - 1, sparse: true, startCluster: -1},
	}
	var err error
	n := totalAlloc(func() { _, err = r.readCompressedRuns(runs, 1<<20, 20) })
	if err == nil {
		t.Error("a 512 MiB compression unit was accepted")
	}
	if n >= bombBudget {
		t.Errorf("allocated %d bytes before refusing", n)
	}
	// The cap is exact: 128 clusters of 512 = 64 KiB passes, 256 does not.
	if _, err := r.readCompressedRuns(nil, 0, 7); err != nil {
		t.Errorf("64 KiB unit refused: %v", err)
	}
	if _, err := r.readCompressedRuns(nil, 0, 8); err == nil {
		t.Error("128 KiB unit accepted")
	}
}

// ReadLink looks for the IntxLNK marker at the start of any file with no
// reparse point. It used to read the whole file to find out.
func TestBomb_ReadLinkDoesNotMaterialiseALargeFile(t *testing.T) {
	r := bombReader()
	fr := &fileRecord{attrs: []attribute{{
		typeCode: attrData, nonResident: true, realSize: 1 << 30,
		runs: []dataRun{{lengthClusters: 1 << 21, sparse: true, startCluster: -1}},
	}}}
	var ok bool
	var err error
	n := totalAlloc(func() { _, ok, err = r.intxLinkTarget(fr) })
	if err != nil || ok {
		t.Errorf("a 1 GiB file is not a link: ok=%v err=%v", ok, err)
	}
	if n >= bombBudget {
		t.Errorf("allocated %d bytes to learn that", n)
	}
}

// Index entries must not overlap: the entry is at least its 0x10-byte header
// and its key lies inside it (Linux ntfs3 hdr_find_e). A 16-byte stride with
// a 576-byte key made every 16 bytes of input decode a 255-character name.
func TestBomb_OverlappingIndexEntries(t *testing.T) {
	const stride = 16
	buf := make([]byte, 256<<10)
	for off := 0; off+stride <= len(buf); off += stride {
		buf[off+0] = 255                                    // name length (read at +0x50)
		binary.LittleEndian.PutUint16(buf[off+8:], stride)  // entry length
		binary.LittleEndian.PutUint16(buf[off+10:], 0x0240) // key length
	}
	var out []indexEntry
	n := totalAlloc(func() { out, _ = parseIndexEntries(buf, 0) })
	if len(out) != 0 {
		t.Errorf("%d entries decoded from overlapping keys (%d bytes allocated)", len(out), n)
	}
	if n >= bombBudget {
		t.Errorf("allocated %d bytes", n)
	}
}

// Legacy NTFSIMG1 header: an ACL length is a uint32 off the image.
func TestBomb_LegacyHeaderACLLength(t *testing.T) {
	hdr := make([]byte, headerSize)
	copy(hdr, headerMagic)
	binary.LittleEndian.PutUint32(hdr[len(headerMagic):], 0) // no files
	binary.LittleEndian.PutUint32(hdr[len(headerMagic)+4:], 0)
	m := hdr[len(headerMagic)+8:]
	copy(m, metaMagic)
	p := len(metaMagic)
	binary.LittleEndian.PutUint32(m[p:], 1) // one meta entry
	p += 4
	binary.LittleEndian.PutUint16(m[p:], 1) // name length
	p += 2
	m[p] = 'x'
	p++
	p += 8 + 4 + 4 + 4 + 8 + 8 + 8 + 1 // inode, mode, uid, gid, a/m/ctime, symlink flag
	binary.LittleEndian.PutUint16(m[p:], 0)
	p += 2
	binary.LittleEndian.PutUint32(m[p:], 0xFFFFFFFF) // aclLen

	fs := &ntfsFS{f: nopReaderAt(hdr), index: map[string]fileEntry{}}
	n := totalAlloc(func() { _ = fs.loadIndex() })
	if n >= bombBudget {
		t.Errorf("allocated %d bytes for a 4 GiB ACL claim", n)
	}
}

// Compact read each file whole into make([]byte, e.Size) with Size off the
// image: one index entry claiming a terabyte crashed the process.
func TestBomb_CompactRefusesAHugeEntry(t *testing.T) {
	var img bytes.Buffer
	img.Write(make([]byte, headerSize+4096))
	fs := &ntfsFS{
		f: nopReaderAt(img.Bytes()),
		index: map[string]fileEntry{
			"/":    {IsDir: true},
			"/a":   {Offset: 1, Size: 3},
			"/big": {Offset: 8, Size: 1 << 40},
		},
		meta: map[string]metaEntry{},
	}
	var err error
	n := totalAlloc(func() { err = fs.Compact() })
	if err == nil {
		t.Error("Compact accepted an entry larger than the image")
	}
	if n >= bombBudget {
		t.Errorf("allocated %d bytes", n)
	}
}
