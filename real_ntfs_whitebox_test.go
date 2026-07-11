// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) the go-filesystems/ntfs authors

package filesystem_ntfs

// White-box tests that drive the defensive error branches of the feature code
// directly, using hand-built realNTFS values and fake backing disks so the
// overflow / short-read / unreachable-record guards are all exercised.

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"
)

// memDisk is an in-memory diskRW.
type memDisk struct{ data []byte }

func (m *memDisk) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (m *memDisk) WriteAt(p []byte, off int64) (int, error) { return len(p), nil }
func (m *memDisk) Close() error                             { return nil }

// errDisk fails every ReadAt with a non-EOF error.
type errDisk struct{}

var errBoom = errors.New("boom")

func (errDisk) ReadAt(p []byte, off int64) (int, error)  { return 0, errBoom }
func (errDisk) WriteAt(p []byte, off int64) (int, error) { return len(p), nil }
func (errDisk) Close() error                             { return nil }

func rawReader(bps, spc uint32) *realNTFS {
	return &realNTFS{
		f:    &memDisk{data: make([]byte, 4096)},
		boot: bootSector{bytesPerSector: bps, sectorsPerCluster: spc},
	}
}

func TestWB_ReadCompressedRuns_Errors(t *testing.T) {
	r := rawReader(512, 1)
	// unitBytes overflow: enormous cluster size with a large compression unit.
	huge := &realNTFS{f: &memDisk{data: make([]byte, 16)}, boot: bootSector{bytesPerSector: 1 << 20, sectorsPerCluster: 1 << 20}}
	if _, err := huge.readCompressedRuns(nil, 64, 30); err == nil {
		t.Fatal("expected unit-size overflow")
	}
	// size larger than MaxInt64.
	if _, err := r.readCompressedRuns(nil, math.MaxUint64, 2); err == nil {
		t.Fatal("expected size-too-large error")
	}
	// size beyond the maxDataSize ceiling (buffer allocation refused).
	if _, err := r.readCompressedRuns(nil, uint64(maxDataSize)+1, 2); err == nil {
		t.Fatal("expected data-buffer error")
	}
	// A unit whose allocated cluster read overflows (start cluster near max).
	runs := []dataRun{{lengthClusters: 1, startCluster: math.MaxInt64}}
	if _, err := r.readCompressedRuns(runs, uint64(4*tClusterSize), 2); err == nil {
		t.Fatal("expected readUnit cluster-read overflow")
	}
}

func TestWB_ReadClusters_Errors(t *testing.T) {
	r := rawReader(512, 1)
	// count * clusterSize overflow.
	if _, err := r.readClusters(0, int64(1)<<62); err == nil {
		t.Fatal("count overflow")
	}
	// lcn * clusterSize overflow.
	if _, err := r.readClusters(int64(1)<<62, 1); err == nil {
		t.Fatal("lcn overflow")
	}
	// base + partOffset overflow.
	r2 := rawReader(512, 1)
	r2.partOffset = math.MaxInt64
	if _, err := r2.readClusters(1, 1); err == nil {
		t.Fatal("absolute offset overflow")
	}
	// buffer size beyond maxDataSize.
	if _, err := r.readClusters(0, int64(maxDataSize)/tClusterSize+1); err == nil {
		t.Fatal("cluster buffer too large")
	}
	// a non-EOF ReadAt error surfaces.
	re := &realNTFS{f: errDisk{}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 1}}
	if _, err := re.readClusters(0, 1); err == nil {
		t.Fatal("expected ReadAt error")
	}
}

func TestWB_LZNT1_TruncatedAndLiteralOverflow(t *testing.T) {
	// Truncated final uncompressed chunk: header claims 6 bytes, only 1 present.
	if b, err := lznt1Decompress([]byte{0x05, 0x00, 0x41}, 100); err != nil || string(b) != "A" {
		t.Fatalf("truncated chunk: b=%q err=%v", b, err)
	}
	// Compressed chunk of literals that overflows the unit ceiling.
	// header 0xB004 = compressed, chunkLen 5; flags 0x00 (all literals) + ABCD.
	stream := []byte{0x04, 0xB0, 0x00, 0x41, 0x42, 0x43, 0x44}
	if _, err := lznt1Decompress(stream, 2); err == nil {
		t.Fatal("expected literal-overflow error in compressed chunk")
	}
}

func TestWB_ResolveAttributes_Errors(t *testing.T) {
	r := openSynthReader(t)

	// $ATTRIBUTE_LIST whose non-resident runlist read fails.
	frBadList := &fileRecord{attrs: []attribute{{
		typeCode:    attrAttributeList,
		nonResident: true,
		realSize:    tClusterSize,
		runs:        []dataRun{{lengthClusters: 1, startCluster: math.MaxInt64}},
	}}}
	if err := r.resolveAttributes(5, frBadList); err == nil {
		t.Fatal("expected list read error")
	}

	// A resident $ATTRIBUTE_LIST with a malformed entry length.
	badBody := attrListEntryBytes(attrData, "", 0, 5, 1)
	badBody[4] = 0x02 // recordLength < 0x1A
	frBadParse := &fileRecord{attrs: []attribute{{typeCode: attrAttributeList, residentData: badBody}}}
	if err := r.resolveAttributes(5, frBadParse); err == nil {
		t.Fatal("expected parse error")
	}

	// A list that references an unreachable extension record.
	body := attrListEntryBytes(attrData, "", 0, 999999, 1)
	frUnreach := &fileRecord{attrs: []attribute{{typeCode: attrAttributeList, residentData: body}}}
	if err := r.resolveAttributes(5, frUnreach); err == nil {
		t.Fatal("expected unreachable extension-record error")
	}

	// No attribute list: a no-op that leaves the record untouched.
	frPlain := &fileRecord{attrs: []attribute{{typeCode: attrData, residentData: []byte("x")}}}
	if err := r.resolveAttributes(5, frPlain); err != nil {
		t.Fatalf("no-list resolve: %v", err)
	}
}

func TestWB_CompressedUnit_DecodeAndTruncate(t *testing.T) {
	// A genuine compressed unit: 1 allocated cluster (holding an LZNT1 stream
	// that decompresses to a full 2048-byte unit) followed by 3 sparse clusters.
	data := bytes.Repeat([]byte("ABCD"), 512) // 2048 bytes, one compUnit=2 unit
	comp := lznt1CompressForTest(data)
	if len(comp) > tClusterSize {
		t.Fatalf("compressed stream %d exceeds one cluster", len(comp))
	}
	disk := make([]byte, 8*tClusterSize)
	copy(disk[tClusterSize:], comp) // allocated cluster is LCN 1
	r := &realNTFS{f: &memDisk{data: disk}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 1}}
	runs := []dataRun{
		{lengthClusters: 1, startCluster: 1},
		{lengthClusters: 3, startCluster: -1, sparse: true},
	}
	// Truncated logical size: only 100 of the 2048 decompressed bytes are kept.
	out, err := r.readCompressedRuns(runs, 100, 2)
	if err != nil || !bytes.Equal(out, data[:100]) {
		t.Fatalf("truncated compressed unit: len=%d err=%v", len(out), err)
	}
	// Full read returns the whole unit.
	full, err := r.readCompressedRuns(runs, uint64(len(data)), 2)
	if err != nil || !bytes.Equal(full, data) {
		t.Fatalf("full compressed unit mismatch: err=%v", err)
	}
}

func TestWB_CompressedUnit_MultiUnitRun(t *testing.T) {
	// One contiguous allocated run of 8 clusters spans two full (verbatim)
	// compression units of 4 clusters each, so segment must split the run at
	// the unit boundary (the n > want path).
	unitBytes := 4 * tClusterSize
	data := make([]byte, 2*unitBytes)
	for i := range data {
		data[i] = byte(i) // non-repeating so each unit stays "uncompressed"
	}
	disk := make([]byte, 16*tClusterSize)
	copy(disk[tClusterSize:], data) // 8 clusters starting at LCN 1
	r := &realNTFS{f: &memDisk{data: disk}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 1}}
	runs := []dataRun{{lengthClusters: 8, startCluster: 1}}
	out, err := r.readCompressedRuns(runs, uint64(len(data)), 2)
	if err != nil || !bytes.Equal(out, data) {
		t.Fatalf("multi-unit run: len=%d err=%v", len(out), err)
	}
}

func TestWB_CompressedUnit_BadStream(t *testing.T) {
	// The allocated cluster holds an invalid LZNT1 stream (a token at the very
	// start of the chunk), so decompression of the unit errors.
	disk := make([]byte, 8*tClusterSize)
	copy(disk[tClusterSize:], []byte{0x03, 0x80, 0x01, 0x00, 0x00})
	r := &realNTFS{f: &memDisk{data: disk}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 1}}
	runs := []dataRun{
		{lengthClusters: 1, startCluster: 1},
		{lengthClusters: 3, startCluster: -1, sparse: true},
	}
	if _, err := r.readCompressedRuns(runs, uint64(4*tClusterSize), 2); err == nil {
		t.Fatal("expected LZNT1 decode error for the unit")
	}
}

func TestWB_IntxLink_NoData(t *testing.T) {
	r := openSynthReader(t)
	// A record with no $DATA is not an IntxLNK symlink (ok=false path).
	fr := &fileRecord{attrs: []attribute{{typeCode: attrStandardInformation, residentData: make([]byte, 48)}}}
	if s, ok, err := r.intxLinkTarget(fr); err != nil || ok || s != "" {
		t.Fatalf("intxLinkTarget(no data) = %q,%v,%v", s, ok, err)
	}
}
