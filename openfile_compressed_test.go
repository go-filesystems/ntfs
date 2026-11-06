package filesystem_ntfs

import (
	"bytes"
	"io"
	"runtime"
	"testing"
)

// A 72 MiB compressed stream of 64 KiB units, alternating LZNT1-compressed,
// stored verbatim and sparse, read by range: across units and past 64 MiB.
func TestOpenFileCompressedReadsARangePast64MiB(t *testing.T) {
	const cs = 4096
	const unitClusters = 16
	const unitBytes = unitClusters * cs
	const units = 72 << 20 / unitBytes
	want := make([]byte, 72<<20)
	var runs []dataRun
	var disk []byte
	lcn := int64(10)
	disk = make([]byte, 10*cs)
	for u := 0; u < units; u++ {
		dst := want[u*unitBytes : (u+1)*unitBytes]
		switch u % 3 {
		case 0: // compressed: the stream's clusters, then sparse padding
			copy(dst, bytes.Repeat([]byte{'A', 'B', byte(u), byte(u >> 8)}, unitBytes/4))
			comp := lznt1CompressForTest(dst)
			n := int64((len(comp) + cs - 1) / cs)
			if n >= unitClusters {
				t.Fatalf("unit %d did not compress", u)
			}
			buf := make([]byte, n*cs)
			copy(buf, comp)
			disk = append(disk, buf...)
			runs = append(runs, dataRun{lengthClusters: n, startCluster: lcn},
				dataRun{lengthClusters: unitClusters - n, sparse: true, startCluster: -1})
			lcn += n
		case 1: // verbatim: all clusters allocated
			for i := range dst {
				dst[i] = byte(i*7 + i>>9 + u)
			}
			disk = append(disk, dst...)
			runs = append(runs, dataRun{lengthClusters: unitClusters, startCluster: lcn})
			lcn += unitClusters
		default: // a hole
			runs = append(runs, dataRun{lengthClusters: unitClusters, sparse: true, startCluster: -1})
		}
	}
	r := &realNTFS{f: &memDisk{data: disk}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 8}}
	f, err := r.openAttr(&attribute{typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 4, runs: runs, realSize: uint64(len(want))})
	if err != nil {
		t.Fatal(err)
	}
	if f.Size() != int64(len(want)) {
		t.Fatalf("Size = %d", f.Size())
	}
	checkRanges(t, f, want, 0, 4095, unitBytes-100, 3*unitBytes+5, 64<<20, 66<<20+123, int64(len(want))-10)
	span := make([]byte, 5<<20+17)
	if n, err := f.ReadAt(span, 30<<20+3); n != len(span) || err != nil || !bytes.Equal(span, want[30<<20+3:30<<20+3+len(span)]) {
		t.Fatalf("a read across units = %d, %v", n, err)
	}

	// What a 1 MiB read at 66 MiB allocates is bounded by its window (16 units),
	// not by the 72 MiB of the file.
	f, _ = r.openAttr(&attribute{typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 4, runs: runs, realSize: uint64(len(want))})
	buf := make([]byte, 1<<20)
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	if _, err := f.ReadAt(buf, 66<<20); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&m1)
	if got := m1.TotalAlloc - m0.TotalAlloc; got > 8<<20 {
		t.Errorf("a 1 MiB read of a 72 MiB compressed file allocated %d bytes", got)
	}
}

// Bombs: a forged size, a forged runlist and a forged unit are bounded or
// refused; none sizes an allocation.
func TestBomb_CompressedOpenFileIsBoundedByTheWindow(t *testing.T) {
	r := &realNTFS{f: &memDisk{data: make([]byte, 64*4096)}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 8}}
	// 1 TiB declared, backed by a 1 TiB sparse run: a 4 KiB read far inside it
	// is zeros and allocates one unit, not a terabyte.
	f, err := r.openAttr(&attribute{typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 4,
		realSize: 1 << 40, runs: []dataRun{{lengthClusters: 1 << 28, sparse: true, startCluster: -1}}})
	if err != nil {
		t.Fatal(err)
	}
	if f.Size() != 1<<40 {
		t.Fatalf("Size = %d", f.Size())
	}
	buf := bytes.Repeat([]byte{1}, 4096)
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	n, err := f.ReadAt(buf, 1<<39)
	runtime.ReadMemStats(&m1)
	if n != 4096 || err != nil || !bytes.Equal(buf, make([]byte, 4096)) {
		t.Fatalf("read in a hole = %d, %v", n, err)
	}
	if got := m1.TotalAlloc - m0.TotalAlloc; got > 1<<20 {
		t.Errorf("a 4 KiB read allocated %d bytes", got)
	}
	// A size claim beyond what the runlist describes is cut to the runlist.
	g, _ := r.openAttr(&attribute{typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 4,
		realSize: 1 << 60, runs: []dataRun{{lengthClusters: 16, sparse: true, startCluster: -1}}})
	if g.Size() != 16*4096 {
		t.Errorf("Size = %d, want the runlist's 65536", g.Size())
	}
	if _, err := g.ReadAt(make([]byte, 8), 16*4096); err != io.EOF {
		t.Errorf("a read past the runlist = %v", err)
	}
	// A unit exponent that overflows, a unit over 64 KiB, a size over 2^62: refused at open.
	for name, a := range map[string]*attribute{
		"exponent 31": {typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 31, realSize: 10},
		"size 2^63":   {typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 4, realSize: 1 << 63},
		"overflow": {typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 4, realSize: 10,
			runs: []dataRun{{lengthClusters: 1 << 62, startCluster: 1}}},
	} {
		if _, err := r.openAttr(a); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	big := &realNTFS{f: &memDisk{data: make([]byte, 4096)}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 16}}
	if _, err := big.openAttr(&attribute{typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 4, realSize: 10}); err == nil {
		t.Error("a 128 KiB compression unit was opened")
	}
	// An LZNT1 stream that does not decode is the read's error, every time.
	disk := make([]byte, 8*4096)
	copy(disk[4096:], []byte{0x03, 0x80, 0x01, 0x00, 0x00})
	bad := &realNTFS{f: &memDisk{data: disk}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 8}}
	h, _ := bad.openAttr(&attribute{typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 4, realSize: 4096,
		runs: []dataRun{{lengthClusters: 1, startCluster: 1}, {lengthClusters: 15, sparse: true, startCluster: -1}}})
	for i := 0; i < 2; i++ {
		if _, err := h.ReadAt(make([]byte, 8), 0); err == nil {
			t.Error("a bad LZNT1 stream was read")
		}
	}
}
