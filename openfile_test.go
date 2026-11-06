package filesystem_ntfs

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

func offsetPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>12)
	}
	return b
}

func checkRanges(t *testing.T, f filesystem.File, want []byte, offs ...int64) {
	t.Helper()
	size := int64(len(want))
	for _, off := range offs {
		buf := make([]byte, 4096)
		n, err := f.ReadAt(buf, off)
		wantN := min(int64(len(buf)), size-off)
		if int64(n) != wantN || (n < len(buf)) != errors.Is(err, io.EOF) || (n == len(buf) && err != nil) {
			t.Fatalf("ReadAt(%d) = %d, %v; want %d", off, n, err, wantN)
		}
		if !bytes.Equal(buf[:n], want[off:off+int64(n)]) {
			t.Fatalf("ReadAt(%d): wrong bytes", off)
		}
	}
	if n, err := f.ReadAt(make([]byte, 8), size); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt at the end = %d, %v", n, err)
	}
	if _, err := f.ReadAt(make([]byte, 8), -1); err == nil {
		t.Error("a negative offset was read")
	}
	if err := f.Close(); err != nil {
		t.Error(err)
	}
}

// This package's own image format: a file is one contiguous extent.
func TestOpenFileFlatReadsARangePast64MiB(t *testing.T) {
	const fileSize = 72 << 20
	path := filepath.Join(t.TempDir(), "flat.img")
	fs, err := Format(path, 2*fileSize, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()
	want := offsetPattern(fileSize)
	if err := fs.WriteFile("/big", want, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	o, ok := fs.(filesystem.Opener)
	if !ok {
		t.Fatal("the driver is not a filesystem.Opener")
	}
	f, err := o.OpenFile("/big")
	if err != nil {
		t.Fatal(err)
	}
	if f.Size() != fileSize {
		t.Fatalf("Size = %d", f.Size())
	}
	checkRanges(t, f, want, 0, 4095, 64<<20, 66<<20+123, fileSize-10)
	if _, err := o.OpenFile("/nope"); err == nil {
		t.Error("a missing file was opened")
	}
	if _, err := o.OpenFile("/"); err == nil {
		t.Error("a directory was opened")
	}
}

// A real NTFS non-resident stream: a 72 MiB file of three runs (data, a hole,
// data) is read by range, across the runs and past 64 MiB.
func TestOpenFileRunsReadsARangePast64MiB(t *testing.T) {
	const cs = 4096
	const clusters = 72 << 20 / cs
	want := offsetPattern(72 << 20)
	disk := make([]byte, (6000+12288+16)*cs)
	runs := []dataRun{
		{lengthClusters: 4096, startCluster: 100},
		{lengthClusters: 2048, sparse: true, startCluster: -1},
		{lengthClusters: clusters - 4096 - 2048, startCluster: 6000},
	}
	copy(disk[100*cs:], want[:4096*cs])
	clear(want[4096*cs : 6144*cs]) // the hole reads as zeros
	copy(disk[6000*cs:], want[6144*cs:])
	r := &realNTFS{f: &memDisk{data: disk}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 8}}
	f, err := r.openAttr(&attribute{typeCode: attrData, nonResident: true, runs: runs, realSize: uint64(len(want))})
	if err != nil {
		t.Fatal(err)
	}
	if f.Size() != int64(len(want)) {
		t.Fatalf("Size = %d", f.Size())
	}
	// The ends of the runs, the hole, and a window across the hole.
	checkRanges(t, f, want, 0, 4095, 16<<20-100, 17<<20, 24<<20-4000, 25<<20, 66<<20+123, int64(len(want))-10)
	span := make([]byte, 20<<20)
	if n, err := f.ReadAt(span, 10<<20); n != len(span) || err != nil || !bytes.Equal(span, want[10<<20:10<<20+len(span)]) {
		t.Fatalf("a read across the hole = %d, %v", n, err)
	}
}

func TestOpenFileResidentAndCompressedAndRefusals(t *testing.T) {
	r := &realNTFS{f: &memDisk{data: make([]byte, 4096)}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 8}}
	res, err := r.openAttr(&attribute{typeCode: attrData, residentData: []byte("hello world")})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if n, err := res.ReadAt(buf, 6); n != 5 || err != nil || string(buf) != "world" || res.Size() != 11 {
		t.Errorf("resident ReadAt = %d %v %q", n, err, buf)
	}
	if n, err := res.ReadAt(make([]byte, 20), 0); n != 11 || !errors.Is(err, io.EOF) {
		t.Errorf("resident ReadAt past the end = %d %v", n, err)
	}
	if _, err := res.ReadAt(buf, -1); err == nil {
		t.Error("a negative offset was read")
	}
	if _, err := r.openAttr(&attribute{typeCode: attrData, nonResident: true, flags: attrFlagEncrypted}); err == nil {
		t.Error("an encrypted stream was opened")
	}
	// A compressed stream is loaded whole, once, on the first read; its failure is the read's.
	comp, err := r.openAttr(&attribute{typeCode: attrData, nonResident: true, flags: 0x0001, compUnit: 4, realSize: 100,
		runs: []dataRun{{lengthClusters: 1, startCluster: 99999}}})
	if err != nil {
		t.Fatal(err)
	}
	if comp.Size() != 100 {
		t.Errorf("compressed Size = %d", comp.Size())
	}
	if _, err := comp.ReadAt(make([]byte, 8), 0); err == nil {
		t.Error("a compressed stream whose run is past the image was read")
	}
	if _, err := comp.ReadAt(make([]byte, 8), 0); err == nil {
		t.Error("the failure of the first load was forgotten")
	}
	if err := comp.Close(); err != nil {
		t.Error(err)
	}
	// Overflowing runs are refused at open.
	if _, err := r.openAttr(&attribute{typeCode: attrData, nonResident: true, realSize: 10,
		runs: []dataRun{{lengthClusters: 1 << 62, startCluster: 1}}}); err == nil {
		t.Error("a run whose byte count overflows was opened")
	}
	if _, err := r.openAttr(&attribute{typeCode: attrData, nonResident: true, realSize: 1 << 63}); err == nil {
		t.Error("a size past 2^62 was opened")
	}
	// A forged start cluster cannot wrap, and a run past the image is refused.
	bad, err := r.openAttr(&attribute{typeCode: attrData, nonResident: true, realSize: 4096,
		runs: []dataRun{{lengthClusters: 1, startCluster: 1 << 62}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.ReadAt(make([]byte, 16), 0); err == nil {
		t.Error("a run at a forged cluster was read")
	}
	past, _ := r.openAttr(&attribute{typeCode: attrData, nonResident: true, realSize: 4096,
		runs: []dataRun{{lengthClusters: 1, startCluster: 50}}})
	if _, err := past.ReadAt(make([]byte, 16), 0); err == nil {
		t.Error("a run past the end of the image was read")
	}
}

// BenchmarkReadRangeOfBigFile: a 1 MiB read at 66 MiB of a 72 MiB file in this
// package's own format, through OpenFile/ReadAt and through ReadFile.
// Allocations are exact; times are not under load.
func BenchmarkReadRangeOfBigFile(b *testing.B) {
	const fileSize = 72 << 20
	path := filepath.Join(b.TempDir(), "flat.img")
	fs, err := Format(path, 2*fileSize, FormatConfig{})
	if err != nil {
		b.Fatal(err)
	}
	defer fs.Close()
	if err := fs.WriteFile("/big", offsetPattern(fileSize), 0o644); err != nil {
		b.Fatal(err)
	}
	b.Run("OpenFile-ReadAt", func(b *testing.B) {
		f, err := fs.(filesystem.Opener).OpenFile("/big")
		if err != nil {
			b.Fatal(err)
		}
		buf := make([]byte, 1<<20)
		b.SetBytes(int64(len(buf)))
		b.ReportAllocs()
		for b.Loop() {
			if _, err := f.ReadAt(buf, 66<<20); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ReadFile-whole", func(b *testing.B) {
		b.SetBytes(1 << 20)
		b.ReportAllocs()
		for b.Loop() {
			data, err := fs.ReadFile("/big")
			if err != nil {
				b.Fatal(err)
			}
			_ = data[66<<20 : 67<<20]
		}
	})
}

// FuzzOpenFileRuns: whatever runlist, size and window a hostile image gives, a
// ReadAt answers or fails; it does not panic, wrap an offset or read outside
// the image.
func FuzzOpenFileRuns(f *testing.F) {
	f.Add(int64(1), int64(10), false, int64(2), int64(5), true, uint64(60000), uint64(0), uint16(64))
	f.Add(int64(1<<62), int64(1<<62), false, int64(-1), int64(1), false, uint64(1<<63), uint64(1<<62), uint16(9))
	f.Fuzz(func(t *testing.T, l1, s1 int64, sp1 bool, l2, s2 int64, sp2 bool, size, off uint64, n uint16) {
		r := &realNTFS{f: &memDisk{data: make([]byte, 1<<20)}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 8}}
		file, err := r.openAttr(&attribute{typeCode: attrData, nonResident: true, realSize: size,
			runs: []dataRun{{lengthClusters: l1, startCluster: s1, sparse: sp1}, {lengthClusters: l2, startCluster: s2, sparse: sp2}}})
		if err != nil {
			return
		}
		_, _ = file.ReadAt(make([]byte, int(n)), int64(off%(1<<30)))
	})
}
