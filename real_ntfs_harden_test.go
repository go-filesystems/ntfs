package filesystem_ntfs

import (
	"os"
	"testing"
)

// This file security-hardens the real-NTFS reader against malicious or
// corrupt images. Every test here feeds a deliberately malformed structure
// and asserts the reader returns a graceful error instead of panicking,
// reading out of bounds, overflowing an integer into a bad allocation,
// looping forever, or OOMing.
//
// FuzzRealNTFS drives the whole Open path with arbitrary bytes; the named
// regression tests pin the exact vectors from the threat model so they run
// (and are asserted) under a plain `go test` even without the fuzzing
// engine.

// ---- low-level helpers exercised directly ----

// TestHarden_isPowerOfTwo covers the power-of-two predicate used to
// validate bytes-per-sector.
func TestHarden_isPowerOfTwo(t *testing.T) {
	cases := []struct {
		v    uint32
		want bool
	}{
		{0, false}, {1, true}, {2, true}, {3, false}, {512, true},
		{513, false}, {1024, true}, {0xFFFFFFFF, false},
	}
	for _, c := range cases {
		if got := isPowerOfTwo(c.v); got != c.want {
			t.Errorf("isPowerOfTwo(%d) = %v, want %v", c.v, got, c.want)
		}
	}
}

// TestHarden_mulCheck_addCheck covers the overflow-safe arithmetic helpers,
// including the negative-operand and wrap branches.
func TestHarden_mulCheck_addCheck(t *testing.T) {
	maxI := int64(^uint64(0) >> 1)

	mulCases := []struct {
		a, b int64
		want int64
		ok   bool
	}{
		{0, 5, 0, true},
		{5, 0, 0, true},
		{6, 7, 42, true},
		{-1, 4, 0, false},
		{4, -1, 0, false},
		{maxI, 2, 0, false}, // overflow
	}
	for _, c := range mulCases {
		got, ok := mulCheck(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("mulCheck(%d,%d) = (%d,%v), want (%d,%v)", c.a, c.b, got, ok, c.want, c.ok)
		}
	}

	addCases := []struct {
		a, b int64
		want int64
		ok   bool
	}{
		{1, 2, 3, true},
		{maxI, 1, 0, false},       // positive overflow
		{-maxI - 1, -1, 0, false}, // negative overflow
		{10, -3, 7, true},
	}
	for _, c := range addCases {
		got, ok := addCheck(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("addCheck(%d,%d) = (%d,%v), want (%d,%v)", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
}

// TestHarden_decodeClustersPerRecord covers M1/M2: positive multiply
// overflow, the restricted negative-shift window, and the in-range cases.
func TestHarden_decodeClustersPerRecord(t *testing.T) {
	cases := []struct {
		name string
		v    int8
		cs   int64
		want uint32
	}{
		{"neg10 => 1024", -10, 512, 1024},
		{"neg9 => 512", -9, 512, 512},
		{"neg16 => 64KiB", -16, 512, 1 << 16},
		// M2: byte = -31 (the threat-model vector) is outside [9,16] => 0.
		{"neg31 rejected", -31, 512, 0},
		{"neg8 rejected", -8, 512, 0},
		{"neg17 rejected", -17, 512, 0},
		{"positive 1 cluster", 1, 1024, 1024},
		// M1: positive multiply overflow => 0 (caller rejects).
		{"positive overflow", 127, 1 << 40, 0},
	}
	for _, c := range cases {
		if got := decodeClustersPerRecord(c.v, c.cs); got != c.want {
			t.Errorf("%s: decodeClustersPerRecord(%d,%d) = %d, want %d", c.name, c.v, c.cs, got, c.want)
		}
	}
}

// bootSectorBytes builds a 512-byte NTFS boot sector with the given
// geometry so parseBoot can be exercised on hostile values.
func bootSectorBytes(bps uint16, spc byte, mftClus uint64, mftRecByte, idxRecByte int8) []byte {
	bs := make([]byte, 512)
	copy(bs[3:], "NTFS    ")
	leU16(bs[0x0B:], bps)
	bs[0x0D] = spc
	leU64(bs[0x30:], mftClus)
	bs[0x40] = byte(mftRecByte)
	bs[0x44] = byte(idxRecByte)
	leU16(bs[510:], bootSignature)
	return bs
}

func leU16(b []byte, v uint16) { b[0] = byte(v); b[1] = byte(v >> 8) }
func leU64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * uint(i)))
	}
}

// TestHarden_parseBoot covers H4/M1/M2 in parseBoot.
func TestHarden_parseBoot(t *testing.T) {
	cases := []struct {
		name      string
		bps       uint16
		spc       byte
		mftByte   int8
		idxByte   int8
		wantError bool
	}{
		// H4: bytesPerSector = 1 makes sectorEnd-2 negative in applyFixup.
		{"bps=1 rejected", 1, 1, -10, -12, true},
		{"bps=0 rejected", 0, 1, -10, -12, true},
		{"bps non-power-of-two", 513, 1, -10, -12, true},
		{"spc=0 rejected", 512, 0, -10, -12, true},
		// M2: clusters-per-record byte = -31 => huge => rejected (record 0).
		{"mft record byte -31", 512, 1, -31, -12, true},
		// M1/M2: an out-of-window index byte yields 0, which the listDir
		// path treats as "fall back to 4096", so parseBoot accepts it.
		{"index record byte -31 accepted", 512, 1, -10, -31, false},
		// M1: a positive index byte large enough to exceed maxRecordSize
		// (e.g. 8 clusters * a huge cluster) is rejected. Use spc to push
		// the cluster size up: spc=255, bps=512 => cs=130560; byte 9 =>
		// 9*130560 ~= 1.17 MiB > 1 MiB.
		{"index record too large", 512, 0xFF, -10, 9, true},
		// Valid.
		{"valid", 512, 1, -10, -12, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bs := bootSectorBytes(c.bps, c.spc, 4, c.mftByte, c.idxByte)
			r := &realNTFS{f: nopReaderAt(bs)}
			err := r.parseBoot()
			if c.wantError && err == nil {
				t.Fatalf("parseBoot(%s): expected error, got nil", c.name)
			}
			if !c.wantError && err != nil {
				t.Fatalf("parseBoot(%s): unexpected error %v", c.name, err)
			}
		})
	}
}

// TestHarden_parseAttribute_short covers C1: a short attribute buffer must
// not panic on the fixed-offset header reads.
func TestHarden_parseAttribute_short(t *testing.T) {
	r := &realNTFS{boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 1, mftRecordSize: 1024}}

	// recLen < 0x18: resident header read would OOB without the guard.
	for n := 0; n < 0x18; n++ {
		buf := make([]byte, n)
		if _, err := r.parseAttribute(buf); err == nil {
			t.Errorf("parseAttribute(len=%d): expected error", n)
		}
	}

	// Non-resident flag set but buffer shorter than 0x40: the 0x20/0x30
	// reads would OOB without the second guard.
	buf := make([]byte, 0x20)
	buf[8] = 1 // non-resident
	if _, err := r.parseAttribute(buf); err == nil {
		t.Error("parseAttribute(non-resident, len=0x20): expected error")
	}

	// Resident attribute whose content offset/length point out of range.
	buf2 := make([]byte, 0x18)
	buf2[8] = 0                 // resident
	leU16(buf2[0x14:], 0xFFFF)  // content offset way past the buffer
	leU16AsU32(buf2[0x10:], 16) // content length
	if _, err := r.parseAttribute(buf2); err == nil {
		t.Error("parseAttribute(resident OOB content): expected error")
	}
}

func leU16AsU32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// TestHarden_decodeRunList covers H3: an 8-byte run length of 0x7FFF...FF
// and a runlist decoding to a negative start cluster are both rejected.
func TestHarden_decodeRunList(t *testing.T) {
	// header 0x18: 8-byte length, 1-byte offset. Length = 0x7FFFFFFFFFFFFFFF.
	huge := []byte{0x18,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, // length
		0x01, // offset delta
	}
	if _, err := decodeRunList(huge); err == nil {
		t.Error("decodeRunList(0x7FFF... length): expected error")
	}

	// A run whose signed offset delta drives the LCN negative.
	// header 0x11: 1-byte length, 1-byte offset. length=1, delta=-1 (0xFF).
	neg := []byte{0x11, 0x01, 0xFF}
	if _, err := decodeRunList(neg); err == nil {
		t.Error("decodeRunList(negative start cluster): expected error")
	}

	// A length of exactly maxRunLengthClusters+1 (6-byte length field).
	over := []byte{0x16,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x01, // 0x010000000001 > 2^40
		0x01, // offset
	}
	if _, err := decodeRunList(over); err == nil {
		t.Error("decodeRunList(over max length): expected error")
	}

	// A well-formed sparse + normal runlist still decodes.
	ok := []byte{0x01, 0x02, 0x21, 0x04, 0x05, 0x00, 0x00}
	if _, err := decodeRunList(ok); err != nil {
		t.Errorf("decodeRunList(valid): unexpected error %v", err)
	}
}

// TestHarden_readRuns covers H1/H2: a 2^63 realSize must be bounded to a
// graceful error rather than OOMing the host, and run arithmetic must not
// overflow.
func TestHarden_readRuns(t *testing.T) {
	r := &realNTFS{boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 1}}

	// H1: realSize = 2^63 (== MaxInt64+1 as a uint64) is rejected before
	// any make(), so it cannot OOM the host.
	if _, err := r.readRuns(nil, 1<<63); err == nil {
		t.Error("readRuns(size = 2^63): expected error, must not OOM")
	}

	// H1: realSize > MaxInt64 boundary is rejected.
	if _, err := r.readRuns(nil, ^uint64(0)); err == nil {
		t.Error("readRuns(size > MaxInt64): expected error")
	}

	// H1: a large-but-in-int64 realSize with no backing runs is bounded to
	// the (zero) runlist capacity, so it yields an empty buffer, not an OOM.
	out, err := r.readRuns(nil, 1<<40)
	if err != nil {
		t.Errorf("readRuns(large size, no runs): unexpected error %v", err)
	}
	if len(out) != 0 {
		t.Errorf("readRuns(no runs): got %d bytes, want 0", len(out))
	}

	// H1: a run capacity exceeding maxDataSize is rejected before make().
	bigRuns := []dataRun{{lengthClusters: (maxDataSize / 512) + 1024, startCluster: 1}}
	if _, err := r.readRuns(bigRuns, uint64(maxDataSize)+1<<20); err == nil {
		t.Error("readRuns(over maxDataSize): expected error")
	}

	// H2: a run whose lengthClusters*clusterSize overflows int64.
	ovRuns := []dataRun{{lengthClusters: maxRunLengthClusters, startCluster: 1}}
	rBig := &realNTFS{boot: bootSector{bytesPerSector: 1 << 16, sectorsPerCluster: 0xFF}}
	if _, err := rBig.readRuns(ovRuns, 1<<20); err == nil {
		t.Error("readRuns(overflowing run capacity): expected error")
	}
}

// TestHarden_mftRecordOffset covers M4: overflow-safe runlist arithmetic
// and the hostile $MftClusterNumber special-case path.
func TestHarden_mftRecordOffset(t *testing.T) {
	// Special case (mftRuns == nil): a negative-as-int64 $MftClusterNumber
	// must not produce a negative offset.
	r := &realNTFS{boot: bootSector{
		bytesPerSector: 512, sectorsPerCluster: 1, mftRecordSize: 1024,
		mftCluster: ^uint64(0), // -1 as int64
	}}
	if _, ok := r.mftRecordOffset(0); ok {
		t.Error("mftRecordOffset(hostile mftCluster): expected unreachable")
	}

	// Populated runlist whose run length * clusterSize overflows int64.
	r2 := &realNTFS{boot: bootSector{
		bytesPerSector: 1 << 16, sectorsPerCluster: 0xFF, mftRecordSize: 1024,
	}}
	r2.mftRuns = []dataRun{{lengthClusters: maxRunLengthClusters, startCluster: 1}}
	if _, ok := r2.mftRecordOffset(0); ok {
		t.Error("mftRecordOffset(overflowing run length): expected unreachable")
	}

	// Populated runlist whose startCluster * clusterSize overflows once the
	// target lands inside the run.
	r3 := &realNTFS{boot: bootSector{
		bytesPerSector: 1 << 16, sectorsPerCluster: 0xFF, mftRecordSize: 1024,
	}}
	r3.mftRuns = []dataRun{{lengthClusters: 1, startCluster: maxRunLengthClusters}}
	if _, ok := r3.mftRecordOffset(0); ok {
		t.Error("mftRecordOffset(overflowing start cluster): expected unreachable")
	}
}

// TestHarden_readRuns_startOverflow covers the run-start overflow branch:
// a run whose startCluster*clusterSize overflows must error during a copy.
func TestHarden_readRuns_startOverflow(t *testing.T) {
	r := &realNTFS{boot: bootSector{bytesPerSector: 1 << 16, sectorsPerCluster: 0xFF}}
	r.f = nopReaderAt(make([]byte, 4096))
	runs := []dataRun{{lengthClusters: 1, startCluster: maxRunLengthClusters}}
	if _, err := r.readRuns(runs, 64); err == nil {
		t.Error("readRuns(start overflow): expected error")
	}
}

// TestHarden_applyFixup_smallSector covers H4 in applyFixup: a sector that
// ends before its own trailing word must error, not panic.
func TestHarden_applyFixup_smallSector(t *testing.T) {
	buf := make([]byte, 64)
	// usaCount=2 => one sector; bytesPerSector=1 => sectorEnd=1 < 2.
	if err := applyFixup(buf, 0x08, 2, 1); err == nil {
		t.Error("applyFixup(bytesPerSector=1): expected error")
	}
}

// TestHarden_listDir_smallINDX covers C5: an indexRecordSize smaller than
// the INDX header is rejected rather than slicing out of bounds.
func TestHarden_listDir_smallINDX(t *testing.T) {
	r := &realNTFS{boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 1, indexRecordSize: 8}}
	// A directory FILE record with an $INDEX_ROOT and an $INDEX_ALLOCATION
	// whose non-resident data is at least one (too-small) block.
	var ab attrBuilder
	ab.addResident(attrStandardInformation, "", stdInfo())
	ab.addResident(attrIndexRoot, "$I30", indexRootBody(nil))
	// Non-resident $INDEX_ALLOCATION pointing at a run we can satisfy.
	rl := runlistSingle(1, 8)
	ab.addNonResident(attrIndexAllocation, "$I30", 512, rl)
	rec := buildFileRecord(true, ab.finish())

	fr, err := r.parseFileRecord(rec)
	if err != nil {
		t.Fatalf("parseFileRecord: %v", err)
	}
	// Back the run read with a small in-memory disk.
	r.f = nopReaderAt(make([]byte, 64*1024))
	if _, err := r.listDirRecord(fr); err == nil {
		t.Error("listDirRecord(indexRecordSize=8): expected error")
	}
}

// ---- end-to-end fuzz over the Open path ----

// buildSeedImage returns the known-good synthetic image bytes used as a
// fuzz seed (a structurally valid starting point the fuzzer mutates).
func buildSeedImage(t testing.TB) []byte {
	dir := t.TempDir()
	path := dir + "/seed.img"
	buildSyntheticNTFS(t, path)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	return b
}

// FuzzRealNTFS feeds arbitrary bytes through the whole real-NTFS Open and
// read path. The invariant under test is: no input, however malformed,
// may panic, OOB-read, overflow into a bad allocation, loop forever, or
// OOM. All failures must surface as a returned error.
func FuzzRealNTFS(f *testing.F) {
	// Seed with a structurally valid image plus the exact threat-model
	// vectors so they are exercised even under plain `go test`.
	f.Add(buildSeedImage(f))

	// Threat-model vectors as standalone seeds.
	for _, s := range hardenSeeds() {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Guard against pathological allocation from a huge seed: the disk
		// is in-memory so the test itself stays bounded.
		if len(data) > 8<<20 {
			data = data[:8<<20]
		}
		disk := nopReaderAt(data)

		if !looksLikeRealNTFS(disk, 0) {
			return
		}
		r, err := openRealNTFS(disk, 0)
		if err != nil {
			return
		}
		// Drive the read surface; every method must return rather than
		// panic. We ignore the (error) results: correctness here means
		// "did not crash".
		_, _ = r.ReadFile("/")
		_, _ = r.ReadFile("/hello.txt")
		_, _ = r.ListDir("/")
		_, _ = r.ListDir("/dir")
		_, _ = r.Stat("/")
		_ = r.Label()
	})
}

// hardenSeeds returns standalone malformed images encoding each threat-model
// vector, so a plain `go test` run (which executes f.Add seeds once) asserts
// the no-panic invariant against them.
func hardenSeeds() [][]byte {
	var seeds [][]byte

	// bytesPerSector = 1 (H4).
	seeds = append(seeds, bootSectorBytes(1, 1, 4, -10, -12))
	// A signed clusters-per-MFT-record byte of -31 (M2).
	seeds = append(seeds, bootSectorBytes(512, 1, 4, -31, -12))
	// indexRecordSize byte producing 8-byte INDX blocks (C5). -3 => 2^3=8.
	seeds = append(seeds, bootSectorBytes(512, 1, 4, -10, -3))
	// A boot sector with an absurd $MftClusterNumber (offset overflow path).
	seeds = append(seeds, bootSectorBytes(512, 1, ^uint64(0), -10, -12))

	// An otherwise valid boot sector padded to a few KiB so openRealNTFS
	// proceeds into MFT parsing on garbage (drives readFileRecordAt).
	bs := bootSectorBytes(512, 1, 4, -10, -12)
	padded := make([]byte, 16*1024)
	copy(padded, bs)
	seeds = append(seeds, padded)

	return seeds
}
