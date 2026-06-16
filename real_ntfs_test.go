package filesystem_ntfs

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"unicode/utf16"
)

// This file hand-crafts a minimal but genuine on-disk NTFS image so the
// real-NTFS reader can be exercised without any external tools. The
// layout is deliberately tiny:
//
//	cluster size      = 512 bytes (1 sector/cluster, 512 bytes/sector)
//	MFT record size   = 1024 bytes (clusters-per-record = -10 => 2^10)
//	$MFT $DATA        = clusters [4..]  (non-resident, one run)
//	non-resident file = cluster 16      (one run, "non-resident payload")
//
// MFT records used:
//	0  $MFT        (non-resident $DATA describing the MFT region)
//	3  $Volume     ($VOLUME_NAME = "SYNTHVOL")
//	5  .           root directory, $INDEX_ROOT listing "dir" and "hello.txt"
//	24 hello.txt   resident $DATA
//	25 dir         directory, $INDEX_ROOT listing "big.bin"
//	26 big.bin     non-resident $DATA (runlist)

const (
	tBytesPerSector = 512
	tSecPerCluster  = 1
	tClusterSize    = tBytesPerSector * tSecPerCluster
	tMFTRecordSize  = 1024
	tMFTCluster     = 4 // where $MFT (record 0) begins

	tRecMFT    = 0
	tRecVolume = 3
	tRecRoot   = 5
	tRecHello  = 24
	tRecDir    = 25
	tRecBig    = 26

	tBigCluster = 16 // LCN of the non-resident file's single run
)

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

// attrBuilder accumulates attribute records for one FILE record.
type attrBuilder struct {
	buf bytes.Buffer
}

// addResident appends a resident attribute with an optional name.
func (ab *attrBuilder) addResident(typeCode uint32, name string, content []byte) {
	nameBytes := utf16le(name)
	nameLen := byte(len(nameBytes) / 2)
	// Header is 0x18 bytes for resident attrs (no padding/name here when
	// nameLen==0; when named, the name follows the header).
	headerLen := 0x18
	nameOff := headerLen
	contentOff := headerLen + len(nameBytes)
	// align content to 8 bytes
	if pad := contentOff % 8; pad != 0 {
		contentOff += 8 - pad
	}
	total := contentOff + len(content)
	if pad := total % 8; pad != 0 {
		total += 8 - pad
	}
	rec := make([]byte, total)
	binary.LittleEndian.PutUint32(rec[0x00:], typeCode)
	binary.LittleEndian.PutUint32(rec[0x04:], uint32(total))
	rec[0x08] = 0 // resident
	rec[0x09] = nameLen
	binary.LittleEndian.PutUint16(rec[0x0A:], uint16(nameOff))
	binary.LittleEndian.PutUint32(rec[0x10:], uint32(len(content)))
	binary.LittleEndian.PutUint16(rec[0x14:], uint16(contentOff))
	copy(rec[nameOff:], nameBytes)
	copy(rec[contentOff:], content)
	ab.buf.Write(rec)
}

// addNonResident appends a non-resident attribute carrying a runlist.
func (ab *attrBuilder) addNonResident(typeCode uint32, name string, realSize uint64, runlist []byte) {
	nameBytes := utf16le(name)
	nameLen := byte(len(nameBytes) / 2)
	headerLen := 0x40
	nameOff := headerLen
	runOff := headerLen + len(nameBytes)
	if pad := runOff % 8; pad != 0 {
		runOff += 8 - pad
	}
	total := runOff + len(runlist)
	if pad := total % 8; pad != 0 {
		total += 8 - pad
	}
	rec := make([]byte, total)
	binary.LittleEndian.PutUint32(rec[0x00:], typeCode)
	binary.LittleEndian.PutUint32(rec[0x04:], uint32(total))
	rec[0x08] = 1 // non-resident
	rec[0x09] = nameLen
	binary.LittleEndian.PutUint16(rec[0x0A:], uint16(nameOff))
	// starting/ending VCN left zero (not used by the reader)
	binary.LittleEndian.PutUint16(rec[0x20:], uint16(runOff))
	binary.LittleEndian.PutUint64(rec[0x28:], realSize) // allocated size (approx)
	binary.LittleEndian.PutUint64(rec[0x30:], realSize) // real size
	binary.LittleEndian.PutUint64(rec[0x38:], realSize) // initialized size
	copy(rec[nameOff:], nameBytes)
	copy(rec[runOff:], runlist)
	ab.buf.Write(rec)
}

// finish renders the attribute stream plus the 0xFFFFFFFF terminator.
func (ab *attrBuilder) finish() []byte {
	out := append([]byte(nil), ab.buf.Bytes()...)
	term := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	out = append(out, term...)
	return out
}

// buildFileRecord assembles a 1024-byte FILE record with the USA fixup
// applied across its two 512-byte sectors.
func buildFileRecord(isDir bool, attrs []byte) []byte {
	rec := make([]byte, tMFTRecordSize)
	copy(rec[0:], "FILE")
	usaOffset := 0x30
	usaCount := tMFTRecordSize/tBytesPerSector + 1 // 1 USN + 2 sectors = 3
	binary.LittleEndian.PutUint16(rec[0x04:], uint16(usaOffset))
	binary.LittleEndian.PutUint16(rec[0x06:], uint16(usaCount))
	attrStart := 0x38 // after the USA (0x30 + 3*2 = 0x36, round up to 8)
	binary.LittleEndian.PutUint16(rec[0x14:], uint16(attrStart))
	flags := uint16(fileRecordInUse)
	if isDir {
		flags |= fileRecordDirectory
	}
	binary.LittleEndian.PutUint16(rec[0x16:], flags)
	binary.LittleEndian.PutUint32(rec[0x18:], uint32(attrStart+len(attrs))) // used size
	binary.LittleEndian.PutUint32(rec[0x1C:], tMFTRecordSize)               // allocated size
	copy(rec[attrStart:], attrs)

	// Apply the USA fixup: write a USN, stash the real last 2 bytes of
	// each sector into the USA, and overwrite the sector tails with USN.
	usn := []byte{0x01, 0x00}
	rec[usaOffset] = usn[0]
	rec[usaOffset+1] = usn[1]
	for i := 0; i < usaCount-1; i++ {
		sectorEnd := (i + 1) * tBytesPerSector
		// save original tail into USA
		rec[usaOffset+2+i*2] = rec[sectorEnd-2]
		rec[usaOffset+2+i*2+1] = rec[sectorEnd-1]
		// write USN into the tail
		rec[sectorEnd-2] = usn[0]
		rec[sectorEnd-1] = usn[1]
	}
	return rec
}

// stdInfo returns a minimal $STANDARD_INFORMATION body (48 bytes).
func stdInfo() []byte { return make([]byte, 48) }

// fileNameAttrBody builds a $FILE_NAME attribute body.
func fileNameAttrBody(parentRef uint64, name string, isDir bool) []byte {
	nameBytes := utf16le(name)
	b := make([]byte, 0x42+len(nameBytes))
	// parentRef occupies bits [0..48); sequence number in the top 16.
	binary.LittleEndian.PutUint64(b[0:], parentRef&0x0000FFFFFFFFFFFF)
	if isDir {
		binary.LittleEndian.PutUint32(b[0x38:], 0x10000000) // FILE_ATTRIBUTE directory
	}
	b[0x40] = byte(len(nameBytes) / 2)
	b[0x41] = fileNameNamespaceWin32
	copy(b[0x42:], nameBytes)
	return b
}

// indexEntryBytes builds one INDEX_ENTRY whose key is a $FILE_NAME.
func indexEntryBytes(mftRef uint64, name string, isDir bool) []byte {
	key := fileNameAttrBody(mftRef, name, isDir)
	// INDEX_ENTRY header is 0x10 bytes; key follows; pad to 8.
	entryLen := 0x10 + len(key)
	if pad := entryLen % 8; pad != 0 {
		entryLen += 8 - pad
	}
	e := make([]byte, entryLen)
	binary.LittleEndian.PutUint64(e[0x00:], mftRef&0x0000FFFFFFFFFFFF)
	binary.LittleEndian.PutUint16(e[0x08:], uint16(entryLen))
	binary.LittleEndian.PutUint16(e[0x0A:], uint16(len(key)))
	binary.LittleEndian.PutUint16(e[0x0C:], 0) // flags: not last, no subnode
	copy(e[0x10:], key)
	return e
}

// indexRootBody builds an $INDEX_ROOT attribute body listing children.
func indexRootBody(children []indexEntry) []byte {
	var entries bytes.Buffer
	for _, c := range children {
		entries.Write(indexEntryBytes(c.mftRef, c.name, c.isDir))
	}
	// Terminating "last" entry: 0x10-byte header with the last flag set.
	last := make([]byte, 0x10)
	binary.LittleEndian.PutUint16(last[0x08:], 0x10)
	binary.LittleEndian.PutUint16(last[0x0C:], indexEntryLast)
	entries.Write(last)

	entriesBytes := entries.Bytes()

	// INDEX_ROOT header (0x10) + INDEX_HEADER (0x10) + entries.
	body := make([]byte, 0x20+len(entriesBytes))
	binary.LittleEndian.PutUint32(body[0x00:], attrFileName) // attribute type indexed
	binary.LittleEndian.PutUint32(body[0x04:], 1)            // collation: filename
	binary.LittleEndian.PutUint32(body[0x08:], 4096)         // index block size
	body[0x0C] = 1                                           // clusters per index block
	// INDEX_HEADER at 0x10:
	ih := body[0x10:]
	binary.LittleEndian.PutUint32(ih[0x00:], 0x10)                           // entries start (relative to INDEX_HEADER)
	binary.LittleEndian.PutUint32(ih[0x04:], uint32(0x10+len(entriesBytes))) // total used
	binary.LittleEndian.PutUint32(ih[0x08:], uint32(0x10+len(entriesBytes))) // allocated
	binary.LittleEndian.PutUint32(ih[0x0C:], 0)                              // flags: small index (no allocation)
	copy(ih[0x10:], entriesBytes)
	return body
}

// runlist encodes a single non-sparse run: length clusters at startLCN.
func runlistSingle(lengthClusters, startLCN int64) []byte {
	// length byte count
	lb := minBytes(uint64(lengthClusters))
	ob := minBytesSigned(startLCN)
	header := byte(lb) | byte(ob<<4)
	out := []byte{header}
	out = appendLE(out, uint64(lengthClusters), lb)
	out = appendLE(out, uint64(startLCN), ob)
	out = append(out, 0) // terminator
	return out
}

func minBytes(v uint64) int {
	n := 1
	for v >>= 8; v != 0; v >>= 8 {
		n++
	}
	return n
}

func minBytesSigned(v int64) int {
	// pick enough bytes that the sign bit is preserved
	for n := 1; n < 8; n++ {
		shift := uint(8*n - 1)
		lo := int64(-1) << shift
		hi := (int64(1) << shift) - 1
		if v >= lo && v <= hi {
			return n
		}
	}
	return 8
}

func appendLE(b []byte, v uint64, n int) []byte {
	for i := 0; i < n; i++ {
		b = append(b, byte(v>>(8*uint(i))))
	}
	return b
}

// buildSyntheticNTFS writes a minimal real-NTFS image to path.
func buildSyntheticNTFS(t *testing.T, path string) {
	t.Helper()

	// Image must be large enough to hold the boot sector, the MFT region
	// and the non-resident file's cluster. 64 clusters * 512 = 32 KiB.
	const totalClusters = 64
	img := make([]byte, totalClusters*tClusterSize)

	// ---- boot sector ----
	bs := img[0:512]
	copy(bs[3:], "NTFS    ")
	binary.LittleEndian.PutUint16(bs[0x0B:], tBytesPerSector)
	bs[0x0D] = tSecPerCluster
	binary.LittleEndian.PutUint64(bs[0x30:], tMFTCluster)
	negTen := int8(-10)
	bs[0x40] = byte(negTen) // 2^10 = 1024-byte MFT records
	bs[0x44] = 1            // 1 cluster per index record (unused in small dirs)
	binary.LittleEndian.PutUint16(bs[510:], bootSignature)

	// ---- build FILE records ----
	mftOffset := int64(tMFTCluster) * tClusterSize

	writeRec := func(recNo int, rec []byte) {
		off := mftOffset + int64(recNo)*tMFTRecordSize
		copy(img[off:], rec)
	}

	// $MFT (record 0): non-resident $DATA covering enough clusters to
	// hold all our records. We place the whole MFT in one run starting at
	// tMFTCluster. 27 records * 1024 = ~27 KiB => 54 clusters; allocate 60.
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "$MFT", false))
		const mftClusters = 60
		rl := runlistSingle(mftClusters, tMFTCluster)
		ab.addNonResident(attrData, "", mftClusters*tClusterSize, rl)
		writeRec(tRecMFT, buildFileRecord(false, ab.finish()))
	}

	// $Volume (record 3): $VOLUME_NAME = "SYNTHVOL".
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		const attrVolumeName = 0x60
		ab.addResident(attrVolumeName, "", utf16le("SYNTHVOL"))
		writeRec(tRecVolume, buildFileRecord(false, ab.finish()))
	}

	// Root directory (record 5): lists "hello.txt" and "dir".
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, ".", true))
		children := []indexEntry{
			{mftRef: tRecHello, name: "hello.txt", isDir: false},
			{mftRef: tRecDir, name: "dir", isDir: true},
		}
		ab.addResident(attrIndexRoot, "$I30", indexRootBody(children))
		writeRec(tRecRoot, buildFileRecord(true, ab.finish()))
	}

	// hello.txt (record 24): resident $DATA.
	helloData := []byte("hello real ntfs")
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "hello.txt", false))
		ab.addResident(attrData, "", helloData)
		writeRec(tRecHello, buildFileRecord(false, ab.finish()))
	}

	// dir (record 25): directory listing "big.bin".
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "dir", true))
		children := []indexEntry{
			{mftRef: tRecBig, name: "big.bin", isDir: false},
		}
		ab.addResident(attrIndexRoot, "$I30", indexRootBody(children))
		writeRec(tRecDir, buildFileRecord(true, ab.finish()))
	}

	// big.bin (record 26): non-resident $DATA pointing at tBigCluster.
	bigData := bytes.Repeat([]byte("ABCD"), 100) // 400 bytes
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecDir, "big.bin", false))
		rl := runlistSingle(1, tBigCluster) // 1 cluster (512 bytes) holds 400 bytes
		ab.addNonResident(attrData, "", uint64(len(bigData)), rl)
		writeRec(tRecBig, buildFileRecord(false, ab.finish()))
	}
	// place big.bin's data at its cluster
	copy(img[int64(tBigCluster)*tClusterSize:], bigData)

	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}
}

func TestRealNTFS_Detect(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	f, err := os.Open(img)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !looksLikeRealNTFS(f, 0) {
		t.Fatal("synthetic image not detected as real NTFS")
	}
}

func TestRealNTFS_OpenRoutes(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	if _, ok := fs.(*realNTFS); !ok {
		t.Fatalf("Open returned %T, want *realNTFS", fs)
	}
}

func TestRealNTFS_BootParse(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	f, err := os.OpenFile(img, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := openRealNTFS(f, 0)
	if err != nil {
		t.Fatalf("openRealNTFS: %v", err)
	}
	if r.boot.bytesPerSector != tBytesPerSector {
		t.Errorf("bytesPerSector=%d want %d", r.boot.bytesPerSector, tBytesPerSector)
	}
	if r.boot.sectorsPerCluster != tSecPerCluster {
		t.Errorf("sectorsPerCluster=%d want %d", r.boot.sectorsPerCluster, tSecPerCluster)
	}
	if r.boot.mftCluster != tMFTCluster {
		t.Errorf("mftCluster=%d want %d", r.boot.mftCluster, tMFTCluster)
	}
	if r.boot.mftRecordSize != tMFTRecordSize {
		t.Errorf("mftRecordSize=%d want %d", r.boot.mftRecordSize, tMFTRecordSize)
	}
}

func TestRealNTFS_DecodeClustersPerRecord(t *testing.T) {
	if got := decodeClustersPerRecord(-10, 512); got != 1024 {
		t.Errorf("neg form: got %d want 1024", got)
	}
	if got := decodeClustersPerRecord(1, 4096); got != 4096 {
		t.Errorf("pos form: got %d want 4096", got)
	}
	if got := decodeClustersPerRecord(4, 1024); got != 4096 {
		t.Errorf("pos form 4*1024: got %d want 4096", got)
	}
}

func TestRealNTFS_ListRoot(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	entries, err := fs.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir(/): %v", err)
	}
	got := map[string]uint8{}
	for _, e := range entries {
		got[e.Name()] = e.FileType()
	}
	if got["hello.txt"] != 8 {
		t.Errorf("hello.txt type=%d want 8", got["hello.txt"])
	}
	if got["dir"] != 2 {
		t.Errorf("dir type=%d want 2", got["dir"])
	}
	if len(got) != 2 {
		names := make([]string, 0, len(got))
		for n := range got {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Errorf("root entries = %v, want exactly [dir hello.txt]", names)
	}
}

func TestRealNTFS_ReadResidentFile(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	data, err := fs.ReadFile("/hello.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hello real ntfs" {
		t.Errorf("ReadFile = %q want %q", data, "hello real ntfs")
	}
}

func TestRealNTFS_ReadNonResidentFile(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	data, err := fs.ReadFile("/dir/big.bin")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	want := bytes.Repeat([]byte("ABCD"), 100)
	if !bytes.Equal(data, want) {
		t.Errorf("ReadFile len=%d want=%d; firstmismatch", len(data), len(want))
	}
}

func TestRealNTFS_ListSubdir(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	entries, err := fs.ListDir("/dir")
	if err != nil {
		t.Fatalf("ListDir(/dir): %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "big.bin" {
		t.Fatalf("ListDir(/dir) = %+v, want [big.bin]", entries)
	}
}

func TestRealNTFS_Stat(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	st, err := fs.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("Stat(/hello.txt): %v", err)
	}
	if st.Size() != uint64(len("hello real ntfs")) {
		t.Errorf("size=%d want %d", st.Size(), len("hello real ntfs"))
	}
	if st.Mode()&0o170000 != 0o100000 {
		t.Errorf("hello.txt mode=%o want regular file", st.Mode())
	}

	dst, err := fs.Stat("/dir")
	if err != nil {
		t.Fatalf("Stat(/dir): %v", err)
	}
	if dst.Mode()&0o170000 != 0o040000 {
		t.Errorf("dir mode=%o want directory", dst.Mode())
	}
}

func TestRealNTFS_Label(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	r, ok := fs.(*realNTFS)
	if !ok {
		t.Fatalf("not realNTFS")
	}
	if got := r.Label(); got != "SYNTHVOL" {
		t.Errorf("Label = %q want %q", got, "SYNTHVOL")
	}
}

func TestRealNTFS_ReadOnly(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err := fs.WriteFile("/x", []byte("y"), 0o644); err == nil {
		t.Error("WriteFile should fail on read-only real NTFS")
	}
	if err := fs.MkDir("/z", 0o755); err == nil {
		t.Error("MkDir should fail on read-only real NTFS")
	}
}

// TestNTFSIMG1_StillWorks confirms the legacy mock format is untouched:
// a fresh image (no NTFS boot sector) keeps using the NTFSIMG1 driver.
func TestNTFSIMG1_StillWorks(t *testing.T) {
	img := filepath.Join(t.TempDir(), "legacy.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if _, ok := fs.(*ntfsFS); !ok {
		t.Fatalf("legacy image routed to %T, want *ntfsFS", fs)
	}
	if err := fs.WriteFile("/a.txt", []byte("legacy"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := fs.ReadFile("/a.txt")
	if err != nil || string(got) != "legacy" {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}
}

// TestRealNTFS_RunlistDecode unit-tests the data-run decoder directly,
// including a multi-run, relative-offset and sparse case.
func TestRealNTFS_RunlistDecode(t *testing.T) {
	// run1: 0x21 0x18 0x34 0x12  -> length=0x18(24) clusters @ LCN 0x1234
	// run2: 0x11 0x05 0x10       -> length=5 @ LCN 0x1234+0x10
	// run3: 0x01 0x07 (sparse)   -> 7 clusters hole (offBytes==0)
	rl := []byte{0x21, 0x18, 0x34, 0x12, 0x11, 0x05, 0x10, 0x01, 0x07, 0x00}
	runs, err := decodeRunList(rl)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 {
		t.Fatalf("got %d runs want 3", len(runs))
	}
	if runs[0].lengthClusters != 24 || runs[0].startCluster != 0x1234 {
		t.Errorf("run0 = %+v", runs[0])
	}
	if runs[1].lengthClusters != 5 || runs[1].startCluster != 0x1244 {
		t.Errorf("run1 = %+v", runs[1])
	}
	if !runs[2].sparse || runs[2].lengthClusters != 7 {
		t.Errorf("run2 = %+v want sparse len 7", runs[2])
	}
}

// TestRealNTFS_RunlistNegativeDelta checks sign-extension of a negative
// relative LCN offset (the run jumps backwards on disk).
func TestRealNTFS_RunlistNegativeDelta(t *testing.T) {
	// run1: 0x21 0x10 0x00 0x10  -> len 16 @ LCN 0x1000
	// run2: 0x11 0x10 0xF0       -> len 16 @ LCN 0x1000 + (-0x10) = 0xFF0
	rl := []byte{0x21, 0x10, 0x00, 0x10, 0x11, 0x10, 0xF0, 0x00}
	runs, err := decodeRunList(rl)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("got %d runs want 2", len(runs))
	}
	if runs[1].startCluster != 0xFF0 {
		t.Errorf("run1 start = %#x want 0xFF0", runs[1].startCluster)
	}
}

// TestInterop_mkntfs is a skip-gated test that, when mkntfs is on PATH,
// formats a real image and reads a file back through the new reader. It
// never fails the suite when the tool is missing.
func TestInterop_mkntfs(t *testing.T) {
	mkntfs, err := exec.LookPath("mkntfs")
	if err != nil {
		t.Skip("mkntfs not on PATH; skipping interop test")
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "interop.ntfs")
	// 8 MiB image is comfortably above mkntfs's minimum.
	if err := os.Truncate(img, 0); err != nil {
		// create then size
		if f, e := os.Create(img); e == nil {
			f.Close()
		}
	}
	if err := os.Truncate(img, 8*1024*1024); err != nil {
		t.Skipf("cannot size interop image: %v", err)
	}
	cmd := exec.Command(mkntfs, "-F", "-q", "-L", "INTEROP", img)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("mkntfs failed (%v): %s", err, out)
	}
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open mkntfs image: %v", err)
	}
	defer fs.Close()
	r, ok := fs.(*realNTFS)
	if !ok {
		t.Fatalf("mkntfs image routed to %T, want *realNTFS", fs)
	}
	// The root directory must at least be listable.
	if _, err := r.ListDir("/"); err != nil {
		t.Fatalf("ListDir(/) on mkntfs image: %v", err)
	}
	if lbl := r.Label(); lbl != "INTEROP" {
		t.Logf("label = %q (want INTEROP; mkntfs layout may vary)", lbl)
	}
}

// openSynthReader is a helper that builds the synthetic image and returns
// the concrete *realNTFS for white-box assertions.
func openSynthReader(t *testing.T) *realNTFS {
	t.Helper()
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { fs.Close() })
	r, ok := fs.(*realNTFS)
	if !ok {
		t.Fatalf("Open returned %T, want *realNTFS", fs)
	}
	return r
}

// TestRealNTFS_ReadOnlyMethods exercises every mutating / capability
// method on the read-only reader, confirming they all reject the call.
func TestRealNTFS_ReadOnlyMethods(t *testing.T) {
	r := openSynthReader(t)
	checks := map[string]error{
		"WriteFile":  r.WriteFile("/x", []byte("y"), 0o644),
		"MkDir":      r.MkDir("/d", 0o755),
		"DeleteFile": r.DeleteFile("/hello.txt"),
		"DeleteDir":  r.DeleteDir("/dir"),
		"Rename":     r.Rename("/hello.txt", "/h2.txt"),
		"Symlink":    r.Symlink("/hello.txt", "/link"),
		"SetLabel":   r.SetLabel("NEW"),
		"Grow":       r.Grow(1 << 20),
		"Shrink":     r.Shrink(1 << 10),
		"Resize":     r.Resize(1 << 20),
		"Compact":    r.Compact(),
	}
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s: expected read-only error, got nil", name)
		}
	}
}

// TestRealNTFS_CapabilityStubs covers the NTFSIMG1-specific reporting
// methods that return empty results for real NTFS, plus ReadLink.
func TestRealNTFS_CapabilityStubs(t *testing.T) {
	r := openSynthReader(t)
	files, used, fe, tf, lf := r.FragmentationStats()
	if files != 0 || used != 0 || fe != 0 || tf != 0 || lf != 0 {
		t.Errorf("FragmentationStats = %d %d %d %d %d, want all zero", files, used, fe, tf, lf)
	}
	if l := r.Layout(); l != nil {
		t.Errorf("Layout = %v, want nil", l)
	}
	if _, err := r.ReadLink("/hello.txt"); err == nil {
		t.Error("ReadLink: expected error")
	}
}

// TestRealNTFS_ErrorPaths covers not-found and type-mismatch errors.
func TestRealNTFS_ErrorPaths(t *testing.T) {
	r := openSynthReader(t)
	if _, err := r.ReadFile("/nope.txt"); err == nil {
		t.Error("ReadFile(/nope.txt): expected not-found error")
	}
	if _, err := r.ReadFile("/dir"); err == nil {
		t.Error("ReadFile(/dir): expected is-a-directory error")
	}
	if _, err := r.ListDir("/hello.txt"); err == nil {
		t.Error("ListDir(/hello.txt): expected not-a-directory error")
	}
	if _, err := r.ListDir("/nope"); err == nil {
		t.Error("ListDir(/nope): expected not-found error")
	}
	if _, err := r.Stat("/nope"); err == nil {
		t.Error("Stat(/nope): expected not-found error")
	}
}

// TestRealNTFS_NamespaceRank checks the long-name preference ordering.
func TestRealNTFS_NamespaceRank(t *testing.T) {
	if namespaceRank(fileNameNamespaceDOS) <= namespaceRank(fileNameNamespaceWin32) {
		t.Error("DOS namespace should rank worse than Win32")
	}
	if namespaceRank(fileNameNamespacePOSIX) != namespaceRank(fileNameNamespaceWin32) {
		t.Error("POSIX and Win32 should rank equally (both long names)")
	}
	if namespaceRank(99) <= namespaceRank(fileNameNamespaceWin32) {
		t.Error("unknown namespace should rank worse than Win32")
	}
}

// TestRealNTFS_DetectRejectsNonNTFS confirms a non-NTFS first sector is
// not misdetected and that Open routes it to the legacy driver.
func TestRealNTFS_DetectRejectsNonNTFS(t *testing.T) {
	buf := make([]byte, 512)
	copy(buf[3:], "MSDOS5.0")
	binary.LittleEndian.PutUint16(buf[510:], 0xAA55)
	rd := bytes.NewReader(buf)
	if looksLikeRealNTFS(rd, 0) {
		t.Error("MSDOS OEM id misdetected as NTFS")
	}
	// missing boot signature
	copy(buf[3:], "NTFS    ")
	binary.LittleEndian.PutUint16(buf[510:], 0x0000)
	rd = bytes.NewReader(buf)
	if looksLikeRealNTFS(rd, 0) {
		t.Error("missing 0xAA55 signature misdetected as NTFS")
	}
}

// TestReadIntLE checks signed sign-extension at byte boundaries.
func TestReadIntLE(t *testing.T) {
	if got := readIntLE([]byte{0xFF}); got != -1 {
		t.Errorf("readIntLE(0xFF) = %d want -1", got)
	}
	if got := readIntLE([]byte{0x00, 0x80}); got != -32768 {
		t.Errorf("readIntLE(0x0080) = %d want -32768", got)
	}
	if got := readIntLE([]byte{0x7F}); got != 127 {
		t.Errorf("readIntLE(0x7F) = %d want 127", got)
	}
	if got := readIntLE(nil); got != 0 {
		t.Errorf("readIntLE(nil) = %d want 0", got)
	}
}

// buildINDXBlock assembles one 512-byte INDX block holding the given
// children, with the USA fixup applied across its single sector.
func buildINDXBlock(vcn uint64, children []indexEntry) []byte {
	const blkSize = 512
	var entries bytes.Buffer
	for _, c := range children {
		entries.Write(indexEntryBytes(c.mftRef, c.name, c.isDir))
	}
	last := make([]byte, 0x10)
	binary.LittleEndian.PutUint16(last[0x08:], 0x10)
	binary.LittleEndian.PutUint16(last[0x0C:], indexEntryLast)
	entries.Write(last)
	entriesBytes := entries.Bytes()

	blk := make([]byte, blkSize)
	copy(blk[0:], "INDX")
	usaOffset := 0x28
	usaCount := blkSize/tBytesPerSector + 1 // 1 USN + 1 sector = 2
	binary.LittleEndian.PutUint16(blk[0x04:], uint16(usaOffset))
	binary.LittleEndian.PutUint16(blk[0x06:], uint16(usaCount))
	binary.LittleEndian.PutUint64(blk[0x10:], vcn) // this block's VCN
	// INDEX_HEADER at 0x18. The USA occupies 0x28..0x2C (within the
	// INDEX_HEADER region), so the first entry must start past it. We use
	// 0x28 relative to the INDEX_HEADER (absolute 0x40) to clear the USA.
	const firstEntry = 0x28
	ih := blk[0x18:]
	binary.LittleEndian.PutUint32(ih[0x00:], firstEntry) // entries start (relative to 0x18)
	binary.LittleEndian.PutUint32(ih[0x04:], uint32(firstEntry+len(entriesBytes)))
	binary.LittleEndian.PutUint32(ih[0x08:], uint32(blkSize-0x18))
	binary.LittleEndian.PutUint32(ih[0x0C:], 0)
	copy(ih[firstEntry:], entriesBytes)

	// USA fixup over the single sector.
	usn := []byte{0x02, 0x00}
	blk[usaOffset] = usn[0]
	blk[usaOffset+1] = usn[1]
	for i := 0; i < usaCount-1; i++ {
		sectorEnd := (i + 1) * tBytesPerSector
		blk[usaOffset+2+i*2] = blk[sectorEnd-2]
		blk[usaOffset+2+i*2+1] = blk[sectorEnd-1]
		blk[sectorEnd-2] = usn[0]
		blk[sectorEnd-1] = usn[1]
	}
	return blk
}

// buildSyntheticNTFSWithIndexAlloc writes an image whose root directory
// stores its children in a non-resident $INDEX_ALLOCATION (0xA0) INDX
// block rather than inline in $INDEX_ROOT. $INDEX_ROOT carries only the
// "last" entry with the sub-node flag conceptually; the reader reads the
// INDX block for the real entries.
func buildSyntheticNTFSWithIndexAlloc(t *testing.T, path string) {
	t.Helper()
	const totalClusters = 64
	img := make([]byte, totalClusters*tClusterSize)

	bs := img[0:512]
	copy(bs[3:], "NTFS    ")
	binary.LittleEndian.PutUint16(bs[0x0B:], tBytesPerSector)
	bs[0x0D] = tSecPerCluster
	binary.LittleEndian.PutUint64(bs[0x30:], tMFTCluster)
	negTen := int8(-10)
	bs[0x40] = byte(negTen)
	bs[0x44] = 1 // 1 cluster (512 B) per index record
	binary.LittleEndian.PutUint16(bs[510:], bootSignature)

	mftOffset := int64(tMFTCluster) * tClusterSize
	writeRec := func(recNo int, rec []byte) {
		copy(img[mftOffset+int64(recNo)*tMFTRecordSize:], rec)
	}

	// $MFT (record 0).
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "$MFT", false))
		const mftClusters = 60
		ab.addNonResident(attrData, "", mftClusters*tClusterSize, runlistSingle(mftClusters, tMFTCluster))
		writeRec(tRecMFT, buildFileRecord(false, ab.finish()))
	}

	// Root directory (record 5): empty $INDEX_ROOT (only the last entry)
	// plus a non-resident $INDEX_ALLOCATION holding the real entries.
	const indxCluster = 20
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, ".", true))
		// $INDEX_ROOT with no inline children (just the terminating entry).
		ab.addResident(attrIndexRoot, "$I30", indexRootBody(nil))
		// $INDEX_ALLOCATION: one 512-byte INDX block at indxCluster.
		ab.addNonResident(attrIndexAllocation, "$I30", 512, runlistSingle(1, indxCluster))
		writeRec(tRecRoot, buildFileRecord(true, ab.finish()))
	}

	// hello.txt (record 24): resident $DATA, referenced from the INDX block.
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "hello.txt", false))
		ab.addResident(attrData, "", []byte("indexed payload"))
		writeRec(tRecHello, buildFileRecord(false, ab.finish()))
	}

	// The INDX block lists hello.txt.
	indx := buildINDXBlock(0, []indexEntry{
		{mftRef: tRecHello, name: "hello.txt", isDir: false},
	})
	copy(img[int64(indxCluster)*tClusterSize:], indx)

	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}
}

// TestRealNTFS_IndexAllocation verifies directory listing through a
// non-resident $INDEX_ALLOCATION (0xA0) INDX block, including the INDX
// USA fixup.
func TestRealNTFS_IndexAllocation(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth_indx.ntfs")
	buildSyntheticNTFSWithIndexAlloc(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	entries, err := fs.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir(/): %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "hello.txt" {
		t.Fatalf("ListDir(/) = %+v, want [hello.txt] from INDX", entries)
	}
	data, err := fs.ReadFile("/hello.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "indexed payload" {
		t.Errorf("ReadFile = %q want %q", data, "indexed payload")
	}
}

// TestRealNTFS_ParseErrors exercises the malformed-input error paths of
// the low-level parsers using a minimal reader instance.
func TestRealNTFS_ParseErrors(t *testing.T) {
	r := &realNTFS{boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 1, mftRecordSize: 1024}}

	// Short record.
	if _, err := r.parseFileRecord(make([]byte, 8)); err == nil {
		t.Error("parseFileRecord(short): expected error")
	}
	// Bad magic.
	bad := make([]byte, 1024)
	copy(bad, "XXXX")
	if _, err := r.parseFileRecord(bad); err == nil {
		t.Error("parseFileRecord(bad magic): expected error")
	}

	// applyFixup: out-of-range USA.
	if err := applyFixup(make([]byte, 16), 100, 3, 512); err == nil {
		t.Error("applyFixup(out of range): expected error")
	}
	// applyFixup: USN mismatch in a sector. Set a nonzero USN in the USA
	// but leave the sector tails zero so the check fails.
	buf := make([]byte, 1024)
	buf[0x30] = 0xAB // USN low byte
	buf[0x31] = 0xCD // USN high byte
	if err := applyFixup(buf, 0x30, 3, 512); err == nil {
		t.Error("applyFixup(mismatch): expected error")
	}
	// applyFixup: zero count is a no-op.
	if err := applyFixup(make([]byte, 1024), 0x30, 0, 512); err != nil {
		t.Errorf("applyFixup(count=0): unexpected error %v", err)
	}

	// decodeRunList: truncated run.
	if _, err := decodeRunList([]byte{0x21, 0x18}); err == nil {
		t.Error("decodeRunList(truncated): expected error")
	}
}

// TestRealNTFS_BootInvalid checks parseBoot rejects a zero BPB.
func TestRealNTFS_BootInvalid(t *testing.T) {
	buf := make([]byte, 512)
	copy(buf[3:], "NTFS    ")
	binary.LittleEndian.PutUint16(buf[510:], bootSignature)
	// bytes/sector and sectors/cluster left zero -> invalid.
	r := &realNTFS{f: nopReaderAt(buf)}
	if err := r.parseBoot(); err == nil {
		t.Error("parseBoot(zero BPB): expected error")
	}
}

// TestRealNTFS_MFTOffsetSparseAndOOR covers the sparse-hole and
// out-of-range branches of mftRecordOffset.
func TestRealNTFS_MFTOffsetSparseAndOOR(t *testing.T) {
	r := &realNTFS{boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 1, mftRecordSize: 1024}}
	r.mftRuns = []dataRun{{lengthClusters: 2, sparse: true, startCluster: -1}}
	if _, ok := r.mftRecordOffset(0); ok {
		t.Error("mftRecordOffset over sparse run should be unreachable")
	}
	// record beyond the runlist
	r.mftRuns = []dataRun{{lengthClusters: 1, startCluster: 4}}
	if _, ok := r.mftRecordOffset(100); ok {
		t.Error("mftRecordOffset beyond runlist should be unreachable")
	}
}

// nopReaderAt adapts a byte slice to diskRW for parser unit tests; only
// ReadAt is meaningful.
type nopReaderAt []byte

func (b nopReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, nil
	}
	n := copy(p, b[off:])
	return n, nil
}
func (b nopReaderAt) WriteAt(p []byte, off int64) (int, error) { return len(p), nil }
func (b nopReaderAt) Close() error                             { return nil }
