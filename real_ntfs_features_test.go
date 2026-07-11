// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) the go-filesystems/ntfs authors

package filesystem_ntfs

// CI-portable synthetic tests for the on-disk feature extensions (LZNT1
// compression, sparse data, named streams, attribute lists and IntxLNK
// symlinks). These hand-craft genuine on-disk structures and read them back,
// so they run everywhere; the ntfs-3g gold tests in real_ntfs_interop_test.go
// independently confirm the decoders against a real NTFS implementation.

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// ---- test-side LZNT1 compressor (mirrors the decoder in the package) ----

// lznt1CompressForTest produces a valid LZNT1 stream for data. Compressible
// blocks are emitted as token chunks; blocks that would not shrink are emitted
// as uncompressed chunks (also exercising the decoder's raw-chunk path).
func lznt1CompressForTest(data []byte) []byte {
	var out []byte
	for start := 0; start < len(data); start += lznt1ChunkSize {
		end := start + lznt1ChunkSize
		if end > len(data) {
			end = len(data)
		}
		block := data[start:end]
		comp := lznt1CompressBlock(block)
		var h [2]byte
		if len(comp) < len(block) {
			binary.LittleEndian.PutUint16(h[:], uint16(len(comp)-1)|0x8000|0x3000)
			out = append(out, h[:]...)
			out = append(out, comp...)
		} else {
			// Store the block verbatim in an uncompressed chunk.
			binary.LittleEndian.PutUint16(h[:], uint16(len(block)-1)|0x3000)
			out = append(out, h[:]...)
			out = append(out, block...)
		}
	}
	return out
}

// lznt1CompressBlock greedily compresses one <=4096-byte block into an LZNT1
// token stream using the same field-width rule as lznt1DecodeChunk.
func lznt1CompressBlock(block []byte) []byte {
	var out []byte
	i := 0
	for i < len(block) {
		flagPos := len(out)
		out = append(out, 0)
		var flags byte
		for bit := 0; bit < 8 && i < len(block); bit++ {
			bestLen, bestOff := 0, 0
			if i > 0 {
				offBits := lznt1OffsetBits(i)
				lenBits := 16 - offBits
				maxLen := (1 << uint(lenBits)) + 2
				maxOff := 1 << uint(offBits)
				if maxOff > i {
					maxOff = i
				}
				for off := 1; off <= maxOff; off++ {
					l := 0
					for i+l < len(block) && l < maxLen && block[i-off+l] == block[i+l] {
						l++
					}
					if l >= 3 && l > bestLen {
						bestLen, bestOff = l, off
					}
				}
			}
			if bestLen >= 3 {
				flags |= 1 << uint(bit)
				offBits := lznt1OffsetBits(i)
				lenBits := 16 - offBits
				token := uint16((bestOff-1)<<uint(lenBits)) | uint16(bestLen-3)
				var tb [2]byte
				binary.LittleEndian.PutUint16(tb[:], token)
				out = append(out, tb[:]...)
				i += bestLen
			} else {
				out = append(out, block[i])
				i++
			}
		}
		out[flagPos] = flags
	}
	return out
}

func TestLZNT1_RoundTrip_TestCompressor(t *testing.T) {
	inputs := [][]byte{
		bytes.Repeat([]byte("ABCD"), 2000),                         // highly compressible
		[]byte("The quick brown fox jumps over the lazy dog.\n"),   // short
		append(bytes.Repeat([]byte("x"), 5000), []byte("tail")...), // run + literal tail
		{},            // empty
		[]byte("abc"), // below match length
	}
	for i, in := range inputs {
		comp := lznt1CompressForTest(in)
		got, err := lznt1Decompress(comp, len(in)+lznt1ChunkSize)
		if err != nil {
			t.Fatalf("case %d: decompress: %v", i, err)
		}
		if !bytes.Equal(got, in) {
			t.Fatalf("case %d: round-trip mismatch\n got %q\nwant %q", i, got, in)
		}
	}
}

func TestLZNT1_Errors(t *testing.T) {
	// End-of-stream: a zero header terminates cleanly.
	if b, err := lznt1Decompress([]byte{0x00, 0x00, 0x11}, 16); err != nil || len(b) != 0 {
		t.Fatalf("zero header: b=%v err=%v", b, err)
	}
	// Uncompressed chunk that overflows the unit ceiling.
	raw := lznt1CompressForTest(bytes.Repeat([]byte{0xAB}, 100)) // stored verbatim
	if _, err := lznt1Decompress(raw, 10); err == nil {
		t.Fatal("expected overflow error for tiny maxOut (uncompressed)")
	}
	// Compressed chunk that overflows the unit ceiling on a back-reference.
	comp := lznt1CompressForTest(bytes.Repeat([]byte("ABCD"), 2000))
	if _, err := lznt1Decompress(comp, 8); err == nil {
		t.Fatal("expected overflow error for tiny maxOut (compressed)")
	}
	// A compressed chunk whose first token is a back-reference (invalid: no
	// prior output) must error. header: compressed, len=3; flag=0x01 (token),
	// token bytes 0,0.
	bad := []byte{0x03, 0x80 | 0x30, 0x01, 0x00, 0x00}
	if _, err := lznt1Decompress(bad, 4096); err == nil {
		t.Fatal("expected back-reference-at-start error")
	}
	// Trailing partial token (flag says token but only 1 byte follows) stops
	// cleanly after emitting the earlier literal.
	partial := []byte{0x03, 0x80 | 0x30, 0x01, 0x41} // flag=literal? bit0=1 -> token, but <2 bytes
	if _, err := lznt1Decompress(partial, 4096); err != nil {
		t.Fatalf("partial token should stop cleanly: %v", err)
	}
}

func TestLZNT1_OffsetBits(t *testing.T) {
	cases := map[int]int{1: 4, 16: 4, 17: 5, 32: 5, 33: 6, 4096: 12, 4097: 12}
	for pos, want := range cases {
		if got := lznt1OffsetBits(pos); got != want {
			t.Errorf("lznt1OffsetBits(%d) = %d, want %d", pos, got, want)
		}
	}
}

func TestLZNT1_BackrefOffsetPast(t *testing.T) {
	// Two literals produced, then a token whose offset (from high bits) points
	// before the block. flags 0x04 => item0,1 literal, item2 token. With pos=2,
	// offBits=4, a token high nibble 0xF -> offset 16 > 2 -> error.
	// header 0xB004: compressed, chunkLen 5.
	blk := []byte{0x04, 0xB0, 0x04, 0x41, 0x42, 0x00, 0xF0}
	if _, err := lznt1Decompress(blk, 4096); err == nil {
		t.Fatal("expected offset-past-block error")
	}
	// Uncompressed chunk that overflows maxOut. header 0x3004: raw, chunkLen 5.
	raw := []byte{0x04, 0x30, 0x41, 0x42, 0x43, 0x44, 0x45}
	if _, err := lznt1Decompress(raw, 2); err == nil {
		t.Fatal("expected uncompressed-chunk overflow error")
	}
	// An attribute-list body that opens with the 0xFFFFFFFF end marker.
	if e, err := parseAttrList([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil || len(e) != 0 {
		t.Fatalf("attrEnd-first: e=%d err=%v", len(e), err)
	}
}

// ---- runlist encoder (inverse of decodeRunList) ----

type trun struct {
	length int64
	lcn    int64
	sparse bool
}

func encodeRunlist(runs []trun) []byte {
	var out []byte
	var prev int64
	for _, r := range runs {
		lb := minBytes(uint64(r.length))
		if r.sparse {
			out = append(out, byte(lb))
			out = appendLE(out, uint64(r.length), lb)
			continue
		}
		delta := r.lcn - prev
		ob := minBytesSigned(delta)
		out = append(out, byte(lb)|byte(ob<<4))
		out = appendLE(out, uint64(r.length), lb)
		out = appendLE(out, uint64(delta), ob)
		prev = r.lcn
	}
	return append(out, 0)
}

// ---- flexible synthetic image assembler ----

const fMFTClusters = 60 // MFT region spans clusters [tMFTCluster, +fMFTClusters)

// assemble builds a real-NTFS image: boot sector, $MFT (record 0), $Volume
// (record 3), a root directory (record 5) listing rootChildren, plus the
// caller's file records and scattered data clusters. dataAt maps an LCN to the
// bytes placed at that cluster.
func assemble(t *testing.T, totalClusters int, records map[int][]byte, rootChildren []indexEntry, dataAt map[int64][]byte) string {
	t.Helper()
	img := make([]byte, totalClusters*tClusterSize)

	bs := img[0:512]
	copy(bs[3:], "NTFS    ")
	binary.LittleEndian.PutUint16(bs[0x0B:], tBytesPerSector)
	bs[0x0D] = tSecPerCluster
	binary.LittleEndian.PutUint64(bs[0x30:], tMFTCluster)
	negTen := int8(-10)
	bs[0x40] = byte(negTen) // 1024-byte MFT records
	bs[0x44] = 1
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
		ab.addNonResident(attrData, "", fMFTClusters*tClusterSize, runlistSingle(fMFTClusters, tMFTCluster))
		writeRec(tRecMFT, buildFileRecord(false, ab.finish()))
	}
	// $Volume (record 3).
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(0x60, "", utf16le("FEATVOL"))
		writeRec(tRecVolume, buildFileRecord(false, ab.finish()))
	}
	// Root directory (record 5).
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, ".", true))
		ab.addResident(attrIndexRoot, "$I30", indexRootBody(rootChildren))
		writeRec(tRecRoot, buildFileRecord(true, ab.finish()))
	}
	for recNo, rec := range records {
		writeRec(recNo, rec)
	}
	for lcn, data := range dataAt {
		copy(img[lcn*tClusterSize:], data)
	}
	path := filepath.Join(t.TempDir(), "feat.ntfs")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}
	return path
}

// addNonResidentEx appends a non-resident attribute with explicit flags,
// compression unit and starting VCN (extends the base helper's zero defaults).
func (ab *attrBuilder) addNonResidentEx(typeCode uint32, name string, realSize uint64, runlist []byte, flags, compUnit uint16, startVCN uint64) {
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
	rec[0x08] = 1
	rec[0x09] = nameLen
	binary.LittleEndian.PutUint16(rec[0x0A:], uint16(nameOff))
	binary.LittleEndian.PutUint16(rec[0x0C:], flags)
	binary.LittleEndian.PutUint64(rec[0x10:], startVCN)
	binary.LittleEndian.PutUint16(rec[0x20:], uint16(runOff))
	binary.LittleEndian.PutUint16(rec[0x22:], compUnit)
	binary.LittleEndian.PutUint64(rec[0x28:], realSize)
	binary.LittleEndian.PutUint64(rec[0x30:], realSize)
	binary.LittleEndian.PutUint64(rec[0x38:], realSize)
	copy(rec[nameOff:], nameBytes)
	copy(rec[runOff:], runlist)
	ab.buf.Write(rec)
}

// layoutCompressed lays out data as a compressed non-resident attribute at the
// given base LCN using compression-unit exponent compUnit. It returns the
// runlist and the per-LCN placements to scatter into the image.
func layoutCompressed(data []byte, compUnit uint16, baseLCN int64) (runlist []byte, dataAt map[int64][]byte) {
	dataAt = map[int64][]byte{}
	unitClusters := int64(1) << compUnit
	unitBytes := unitClusters * tClusterSize
	lcn := baseLCN
	var runs []trun
	for pos := int64(0); pos < int64(len(data)); pos += unitBytes {
		end := pos + unitBytes
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		plain := data[pos:end]
		comp := lznt1CompressForTest(plain)
		allocClusters := int64((len(comp) + tClusterSize - 1) / tClusterSize)
		full := (end-pos == unitBytes)
		if allocClusters >= unitClusters || !full {
			// Store verbatim: whole clusters, no sparse padding.
			nClusters := int64((len(plain) + tClusterSize - 1) / tClusterSize)
			block := make([]byte, nClusters*tClusterSize)
			copy(block, plain)
			for c := int64(0); c < nClusters; c++ {
				dataAt[lcn+c] = block[c*tClusterSize : (c+1)*tClusterSize]
			}
			runs = append(runs, trun{length: nClusters, lcn: lcn})
			lcn += nClusters
		} else {
			block := make([]byte, allocClusters*tClusterSize)
			copy(block, comp)
			for c := int64(0); c < allocClusters; c++ {
				dataAt[lcn+c] = block[c*tClusterSize : (c+1)*tClusterSize]
			}
			runs = append(runs, trun{length: allocClusters, lcn: lcn})
			runs = append(runs, trun{length: unitClusters - allocClusters, sparse: true})
			lcn += allocClusters
		}
	}
	return encodeRunlist(runs), dataAt
}

func TestFeature_CompressedFile(t *testing.T) {
	// ~5 KiB compressible payload -> several compUnit=2 (4-cluster/2 KiB) units,
	// mixing compressed and a partial final unit.
	var buf bytes.Buffer
	for buf.Len() < 5000 {
		buf.WriteString("compress me please, compress me please! ")
	}
	payload := buf.Bytes()
	const compUnit = 2
	rl, dataAt := layoutCompressed(payload, compUnit, 100)

	var ab attrBuilder
	ab.addResident(attrStandardInformation, "", stdInfo())
	ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "comp.txt", false))
	ab.addNonResidentEx(attrData, "", uint64(len(payload)), rl, attrFlagCompressed, compUnit, 0)
	rec := buildFileRecord(false, ab.finish())

	img := assemble(t, 512,
		map[int][]byte{24: rec},
		[]indexEntry{{mftRef: 24, name: "comp.txt"}},
		dataAt)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	got, err := fs.ReadFile("/comp.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("compressed round-trip mismatch: got %d want %d bytes", len(got), len(payload))
	}
	// Stat should report the logical (decompressed) size.
	st, err := fs.Stat("/comp.txt")
	if err != nil || st.Size() != uint64(len(payload)) {
		t.Fatalf("Stat size = %d err=%v, want %d", st.Size(), err, len(payload))
	}
}

func TestFeature_SparseAndZeroUnit(t *testing.T) {
	// A compressed attribute whose first unit is fully sparse (all zeros) and
	// second unit is stored verbatim.
	const compUnit = 2
	unitClusters := int64(1) << compUnit
	unitBytes := unitClusters * tClusterSize
	tail := bytes.Repeat([]byte{0x5A}, int(unitBytes))
	payload := append(make([]byte, unitBytes), tail...) // zeros then 0x5A unit

	// Runs: sparse unit, then verbatim unit at LCN 200.
	runs := []trun{
		{length: unitClusters, sparse: true},
		{length: unitClusters, lcn: 200},
	}
	dataAt := map[int64][]byte{}
	for c := int64(0); c < unitClusters; c++ {
		dataAt[200+c] = tail[c*tClusterSize : (c+1)*tClusterSize]
	}
	var ab attrBuilder
	ab.addResident(attrStandardInformation, "", stdInfo())
	ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "sparse.bin", false))
	ab.addNonResidentEx(attrData, "", uint64(len(payload)), encodeRunlist(runs), attrFlagCompressed, compUnit, 0)
	rec := buildFileRecord(false, ab.finish())

	img := assemble(t, 512,
		map[int][]byte{24: rec},
		[]indexEntry{{mftRef: 24, name: "sparse.bin"}}, dataAt)
	fs, _ := Open(img, 0)
	defer fs.Close()
	got, err := fs.ReadFile("/sparse.bin")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("sparse/zero unit mismatch")
	}
}

func TestFeature_NamedStreams(t *testing.T) {
	base := []byte("default stream")
	adsResident := []byte("resident ADS payload")
	// A compressed named stream.
	var big bytes.Buffer
	for big.Len() < 3000 {
		big.WriteString("named stream compressed content ")
	}
	adsCompPayload := big.Bytes()
	rl, dataAt := layoutCompressed(adsCompPayload, 2, 300)

	var ab attrBuilder
	ab.addResident(attrStandardInformation, "", stdInfo())
	ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "streams.txt", false))
	ab.addResident(attrData, "", base)
	ab.addResident(attrData, "meta", adsResident)
	// A duplicate-named $DATA exercises the ListStreams de-duplication path.
	ab.addResident(attrData, "meta", adsResident)
	ab.addNonResidentEx(attrData, "big", uint64(len(adsCompPayload)), rl, attrFlagCompressed, 2, 0)
	rec := buildFileRecord(false, ab.finish())

	img := assemble(t, 512,
		map[int][]byte{24: rec},
		[]indexEntry{{mftRef: 24, name: "streams.txt"}}, dataAt)
	fs, _ := Open(img, 0)
	defer fs.Close()
	sr, ok := fs.(StreamReader)
	if !ok {
		t.Fatal("not a StreamReader")
	}
	names, err := sr.ListStreams("/streams.txt")
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	want := []string{"", "big", "meta"}
	if len(names) != 3 || names[0] != want[0] || names[1] != want[1] || names[2] != want[2] {
		t.Fatalf("ListStreams = %v, want %v", names, want)
	}
	if b, _ := sr.ReadStream("/streams.txt", ""); !bytes.Equal(b, base) {
		t.Fatalf("default stream = %q", b)
	}
	if b, _ := sr.ReadStream("/streams.txt", "meta"); !bytes.Equal(b, adsResident) {
		t.Fatalf("meta stream = %q", b)
	}
	if b, err := sr.ReadStream("/streams.txt", "big"); err != nil || !bytes.Equal(b, adsCompPayload) {
		t.Fatalf("big stream err=%v len=%d want %d", err, len(b), len(adsCompPayload))
	}
	// Missing stream and missing path error out.
	if _, err := sr.ReadStream("/streams.txt", "nope"); err == nil {
		t.Fatal("expected error for missing stream")
	}
	if _, err := sr.ListStreams("/nope"); err == nil {
		t.Fatal("expected error for missing path")
	}
	if _, err := sr.ReadStream("/nope", ""); err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestFeature_IntxLnkSymlink(t *testing.T) {
	target := "some/dir/target.txt"
	data := append([]byte(intxLnkMagic), utf16le(target)...)

	var ab attrBuilder
	ab.addResident(attrStandardInformation, "", stdInfo())
	ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "link", false))
	ab.addResident(attrData, "", data)
	rec := buildFileRecord(false, ab.finish())

	// A plain file (no IntxLNK marker) for the negative case.
	var ab2 attrBuilder
	ab2.addResident(attrStandardInformation, "", stdInfo())
	ab2.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "plain.txt", false))
	ab2.addResident(attrData, "", []byte("not a link"))
	rec2 := buildFileRecord(false, ab2.finish())

	img := assemble(t, 256,
		map[int][]byte{24: rec, 25: rec2},
		[]indexEntry{{mftRef: 24, name: "link"}, {mftRef: 25, name: "plain.txt"}}, nil)
	fs, _ := Open(img, 0)
	defer fs.Close()
	got, err := fs.ReadLink("/link")
	if err != nil {
		t.Fatalf("ReadLink: %v", err)
	}
	if got != target {
		t.Fatalf("ReadLink = %q, want %q", got, target)
	}
	if _, err := fs.ReadLink("/plain.txt"); err == nil {
		t.Fatal("expected 'not a symlink' for a plain file")
	}
}

// ---- $ATTRIBUTE_LIST ----

func attrListEntryBytes(typeCode uint32, name string, startVCN, baseRef uint64, attrID uint16) []byte {
	nb := utf16le(name)
	recLen := 0x1A + len(nb)
	if pad := recLen % 8; pad != 0 {
		recLen += 8 - pad
	}
	e := make([]byte, recLen)
	binary.LittleEndian.PutUint32(e[0:], typeCode)
	binary.LittleEndian.PutUint16(e[4:], uint16(recLen))
	e[6] = byte(len(nb) / 2)
	e[7] = 0x1A
	binary.LittleEndian.PutUint64(e[8:], startVCN)
	binary.LittleEndian.PutUint64(e[0x10:], baseRef&0x0000FFFFFFFFFFFF)
	binary.LittleEndian.PutUint16(e[0x18:], attrID)
	copy(e[0x1A:], nb)
	return e
}

func TestFeature_AttributeListSplitData(t *testing.T) {
	// A file (record 24) whose $DATA is split across two records: VCN 0 in the
	// base record, VCN 1 in extension record 25. The $ATTRIBUTE_LIST lists all
	// attributes. Each cluster holds a distinct 512-byte payload.
	frag0 := bytes.Repeat([]byte{0xA1}, tClusterSize)
	frag1 := bytes.Repeat([]byte{0xB2}, tClusterSize)
	full := append(append([]byte(nil), frag0...), frag1...)

	var list bytes.Buffer
	list.Write(attrListEntryBytes(attrStandardInformation, "", 0, 24, 0))
	list.Write(attrListEntryBytes(attrFileName, "", 0, 24, 1))
	list.Write(attrListEntryBytes(attrData, "", 0, 24, 2)) // fragment in base
	list.Write(attrListEntryBytes(attrData, "", 1, 25, 3)) // fragment in ext

	var base attrBuilder
	base.addResident(attrStandardInformation, "", stdInfo())
	base.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "split.bin", false))
	base.addResident(attrAttributeList, "", list.Bytes())
	base.addNonResidentEx(attrData, "", uint64(len(full)), encodeRunlist([]trun{{length: 1, lcn: 150}}), 0, 0, 0)
	rec24 := buildFileRecord(false, base.finish())

	var ext attrBuilder
	// Extension record holds the VCN-1 fragment (its own runlist, startVCN 1).
	ext.addNonResidentEx(attrData, "", uint64(len(full)), encodeRunlist([]trun{{length: 1, lcn: 151}}), 0, 0, 1)
	rec25 := buildFileRecord(false, ext.finish())

	img := assemble(t, 256,
		map[int][]byte{24: rec24, 25: rec25},
		[]indexEntry{{mftRef: 24, name: "split.bin"}},
		map[int64][]byte{150: frag0, 151: frag1})
	fs, _ := Open(img, 0)
	defer fs.Close()
	got, err := fs.ReadFile("/split.bin")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, full) {
		t.Fatalf("split $DATA mismatch: got %d bytes", len(got))
	}
}

func TestFeature_ParseAttrList(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(attrListEntryBytes(attrData, "stream", 0, 5, 1))
	entries, err := parseAttrList(buf.Bytes())
	if err != nil {
		t.Fatalf("parseAttrList: %v", err)
	}
	if len(entries) != 1 || entries[0].name != "stream" || entries[0].baseRef != 5 || entries[0].typeCode != attrData {
		t.Fatalf("entries = %+v", entries)
	}
	// End marker (0xFFFFFFFF) terminates.
	term := append(attrListEntryBytes(attrData, "", 0, 5, 1), 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	if e, err := parseAttrList(term); err != nil || len(e) != 1 {
		t.Fatalf("terminator: e=%d err=%v", len(e), err)
	}
	// Bad record length.
	bad := attrListEntryBytes(attrData, "", 0, 5, 1)
	binary.LittleEndian.PutUint16(bad[4:], 0x02) // < 0x1A
	if _, err := parseAttrList(bad); err == nil {
		t.Fatal("expected bad-length error")
	}
}

func TestFeature_MergeAttributes(t *testing.T) {
	// Two non-resident $DATA fragments (out of VCN order) merge into one with
	// runs concatenated in ascending startVCN; a resident $FILE_NAME is kept.
	all := []attribute{
		{typeCode: attrFileName, name: "", residentData: []byte("x")},
		{typeCode: attrData, name: "", nonResident: true, startVCN: 1, realSize: 99, runs: []dataRun{{lengthClusters: 2, startCluster: 20}}},
		{typeCode: attrData, name: "", nonResident: true, startVCN: 0, realSize: 42, runs: []dataRun{{lengthClusters: 1, startCluster: 10}}},
		{typeCode: attrAttributeList, name: "", residentData: []byte("skip")},
	}
	out := mergeAttributes(all)
	var data *attribute
	nFileName := 0
	for i := range out {
		if out[i].typeCode == attrData {
			data = &out[i]
		}
		if out[i].typeCode == attrFileName {
			nFileName++
		}
		if out[i].typeCode == attrAttributeList {
			t.Fatal("attribute list must be dropped from merged set")
		}
	}
	if nFileName != 1 {
		t.Fatalf("resident $FILE_NAME count = %d", nFileName)
	}
	if data == nil || data.realSize != 42 || len(data.runs) != 2 ||
		data.runs[0].startCluster != 10 || data.runs[1].startCluster != 20 {
		t.Fatalf("merged $DATA = %+v", data)
	}
}

func TestFeature_EncryptedRejected(t *testing.T) {
	var ab attrBuilder
	ab.addResident(attrStandardInformation, "", stdInfo())
	ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "secret", false))
	ab.addNonResidentEx(attrData, "", tClusterSize, encodeRunlist([]trun{{length: 1, lcn: 150}}), attrFlagEncrypted, 0, 0)
	rec := buildFileRecord(false, ab.finish())
	img := assemble(t, 256, map[int][]byte{24: rec},
		[]indexEntry{{mftRef: 24, name: "secret"}},
		map[int64][]byte{150: bytes.Repeat([]byte{1}, tClusterSize)})
	fs, _ := Open(img, 0)
	defer fs.Close()
	if _, err := fs.ReadFile("/secret"); err == nil {
		t.Fatal("expected encrypted-data error")
	}
}

func TestFeature_CompressedReadErrors(t *testing.T) {
	r := openSynthReader(t)
	// Invalid compression-unit exponent.
	if _, err := r.readCompressedRuns(nil, 10, 0); err == nil {
		t.Fatal("compUnit 0 should error")
	}
	if _, err := r.readCompressedRuns(nil, 10, 40); err == nil {
		t.Fatal("compUnit 40 should error")
	}
	// A single sparse unit reads back as zeros of the requested size.
	unit := int64(1) << 2
	runs := []dataRun{{lengthClusters: unit, sparse: true, startCluster: -1}}
	b, err := r.readCompressedRuns(runs, uint64(unit*tClusterSize), 2)
	if err != nil {
		t.Fatalf("sparse-only unit: %v", err)
	}
	if !bytes.Equal(b, make([]byte, unit*tClusterSize)) {
		t.Fatal("sparse-only unit should be all zeros")
	}
	// Runlist shorter than declared size: the tail stays zero (loop breaks).
	b, err = r.readCompressedRuns(nil, uint64(unit*tClusterSize), 2)
	if err != nil || !bytes.Equal(b, make([]byte, unit*tClusterSize)) {
		t.Fatalf("empty runlist: b=%d err=%v", len(b), err)
	}
}

func TestFeature_ReadClustersOverflow(t *testing.T) {
	r := openSynthReader(t)
	// A cluster count large enough to overflow the byte-count multiply.
	if _, err := r.readClusters(0, int64(1)<<62); err == nil {
		t.Fatal("expected cluster byte-count overflow")
	}
}
