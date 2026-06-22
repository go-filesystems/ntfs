package filesystem_ntfs

// Real on-disk NTFS reader.
//
// This file implements a *read-only* foundation for genuine NTFS
// volumes, parsed straight off the on-disk structures (boot sector,
// $MFT, FILE records, attributes, runlists and directory indexes). It
// lives ALONGSIDE the legacy NTFSIMG1 mock driver in this package: Open
// sniffs the boot sector and routes real NTFS images here while the
// custom "NTFSIMG1" blob format keeps using the original code path.
//
// What is implemented and verified (see real_ntfs_test.go):
//   - Boot sector / BPB parse (bytes-per-sector, sectors-per-cluster,
//     $MFT cluster, clusters-per-MFT-record incl. the signed/2^-n form,
//     MFT record size).
//   - FILE record parse with update-sequence-array (USA) fixup and an
//     attribute walk.
//   - $STANDARD_INFORMATION (0x10), $FILE_NAME (0x30), resident and
//     non-resident $DATA (0x80) including data-run (runlist) decoding.
//   - Directory listing via $INDEX_ROOT (0x90) and $INDEX_ALLOCATION
//     (0xA0) with the INDX block USA fixup.
//   - ReadFile / ListDir / Stat wired to the above.
//
// What is intentionally NOT implemented here (the reader returns an
// error or an empty result): any write path, $Bitmap accounting,
// attribute lists ($ATTRIBUTE_LIST 0x20) that span multiple FILE
// records, compressed/sparse/encrypted runs, reparse points, and named
// data streams. These are documented as follow-up work.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"unicode/utf16"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-volumes/safeio"
)

const (
	// oemIDOffset is the byte offset of the 8-byte OEM identifier in the
	// boot sector. Real NTFS volumes carry the literal "NTFS    ".
	oemIDOffset = 3
	oemIDNTFS   = "NTFS    "

	// bootSignatureOffset is the offset of the 0xAA55 boot signature.
	bootSignatureOffset = 510
	bootSignature       = 0xAA55

	// Well-known MFT record numbers.
	mftRecordMFT  = 0 // $MFT itself
	mftRecordRoot = 5 // the root directory "."

	// Attribute type codes.
	attrStandardInformation = 0x10
	attrAttributeList       = 0x20
	attrFileName            = 0x30
	attrData                = 0x80
	attrIndexRoot           = 0x90
	attrIndexAllocation     = 0xA0
	attrEnd                 = 0xFFFFFFFF

	// $FILE_NAME namespace values.
	fileNameNamespacePOSIX  = 0
	fileNameNamespaceWin32  = 1
	fileNameNamespaceDOS    = 2
	fileNameNamespaceWinDOS = 3

	// INDEX_ENTRY flags.
	indexEntryHasSubNode = 0x01
	indexEntryLast       = 0x02

	// FILE record header flags.
	fileRecordInUse     = 0x0001
	fileRecordDirectory = 0x0002

	// Hardening limits for untrusted images. NTFS records are tiny by
	// spec; these ceilings reject malicious geometry before it reaches a
	// make()/slice and turns into an OOM or an out-of-bounds panic.
	//
	// maxRecordSize caps a single MFT FILE record / INDX block. The NTFS
	// spec allows 512B..64KiB; we allow up to 1 MiB of slack and reject
	// anything larger (e.g. the ~2 GiB a signed-shift byte can produce).
	maxRecordSize = 1 << 20 // 1 MiB
	// maxDataSize caps the logical size of any non-resident attribute we
	// will buffer in memory (e.g. a $DATA stream or an $INDEX_ALLOCATION).
	// 1 GiB is far larger than any directory index or metadata stream this
	// read-only foundation legitimately materialises, while still bounding
	// a 2^63 realSize field to a graceful error.
	maxDataSize = 1 << 30 // 1 GiB
	// maxRunLengthClusters bounds the cluster count of a single data run so
	// an 8-byte length field of 0x7FFF...FF cannot drive run arithmetic to
	// overflow or a huge allocation. 2^40 clusters is a petabyte-scale
	// ceiling that no legitimate run reaches.
	maxRunLengthClusters = int64(1) << 40
	// minBytesPerSector is the smallest sane sector size; NTFS uses 512 and
	// up. Anything below this (notably 1, which makes sectorEnd-2 negative)
	// is rejected. The boot field is a uint16 so the value is already
	// bounded above by 64 KiB; we only need a floor plus a power-of-two
	// requirement.
	minBytesPerSector = 512
)

// realErrReadOnly is returned by every mutating method on the real-NTFS
// reader: this foundation is read-only.
var realErrReadOnly = errors.New("ntfs: real-NTFS volumes are read-only in this driver")

// bootSector holds the parsed BIOS Parameter Block fields the reader
// needs. All multi-byte fields are little-endian on disk.
type bootSector struct {
	bytesPerSector    uint32
	sectorsPerCluster uint32
	mftCluster        uint64 // $MftClusterNumber
	mftRecordSize     uint32 // bytes per FILE record
	indexRecordSize   uint32 // bytes per INDX block
}

func (b *bootSector) clusterSize() int64 {
	return int64(b.bytesPerSector) * int64(b.sectorsPerCluster)
}

// realNTFS is the read-only driver for genuine NTFS volumes. It
// satisfies the same FS interface as the legacy ntfsFS so Open can hand
// either back to callers transparently.
type realNTFS struct {
	f          diskRW
	partOffset int64
	boot       bootSector

	// mftRuns is the decoded runlist for $MFT's $DATA, used to map an
	// arbitrary MFT record number to a byte offset even when the MFT is
	// fragmented.
	mftRuns []dataRun
}

var (
	_ filesystem.Filesystem = (*realNTFS)(nil)
	_ FS                    = (*realNTFS)(nil)
)

// dataRun is one extent of a non-resident attribute: lengthClusters
// clusters starting at startCluster. A sparse run has startCluster == -1
// and represents a hole (zeroes).
type dataRun struct {
	lengthClusters int64
	startCluster   int64
	sparse         bool
}

// looksLikeRealNTFS reports whether the first sector at partOffset is a
// real NTFS boot sector (OEM id "NTFS    " plus the 0xAA55 signature).
func looksLikeRealNTFS(f io.ReaderAt, partOffset int64) bool {
	buf := make([]byte, 512)
	if _, err := f.ReadAt(buf, partOffset); err != nil && err != io.EOF {
		return false
	}
	if string(buf[oemIDOffset:oemIDOffset+len(oemIDNTFS)]) != oemIDNTFS {
		return false
	}
	if binary.LittleEndian.Uint16(buf[bootSignatureOffset:]) != bootSignature {
		return false
	}
	return true
}

// openRealNTFS parses the boot sector and $MFT runlist and returns a
// read-only driver. The caller has already verified looksLikeRealNTFS.
func openRealNTFS(f diskRW, partOffset int64) (*realNTFS, error) {
	r := &realNTFS{f: f, partOffset: partOffset}
	if err := r.parseBoot(); err != nil {
		return nil, err
	}
	if err := r.loadMFTRuns(); err != nil {
		return nil, err
	}
	return r, nil
}

// parseBoot decodes the BIOS Parameter Block.
func (r *realNTFS) parseBoot() error {
	buf := make([]byte, 512)
	if _, err := r.f.ReadAt(buf, r.partOffset); err != nil && err != io.EOF {
		return fmt.Errorf("ntfs: read boot sector: %w", err)
	}
	bps := uint32(binary.LittleEndian.Uint16(buf[0x0B:]))
	spc := uint32(buf[0x0D])
	if spc == 0 {
		return fmt.Errorf("ntfs: invalid BPB (bytes/sector=%d sectors/cluster=%d)", bps, spc)
	}
	// H4: a bytes-per-sector value of 0 or 1 makes sectorEnd-2 negative in
	// applyFixup; a non-power-of-two confuses sector arithmetic. Require a
	// power of two in [512, 64KiB].
	if !isPowerOfTwo(bps) || bps < minBytesPerSector {
		return fmt.Errorf("ntfs: invalid bytes-per-sector %d (must be a power of two >= %d)",
			bps, minBytesPerSector)
	}
	mftClus := binary.LittleEndian.Uint64(buf[0x30:])

	b := bootSector{
		bytesPerSector:    bps,
		sectorsPerCluster: spc,
		mftCluster:        mftClus,
	}
	b.mftRecordSize = decodeClustersPerRecord(int8(buf[0x40]), b.clusterSize())
	b.indexRecordSize = decodeClustersPerRecord(int8(buf[0x44]), b.clusterSize())
	// M1: clamp record sizes to a sane ceiling; a signed-shift byte can
	// otherwise produce a ~2 GiB record size that OOMs the make() in
	// readFileRecordAt / the INDX walk.
	if b.mftRecordSize == 0 || b.mftRecordSize > maxRecordSize {
		return fmt.Errorf("ntfs: invalid MFT record size %d", b.mftRecordSize)
	}
	if b.indexRecordSize > maxRecordSize {
		return fmt.Errorf("ntfs: invalid index record size %d", b.indexRecordSize)
	}
	r.boot = b
	return nil
}

// isPowerOfTwo reports whether v is a non-zero power of two.
func isPowerOfTwo(v uint32) bool { return v != 0 && v&(v-1) == 0 }

// decodeClustersPerRecord interprets the signed "clusters per record"
// byte used for both MFT records (0x40) and index records (0x44). A
// positive value is a cluster count; a negative value v means the record
// is 2^(-v) bytes (the common case when a record is smaller than a
// cluster, e.g. -10 => 1024 bytes).
func decodeClustersPerRecord(v int8, clusterSize int64) uint32 {
	if v >= 0 {
		// M1: positive cluster counts are bounded by the caller clamping
		// the result to maxRecordSize, but guard the multiply against
		// overflow so a huge clusterSize cannot wrap into a small value.
		sz := int64(v) * clusterSize
		if clusterSize != 0 && sz/clusterSize != int64(v) {
			return 0 // overflow → rejected by the caller's size check
		}
		if sz < 0 || sz > math.MaxUint32 {
			return 0
		}
		return uint32(sz)
	}
	// M2: a negative byte v means 2^(-v) bytes. Restrict the shift to
	// [9,16] (512 B .. 64 KiB records); anything outside that range (e.g.
	// -31 => 2 GiB) is rejected with a zero the caller treats as invalid.
	shift := -int(v)
	if shift < 9 || shift > 16 {
		return 0
	}
	return uint32(int64(1) << uint(shift))
}

// loadMFTRuns reads MFT record 0 ($MFT) to recover its $DATA runlist so
// the reader can locate any MFT record even on a fragmented volume. $MFT
// record 0 is always at $MftClusterNumber and is self-describing.
func (r *realNTFS) loadMFTRuns() error {
	// A hostile $MftClusterNumber (e.g. 0xFFFF...FF) would make the byte
	// offset negative or overflow; compute it with the same guards
	// mftRecordOffset uses so a corrupt boot sector yields an error rather
	// than a negative ReadAt offset (and a slice-bounds panic).
	off, ok := r.mftRecordOffset(mftRecordMFT)
	if !ok {
		return fmt.Errorf("ntfs: $MFT record offset unreachable")
	}
	rec, err := r.readFileRecordAt(off)
	if err != nil {
		return fmt.Errorf("ntfs: read $MFT record: %w", err)
	}
	for _, a := range rec.attrs {
		if a.typeCode == attrData && a.name == "" {
			if a.nonResident {
				r.mftRuns = a.runs
				return nil
			}
		}
	}
	return fmt.Errorf("ntfs: $MFT has no non-resident $DATA")
}

// mftRecordOffset maps a record number to its absolute byte offset using
// the $MFT runlist. Returns (offset, true) when the record is reachable.
func (r *realNTFS) mftRecordOffset(recNo uint64) (int64, bool) {
	// Bytes into the $MFT $DATA stream where this record begins. recNo and
	// mftRecordSize are both bounded (record size <= 1 MiB), but compute the
	// product overflow-safely anyway.
	target, ok := mulCheck(int64(recNo), int64(r.boot.mftRecordSize))
	if !ok {
		return 0, false
	}
	cs := r.boot.clusterSize()
	// Special-case: before loadMFTRuns populates mftRuns we still need
	// record 0; it sits at mftCluster. A hostile $MftClusterNumber must not
	// produce a negative or overflowing byte offset.
	if r.mftRuns == nil {
		base, ok := mulCheck(int64(r.boot.mftCluster), cs)
		if !ok || int64(r.boot.mftCluster) < 0 {
			return 0, false
		}
		abs, ok := addCheck(base, target)
		if !ok {
			return 0, false
		}
		abs, ok = addCheck(abs, r.partOffset)
		if !ok || abs < 0 {
			return 0, false
		}
		return abs, true
	}
	var streamPos int64 // byte position of the start of the current run
	for _, run := range r.mftRuns {
		// M4: overflow-safe run arithmetic. A malicious $MFT runlist could
		// otherwise drive lengthClusters*cs or startCluster*cs negative and
		// misdirect a record read.
		runBytes, ok := mulCheck(run.lengthClusters, cs)
		if !ok {
			return 0, false
		}
		streamEnd, ok := addCheck(streamPos, runBytes)
		if !ok {
			return 0, false
		}
		if target < streamEnd {
			if run.sparse {
				return 0, false
			}
			within := target - streamPos
			base, ok := mulCheck(run.startCluster, cs)
			if !ok {
				return 0, false
			}
			abs, ok := addCheck(base, within)
			if !ok {
				return 0, false
			}
			abs, ok = addCheck(abs, r.partOffset)
			if !ok || abs < 0 {
				return 0, false
			}
			return abs, true
		}
		streamPos = streamEnd
	}
	return 0, false
}

// mulCheck returns a*b and whether the product fit in int64 without
// overflow (treating a*b as a non-negative byte count: a negative operand
// or a wrapped result reports !ok).
func mulCheck(a, b int64) (int64, bool) {
	if a < 0 || b < 0 {
		return 0, false
	}
	if a == 0 || b == 0 {
		return 0, true
	}
	p := a * b
	if p/b != a || p < 0 {
		return 0, false
	}
	return p, true
}

// addCheck returns a+b and whether the sum fit in int64 without overflow.
func addCheck(a, b int64) (int64, bool) {
	s := a + b
	if (b > 0 && s < a) || (b < 0 && s > a) {
		return 0, false
	}
	return s, true
}

// ---- FILE record parsing ----

type fileRecord struct {
	flags uint16
	attrs []attribute
}

func (fr *fileRecord) isDir() bool { return fr.flags&fileRecordDirectory != 0 }

type attribute struct {
	typeCode    uint32
	name        string
	nonResident bool

	// resident payload
	residentData []byte

	// non-resident payload
	runs     []dataRun
	realSize uint64 // logical data size in bytes
}

// readFileRecordAt reads one FILE record at an absolute byte offset,
// applies the update-sequence-array fixup and parses its attributes.
func (r *realNTFS) readFileRecordAt(off int64) (*fileRecord, error) {
	buf := make([]byte, r.boot.mftRecordSize)
	if _, err := r.f.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, err
	}
	return r.parseFileRecord(buf)
}

// readFileRecord reads MFT record recNo.
func (r *realNTFS) readFileRecord(recNo uint64) (*fileRecord, error) {
	off, ok := r.mftRecordOffset(recNo)
	if !ok {
		return nil, fmt.Errorf("ntfs: MFT record %d unreachable", recNo)
	}
	return r.readFileRecordAt(off)
}

func (r *realNTFS) parseFileRecord(buf []byte) (*fileRecord, error) {
	if len(buf) < 0x30 {
		return nil, fmt.Errorf("ntfs: short FILE record")
	}
	if string(buf[0:4]) != "FILE" {
		return nil, fmt.Errorf("ntfs: bad FILE magic %q", buf[0:4])
	}
	usaOffset := binary.LittleEndian.Uint16(buf[0x04:])
	usaCount := binary.LittleEndian.Uint16(buf[0x06:])
	if err := applyFixup(buf, usaOffset, usaCount, r.boot.bytesPerSector); err != nil {
		return nil, fmt.Errorf("ntfs: FILE fixup: %w", err)
	}

	flags := binary.LittleEndian.Uint16(buf[0x16:])
	firstAttr := binary.LittleEndian.Uint16(buf[0x14:])

	fr := &fileRecord{flags: flags}
	off := int(firstAttr)
	for off+4 <= len(buf) {
		typeCode := binary.LittleEndian.Uint32(buf[off:])
		if typeCode == attrEnd {
			break
		}
		if off+8 > len(buf) {
			break
		}
		recLen := int(binary.LittleEndian.Uint32(buf[off+4:]))
		if recLen <= 0 || off+recLen > len(buf) {
			return nil, fmt.Errorf("ntfs: bad attribute length %d at %d", recLen, off)
		}
		a, err := r.parseAttribute(buf[off : off+recLen])
		if err != nil {
			return nil, err
		}
		fr.attrs = append(fr.attrs, a)
		off += recLen
	}
	return fr, nil
}

// parseAttribute decodes one attribute record (header + body).
func (r *realNTFS) parseAttribute(buf []byte) (attribute, error) {
	var a attribute
	// C1: the fixed-offset reads below (buf[8], buf[10:], buf[0x10:],
	// buf[0x14:]) require a full resident attribute header. The caller only
	// guarantees recLen>0, so a short attribute would panic without this.
	if err := safeio.CheckBounds(0, 0x18, len(buf)); err != nil {
		return a, fmt.Errorf("ntfs: short attribute header: %w", err)
	}
	a.typeCode = binary.LittleEndian.Uint32(buf[0:])
	nonResident := buf[8]
	nameLen := int(buf[9])
	nameOff := int(binary.LittleEndian.Uint16(buf[10:]))
	if nameLen > 0 {
		if name, err := safeio.Slice(buf, nameOff, nameLen*2); err == nil {
			a.name = decodeUTF16(name)
		}
	}
	if nonResident == 0 {
		// Resident attribute.
		contentLen := int(binary.LittleEndian.Uint32(buf[0x10:]))
		contentOff := int(binary.LittleEndian.Uint16(buf[0x14:]))
		content, err := safeio.Slice(buf, contentOff, contentLen)
		if err != nil {
			return a, fmt.Errorf("ntfs: resident attr content out of range: %w", err)
		}
		a.residentData = append([]byte(nil), content...)
		a.realSize = uint64(contentLen)
		return a, nil
	}
	// Non-resident attribute. The runlist-offset (0x20) and real-size
	// (0x30) fields live in the extended (non-resident) header, so require
	// at least 0x40 bytes before reading them.
	if err := safeio.CheckBounds(0, 0x40, len(buf)); err != nil {
		return a, fmt.Errorf("ntfs: short non-resident attribute header: %w", err)
	}
	a.nonResident = true
	a.realSize = binary.LittleEndian.Uint64(buf[0x30:])
	runOff := int(binary.LittleEndian.Uint16(buf[0x20:]))
	runData, err := safeio.Slice(buf, runOff, len(buf)-runOff)
	if err != nil {
		return a, fmt.Errorf("ntfs: bad runlist offset: %w", err)
	}
	runs, err := decodeRunList(runData)
	if err != nil {
		return a, err
	}
	a.runs = runs
	return a, nil
}

// applyFixup performs the NTFS update-sequence-array correction. The
// USA's first word is the update sequence number; the remaining words
// are the original last two bytes of each sector. On disk, the last two
// bytes of every sector in the record hold the USN; this routine
// verifies that and restores the saved bytes.
func applyFixup(buf []byte, usaOffset, usaCount uint16, bytesPerSector uint32) error {
	if usaCount == 0 {
		return nil
	}
	uo := int(usaOffset)
	if err := safeio.CheckBounds(uo, int(usaCount)*2, len(buf)); err != nil {
		return fmt.Errorf("USA out of range: %w", err)
	}
	usn := buf[uo : uo+2]
	sectors := int(usaCount) - 1
	for i := 0; i < sectors; i++ {
		sectorEnd := (i + 1) * int(bytesPerSector)
		// H4: a bytes-per-sector of 0/1 (or any sector ending before its
		// own trailing word) makes sectorEnd-2 negative; reject it rather
		// than panic. parseBoot already enforces bps>=512, but INDX blocks
		// reach here through the same path so keep the guard local.
		if sectorEnd < 2 || sectorEnd > len(buf) {
			return fmt.Errorf("fixup sector %d beyond record", i)
		}
		tail := buf[sectorEnd-2 : sectorEnd]
		if tail[0] != usn[0] || tail[1] != usn[1] {
			return fmt.Errorf("fixup mismatch in sector %d", i)
		}
		saved := buf[uo+2+i*2 : uo+2+i*2+2]
		tail[0] = saved[0]
		tail[1] = saved[1]
	}
	return nil
}

// decodeRunList decodes an NTFS data-run list into extents. Each run
// begins with a header byte: low nibble = byte count of the length
// field, high nibble = byte count of the (signed, relative) offset
// field. A zero header terminates the list. A run with a zero-length
// offset field is sparse (a hole).
func decodeRunList(buf []byte) ([]dataRun, error) {
	var runs []dataRun
	var prevLCN int64
	i := 0
	// A runlist cannot have more runs than it has bytes (each run is at
	// least 2 bytes: a non-zero header + one length byte); bound the walk
	// so a degenerate buffer cannot spin.
	guard := safeio.NewLoopGuard(len(buf) + 1)
	for i < len(buf) {
		if err := guard.Next(); err != nil {
			return nil, fmt.Errorf("ntfs: runlist: %w", err)
		}
		header := buf[i]
		if header == 0 {
			break
		}
		i++
		lenBytes := int(header & 0x0F)
		offBytes := int(header >> 4)
		if lenBytes == 0 || i+lenBytes+offBytes > len(buf) {
			return nil, fmt.Errorf("ntfs: malformed data run")
		}
		length := int64(readUintLE(buf[i : i+lenBytes]))
		i += lenBytes
		// H3: bound the cluster count so an 8-byte length of 0x7FFF...FF
		// cannot feed H1/H2. A negative (top-bit-set) length is also
		// rejected.
		if length < 0 || length > maxRunLengthClusters {
			return nil, fmt.Errorf("ntfs: data run length %d out of range", length)
		}

		run := dataRun{lengthClusters: length}
		if offBytes == 0 {
			run.sparse = true
			run.startCluster = -1
		} else {
			delta := readIntLE(buf[i : i+offBytes])
			i += offBytes
			prevLCN += delta
			// H3: a non-sparse run must reference a non-negative cluster;
			// reject a runlist that decodes to a negative LCN so the
			// startCluster*cs arithmetic downstream stays non-negative.
			if prevLCN < 0 {
				return nil, fmt.Errorf("ntfs: data run negative start cluster %d", prevLCN)
			}
			run.startCluster = prevLCN
		}
		runs = append(runs, run)
	}
	return runs, nil
}

// readUintLE reads up to 8 little-endian bytes as an unsigned integer.
func readUintLE(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// readIntLE reads up to 8 little-endian bytes as a sign-extended signed
// integer (used for run offset deltas, which are relative and signed).
func readIntLE(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var v int64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | int64(b[i])
	}
	// Sign-extend from the top bit of the most significant byte.
	shift := uint(64 - 8*len(b))
	v = (v << shift) >> shift
	return v
}

// decodeUTF16 decodes little-endian UTF-16 bytes to a Go string.
func decodeUTF16(b []byte) string {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// ---- non-resident data reads ----

// readRuns reads logical bytes [0,size) from a runlist. Sparse runs
// yield zeroes. Clusters are read relative to partOffset.
func (r *realNTFS) readRuns(runs []dataRun, size uint64) ([]byte, error) {
	cs := r.boot.clusterSize()
	// H1: bound the requested logical size by both the total capacity the
	// runlist can actually back AND an absolute ceiling, so an attacker's
	// uint64 realSize cannot OOM. Compute the runlist capacity with
	// overflow-safe arithmetic (H2/H3 already bound each run length).
	var capBytes int64
	for _, run := range runs {
		rb, ok := mulCheck(run.lengthClusters, cs)
		if !ok {
			return nil, fmt.Errorf("ntfs: run capacity overflow")
		}
		capBytes, ok = addCheck(capBytes, rb)
		if !ok {
			return nil, fmt.Errorf("ntfs: run capacity overflow")
		}
	}
	// The output is at most the smaller of the declared size and the
	// runlist capacity, and never more than maxDataSize.
	if size > uint64(math.MaxInt64) {
		return nil, fmt.Errorf("ntfs: data size %d too large", size)
	}
	want := int64(size)
	if want > capBytes {
		want = capBytes
	}
	out, err := safeio.MakeBytes(want, maxDataSize)
	if err != nil {
		return nil, fmt.Errorf("ntfs: data buffer: %w", err)
	}
	var pos int64 // logical byte position in the output
	for _, run := range runs {
		if pos >= want {
			break
		}
		// H2: overflow-safe runlist cluster math.
		runBytes, ok := mulCheck(run.lengthClusters, cs)
		if !ok {
			return nil, fmt.Errorf("ntfs: run byte count overflow")
		}
		toCopy := runBytes
		if pos+toCopy > want {
			toCopy = want - pos
		}
		if run.sparse {
			// leave zeroes
			pos += toCopy
			continue
		}
		base, ok := mulCheck(run.startCluster, cs)
		if !ok {
			return nil, fmt.Errorf("ntfs: run start overflow")
		}
		abs, ok := addCheck(base, r.partOffset)
		if !ok || abs < 0 {
			return nil, fmt.Errorf("ntfs: run absolute offset overflow")
		}
		if _, err := r.f.ReadAt(out[pos:pos+toCopy], abs); err != nil && err != io.EOF {
			return nil, err
		}
		pos += toCopy
	}
	return out, nil
}

// dataBytes returns the bytes of the unnamed $DATA attribute of a FILE
// record, handling both resident and non-resident storage.
func (r *realNTFS) dataBytes(fr *fileRecord) ([]byte, bool, error) {
	for _, a := range fr.attrs {
		if a.typeCode != attrData || a.name != "" {
			continue
		}
		if !a.nonResident {
			return a.residentData, true, nil
		}
		b, err := r.readRuns(a.runs, a.realSize)
		if err != nil {
			return nil, true, err
		}
		return b, true, nil
	}
	return nil, false, nil
}

// ---- $FILE_NAME ----

type fileNameAttr struct {
	parentRef uint64 // low 48 bits are the parent MFT record number
	name      string
	namespace byte
}

// parseFileName decodes a $FILE_NAME attribute body.
func parseFileName(b []byte) (fileNameAttr, error) {
	var fn fileNameAttr
	if len(b) < 0x42 {
		return fn, fmt.Errorf("ntfs: short $FILE_NAME")
	}
	fn.parentRef = binary.LittleEndian.Uint64(b[0:]) & 0x0000FFFFFFFFFFFF
	nameLen := int(b[0x40])
	fn.namespace = b[0x41]
	start := 0x42
	if start+nameLen*2 > len(b) {
		return fn, fmt.Errorf("ntfs: $FILE_NAME name out of range")
	}
	fn.name = decodeUTF16(b[start : start+nameLen*2])
	return fn, nil
}

// namespaceRank orders namespaces so the preferred long name wins
// (lower is better). Win32/WinDOS/POSIX outrank a pure DOS alias.
func namespaceRank(ns byte) int {
	switch ns {
	case fileNameNamespaceWin32, fileNameNamespaceWinDOS, fileNameNamespacePOSIX:
		return 0
	case fileNameNamespaceDOS:
		return 2
	default:
		return 1
	}
}

// ---- directory index ----

// indexEntry is one parsed INDEX_ENTRY pointing at a child file.
type indexEntry struct {
	mftRef uint64
	name   string
	ns     byte
	isDir  bool
}

// listDirRecord enumerates the children of a directory FILE record by
// walking $INDEX_ROOT and, when present, $INDEX_ALLOCATION.
func (r *realNTFS) listDirRecord(fr *fileRecord) ([]indexEntry, error) {
	var entries []indexEntry

	// $INDEX_ROOT (0x90), always resident, named "$I30" for directories.
	var rootAttr *attribute
	for i := range fr.attrs {
		if fr.attrs[i].typeCode == attrIndexRoot {
			rootAttr = &fr.attrs[i]
			break
		}
	}
	if rootAttr == nil {
		return entries, nil
	}
	rb := rootAttr.residentData
	if len(rb) < 0x20 {
		return entries, fmt.Errorf("ntfs: short $INDEX_ROOT")
	}
	// INDEX_ROOT header is 0x10 bytes, then an INDEX_HEADER. The first
	// entry offset is relative to the start of the INDEX_HEADER (0x10).
	indexHeader := rb[0x10:]
	firstEntryOff := binary.LittleEndian.Uint32(indexHeader[0x00:])
	rootEntries, err := parseIndexEntries(indexHeader, int(firstEntryOff))
	if err != nil {
		return entries, err
	}
	entries = append(entries, rootEntries...)

	// $INDEX_ALLOCATION (0xA0): non-resident INDX blocks holding the
	// rest of a large directory's entries.
	for i := range fr.attrs {
		if fr.attrs[i].typeCode != attrIndexAllocation {
			continue
		}
		a := &fr.attrs[i]
		raw, err := r.readRuns(a.runs, a.realSize)
		if err != nil {
			return entries, err
		}
		blkSize := int(r.boot.indexRecordSize)
		if blkSize == 0 {
			blkSize = 4096
		}
		// C5: the INDX header read below dereferences blk[0:4] (magic),
		// blk[0x04:]/blk[0x06:] (USA words) and blk[0x18:]+4 (first-entry
		// offset). A small indexRecordSize (e.g. 4 or 8) would make those
		// reads OOB. Require a block large enough to hold the header.
		if blkSize < 0x1C {
			return entries, fmt.Errorf("ntfs: INDX block size %d too small", blkSize)
		}
		for off := 0; off+blkSize <= len(raw); off += blkSize {
			blk := raw[off : off+blkSize]
			if string(blk[0:4]) != "INDX" {
				continue
			}
			usaOff := binary.LittleEndian.Uint16(blk[0x04:])
			usaCnt := binary.LittleEndian.Uint16(blk[0x06:])
			if err := applyFixup(blk, usaOff, usaCnt, r.boot.bytesPerSector); err != nil {
				return entries, fmt.Errorf("ntfs: INDX fixup: %w", err)
			}
			// INDX header: bytes 0x18 begin the INDEX_HEADER. Entry
			// offsets are relative to 0x18 (the blkSize>=0x1C check above
			// guarantees these four bytes are in range).
			ih := blk[0x18:]
			firstOff := binary.LittleEndian.Uint32(ih[0x00:])
			blkEntries, err := parseIndexEntries(ih, int(firstOff))
			if err != nil {
				return entries, err
			}
			entries = append(entries, blkEntries...)
		}
	}
	return entries, nil
}

// parseIndexEntries walks a run of INDEX_ENTRY structures starting at
// firstOff within buf (buf begins at an INDEX_HEADER).
func parseIndexEntries(buf []byte, firstOff int) ([]indexEntry, error) {
	var out []indexEntry
	off := firstOff
	for off+0x10 <= len(buf) {
		mftRef := binary.LittleEndian.Uint64(buf[off:]) & 0x0000FFFFFFFFFFFF
		entryLen := int(binary.LittleEndian.Uint16(buf[off+0x08:]))
		keyLen := int(binary.LittleEndian.Uint16(buf[off+0x0A:]))
		flags := binary.LittleEndian.Uint16(buf[off+0x0C:])
		if flags&indexEntryLast != 0 {
			break
		}
		if entryLen <= 0 || off+entryLen > len(buf) {
			break
		}
		// The key is a $FILE_NAME structure starting at off+0x10.
		if keyLen >= 0x42 && off+0x10+keyLen <= len(buf) {
			fn, err := parseFileName(buf[off+0x10 : off+0x10+keyLen])
			if err == nil {
				// FILE_NAME flags at +0x38 hold the FILE_ATTRIBUTE bits;
				// bit 0x10000000 marks a directory.
				fileAttr := binary.LittleEndian.Uint32(buf[off+0x10+0x38:])
				out = append(out, indexEntry{
					mftRef: mftRef,
					name:   fn.name,
					ns:     fn.namespace,
					isDir:  fileAttr&0x10000000 != 0,
				})
			}
		}
		off += entryLen
	}
	return out, nil
}

// ---- path resolution ----

// resolvePath walks an absolute path from the root directory (record 5)
// and returns the target's MFT record number plus its FILE record.
func (r *realNTFS) resolvePath(p string) (uint64, *fileRecord, error) {
	p = normalizePath(p)
	curNo := uint64(mftRecordRoot)
	cur, err := r.readFileRecord(curNo)
	if err != nil {
		return 0, nil, err
	}
	if p == "/" {
		return curNo, cur, nil
	}
	for _, comp := range strings.Split(strings.Trim(p, "/"), "/") {
		if comp == "" {
			continue
		}
		entries, err := r.listDirRecord(cur)
		if err != nil {
			return 0, nil, err
		}
		var nextNo uint64
		found := false
		for _, e := range entries {
			if e.name == comp {
				nextNo = e.mftRef
				found = true
				break
			}
		}
		if !found {
			return 0, nil, fmt.Errorf("ntfs: %q not found", p)
		}
		curNo = nextNo
		cur, err = r.readFileRecord(curNo)
		if err != nil {
			return 0, nil, err
		}
	}
	return curNo, cur, nil
}

// ---- filesystem.Filesystem (read side) ----

func (r *realNTFS) Close() error { return r.f.Close() }

func (r *realNTFS) ReadFile(p string) ([]byte, error) {
	_, fr, err := r.resolvePath(p)
	if err != nil {
		return nil, err
	}
	if fr.isDir() {
		return nil, fmt.Errorf("ntfs: %q is a directory", p)
	}
	data, ok, err := r.dataBytes(fr)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("ntfs: %q has no $DATA", p)
	}
	return data, nil
}

func (r *realNTFS) ListDir(p string) ([]filesystem.DirEntry, error) {
	_, fr, err := r.resolvePath(p)
	if err != nil {
		return nil, err
	}
	if !fr.isDir() {
		return nil, fmt.Errorf("ntfs: %q is not a directory", p)
	}
	entries, err := r.listDirRecord(fr)
	if err != nil {
		return nil, err
	}
	// Deduplicate by name (a file may appear once per namespace) keeping
	// the preferred long name, and skip the "." self entry.
	byName := map[string]indexEntry{}
	for _, e := range entries {
		if e.name == "." || e.name == "" {
			continue
		}
		prev, ok := byName[e.name]
		if !ok || namespaceRank(e.ns) < namespaceRank(prev.ns) {
			byName[e.name] = e
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]filesystem.DirEntry, 0, len(names))
	for _, n := range names {
		e := byName[n]
		ft := uint8(8) // regular file
		if e.isDir {
			ft = 2 // directory
		}
		out = append(out, filesystem.NewDirEntry(e.mftRef, n, ft))
	}
	return out, nil
}

func (r *realNTFS) Stat(p string) (filesystem.Stat, error) {
	recNo, fr, err := r.resolvePath(p)
	if err != nil {
		return nil, err
	}
	if fr.isDir() {
		return filesystem.NewStat(0o040755, 0, recNo), nil
	}
	var size uint64
	for _, a := range fr.attrs {
		if a.typeCode == attrData && a.name == "" {
			size = a.realSize
			break
		}
	}
	return filesystem.NewStat(0o100644, size, recNo), nil
}

func (r *realNTFS) ReadLink(p string) (string, error) {
	return "", errors.New("ntfs: ReadLink not implemented for real NTFS")
}

// ---- mutating methods: read-only foundation ----

func (r *realNTFS) WriteFile(p string, data []byte, perm os.FileMode) error { return realErrReadOnly }
func (r *realNTFS) MkDir(p string, perm os.FileMode) error                  { return realErrReadOnly }
func (r *realNTFS) DeleteFile(p string) error                               { return realErrReadOnly }
func (r *realNTFS) DeleteDir(p string) error                                { return realErrReadOnly }
func (r *realNTFS) Rename(oldPath, newPath string) error                    { return realErrReadOnly }
func (r *realNTFS) Symlink(target, linkPath string) error                   { return realErrReadOnly }
func (r *realNTFS) SetLabel(label string) error                             { return realErrReadOnly }
func (r *realNTFS) Grow(newSizeBytes int64) error                           { return realErrReadOnly }
func (r *realNTFS) Shrink(newSizeBytes int64) error                         { return realErrReadOnly }
func (r *realNTFS) Resize(newSizeBytes int64) error                         { return realErrReadOnly }

// Compact is a no-op for real NTFS (the NTFSIMG1 in-image compaction has
// no meaning here).
func (r *realNTFS) Compact() error { return realErrReadOnly }

// FragmentationStats / Layout are NTFSIMG1-specific concepts; the real
// reader reports empties rather than fabricating numbers.
func (r *realNTFS) FragmentationStats() (files int, used uint64, freeExtents int, totalFree uint64, largestFree uint64) {
	return 0, 0, 0, 0, 0
}

func (r *realNTFS) Layout() []FileLayout { return nil }

// Label reads the volume label from the $VOLUME_NAME attribute of the
// $Volume metadata file (MFT record 3). An empty string means no label.
func (r *realNTFS) Label() string {
	fr, err := r.readFileRecord(3)
	if err != nil {
		return ""
	}
	const attrVolumeName = 0x60
	for _, a := range fr.attrs {
		if a.typeCode == attrVolumeName && !a.nonResident {
			return decodeUTF16(a.residentData)
		}
	}
	return ""
}
