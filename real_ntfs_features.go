// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) the go-filesystems/ntfs authors

package filesystem_ntfs

// On-disk NTFS feature extensions to the read-only reader in real_ntfs.go.
//
// This file adds genuine on-disk structures that the foundation reader
// originally deferred:
//
//   - LZNT1 compression: compressed non-resident $DATA (and any compressed
//     named stream) is decompressed per NTFS compression unit, exactly as
//     Windows and ntfs-3g write it.
//   - Named data streams (ADS): every $DATA attribute name is enumerable and
//     independently readable via the StreamReader capability interface.
//   - $ATTRIBUTE_LIST (0x20): attributes that overflow the base FILE record
//     into extension records are stitched back into one logical attribute,
//     concatenating split non-resident runlists in VCN order.
//   - IntxLNK symlinks: the ntfs-3g / Services-for-Unix convention of storing
//     a symlink as a plain file whose $DATA opens with an "IntxLNK\1" marker
//     is decoded by ReadLink (complementing the $REPARSE_POINT form).
//
// Encrypted ($EFS) data remains genuinely out of scope: it cannot be
// materialised without the user's decryption keys, so readAttrData surfaces a
// clear error rather than returning ciphertext.

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/go-volumes/safeio"
)

// ---- LZNT1 compression ----

// readCompressedRuns materialises a compressed non-resident attribute. The
// runlist is walked one compression unit at a time (2^compUnit clusters per
// unit). Each unit is stored in one of three ways, which this routine detects
// from how the unit's clusters are allocated:
//
//   - all clusters allocated        → the unit is stored uncompressed verbatim
//   - some allocated then sparse     → the allocated clusters hold an LZNT1
//     stream that decompresses to the full unit
//   - all sparse                     → the unit is a run of zeroes
//
// The final unit may be partial; only realSize bytes are ever returned.
func (r *realNTFS) readCompressedRuns(runs []dataRun, size uint64, compUnit uint16) ([]byte, error) {
	// A compression unit spans 2^compUnit clusters. Windows uses 16 clusters
	// (compUnit==4); reject an exponent large enough to overflow the shift or
	// blow past any sane unit.
	if compUnit == 0 || compUnit > 30 {
		return nil, fmt.Errorf("ntfs: invalid compression unit exponent %d", compUnit)
	}
	cs := r.boot.clusterSize()
	unitClusters := int64(1) << compUnit
	unitBytes, ok := mulCheck(unitClusters, cs)
	if !ok || unitBytes <= 0 {
		return nil, fmt.Errorf("ntfs: compression unit size overflow")
	}
	if size > uint64(math.MaxInt64) {
		return nil, fmt.Errorf("ntfs: compressed data size %d too large", size)
	}
	out, err := safeio.MakeBytes(int64(size), maxDataSize)
	if err != nil {
		return nil, fmt.Errorf("ntfs: compressed data buffer: %w", err)
	}
	want := int64(len(out))

	rr := &runReader{r: r, runs: runs}
	// Each iteration advances the logical position by one compression unit, so
	// the loop is bounded by want/unitBytes+1; a guard keeps a degenerate
	// runlist from spinning even if pos somehow fails to advance.
	guard := safeio.NewLoopGuard(int(want/unitBytes) + 2)
	var pos int64
	for pos < want {
		if err := guard.Next(); err != nil {
			return nil, fmt.Errorf("ntfs: compressed read: %w", err)
		}
		raw, allocated, sawSparse, err := rr.readUnit(unitClusters)
		if err != nil {
			return nil, err
		}
		if allocated == 0 && !sawSparse {
			// Runlist exhausted before the declared size; leave the rest zero.
			break
		}
		n := unitBytes
		if pos+n > want {
			n = want - pos
		}
		// The presence of a sparse cluster inside the unit is the on-disk
		// signal that the real clusters hold an LZNT1 stream: an uncompressed
		// unit is stored as whole clusters with no sparse padding (including a
		// partial final unit), a compressed unit as its real clusters followed
		// by sparse padding, and an all-zero unit as fully sparse.
		switch {
		case allocated == 0:
			// Fully sparse unit: leave the pre-zeroed output untouched.
		case !sawSparse:
			// Stored verbatim (uncompressed): the raw clusters are the data.
			m := int64(len(raw))
			if m > n {
				m = n
			}
			copy(out[pos:pos+m], raw[:m])
		default:
			// Compressed unit: the allocated clusters hold an LZNT1 stream.
			dec, err := lznt1Decompress(raw, int(unitBytes))
			if err != nil {
				return nil, fmt.Errorf("ntfs: lznt1: %w", err)
			}
			m := int64(len(dec))
			if m > n {
				m = n
			}
			copy(out[pos:pos+m], dec[:m])
		}
		pos += n
	}
	return out, nil
}

// runReader is a forward cursor over a runlist that hands back cluster
// segments. It is used to carve a runlist into compression units without
// materialising a per-cluster map.
type runReader struct {
	r        *realNTFS
	runs     []dataRun
	ri       int   // index of the current run
	consumed int64 // clusters already consumed from runs[ri]
}

// segment returns up to want clusters from the current position as a single
// homogeneous segment (either all sparse or all allocated). n==0 signals the
// runlist is exhausted.
func (rr *runReader) segment(want int64) (lcn int64, sparse bool, n int64) {
	for rr.ri < len(rr.runs) && rr.consumed >= rr.runs[rr.ri].lengthClusters {
		rr.ri++
		rr.consumed = 0
	}
	if rr.ri >= len(rr.runs) {
		return 0, false, 0
	}
	run := rr.runs[rr.ri]
	avail := run.lengthClusters - rr.consumed
	n = avail
	if n > want {
		n = want
	}
	sparse = run.sparse
	if !sparse {
		lcn = run.startCluster + rr.consumed
	}
	rr.consumed += n
	return lcn, sparse, n
}

// readUnit reads the next unitClusters clusters, returning the concatenated
// bytes of the allocated (non-sparse) clusters, the number of allocated
// clusters and whether any sparse cluster was seen. In a compressed unit the
// allocated clusters precede the sparse padding, so raw is exactly the LZNT1
// stream.
func (rr *runReader) readUnit(unitClusters int64) (raw []byte, allocated int64, sawSparse bool, err error) {
	remaining := unitClusters
	for remaining > 0 {
		lcn, sparse, n := rr.segment(remaining)
		if n == 0 {
			break
		}
		if sparse {
			sawSparse = true
		} else {
			b, err := rr.r.readClusters(lcn, n)
			if err != nil {
				return nil, 0, false, err
			}
			raw = append(raw, b...)
			allocated += n
		}
		remaining -= n
	}
	return raw, allocated, sawSparse, nil
}

// readClusters reads count clusters starting at the absolute LCN into a fresh
// buffer, relative to partOffset. All arithmetic is overflow-checked.
func (r *realNTFS) readClusters(lcn, count int64) ([]byte, error) {
	cs := r.boot.clusterSize()
	nBytes, ok := mulCheck(count, cs)
	if !ok {
		return nil, fmt.Errorf("ntfs: cluster byte count overflow")
	}
	base, ok := mulCheck(lcn, cs)
	if !ok {
		return nil, fmt.Errorf("ntfs: cluster offset overflow")
	}
	abs, ok := addCheck(base, r.partOffset)
	if !ok || abs < 0 {
		return nil, fmt.Errorf("ntfs: cluster absolute offset overflow")
	}
	buf, err := safeio.MakeBytes(nBytes, maxDataSize)
	if err != nil {
		return nil, fmt.Errorf("ntfs: cluster buffer: %w", err)
	}
	if _, err := r.f.ReadAt(buf, abs); err != nil && err != io.EOF {
		return nil, err
	}
	return buf, nil
}

// lznt1Decompress decompresses one NTFS compression unit's LZNT1 stream into
// at most maxOut bytes. The stream is a sequence of chunks: a 2-byte
// little-endian header then that many payload bytes. A zero header or the end
// of input terminates the stream. Each chunk decompresses to at most 4096
// bytes; a chunk is either stored raw or as a token stream of literals and
// (offset,length) back-references whose field widths grow with the output
// position inside the chunk.
func lznt1Decompress(src []byte, maxOut int) ([]byte, error) {
	out := make([]byte, 0, maxOut)
	i := 0
	guard := safeio.NewLoopGuard(len(src) + 1)
	for i+2 <= len(src) {
		if err := guard.Next(); err != nil {
			return nil, fmt.Errorf("chunk walk: %w", err)
		}
		header := binary.LittleEndian.Uint16(src[i:])
		if header == 0 {
			break // end-of-stream padding
		}
		i += 2
		chunkLen := int(header&0x0FFF) + 1
		if i+chunkLen > len(src) {
			chunkLen = len(src) - i // tolerate a truncated final chunk
		}
		chunk := src[i : i+chunkLen]
		i += chunkLen
		if header&0x8000 == 0 {
			// Uncompressed chunk: copy the payload verbatim.
			if len(out)+len(chunk) > maxOut {
				return nil, fmt.Errorf("uncompressed chunk overflows unit")
			}
			out = append(out, chunk...)
			continue
		}
		var err error
		out, err = lznt1DecodeChunk(out, chunk, maxOut)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// lznt1DecodeChunk decodes one compressed chunk onto out and returns the
// grown slice. blockStart marks where this chunk's decompressed data begins,
// which is the reference frame for back-reference offsets.
func lznt1DecodeChunk(out, chunk []byte, maxOut int) ([]byte, error) {
	blockStart := len(out)
	j := 0
	guard := safeio.NewLoopGuard(len(chunk) + 1)
	for j < len(chunk) {
		if err := guard.Next(); err != nil {
			return nil, fmt.Errorf("token walk: %w", err)
		}
		flags := chunk[j]
		j++
		for bit := 0; bit < 8 && j < len(chunk); bit++ {
			if flags&(1<<uint(bit)) == 0 {
				// Literal byte.
				if len(out) >= maxOut {
					return nil, fmt.Errorf("literal overflows unit")
				}
				out = append(out, chunk[j])
				j++
				continue
			}
			// Back-reference token (2 bytes).
			if j+2 > len(chunk) {
				return out, nil // trailing partial token: stop cleanly
			}
			token := binary.LittleEndian.Uint16(chunk[j:])
			j += 2
			pos := len(out) - blockStart
			if pos <= 0 {
				return nil, fmt.Errorf("back-reference at chunk start")
			}
			offBits := lznt1OffsetBits(pos)
			lenBits := 16 - offBits
			length := int(token&(1<<uint(lenBits)-1)) + 3
			offset := int(token>>uint(lenBits)) + 1
			if offset > pos {
				return nil, fmt.Errorf("back-reference offset %d past %d bytes", offset, pos)
			}
			srcPos := len(out) - offset
			for k := 0; k < length; k++ {
				if len(out) >= maxOut {
					return nil, fmt.Errorf("back-reference overflows unit")
				}
				out = append(out, out[srcPos+k])
			}
		}
	}
	return out, nil
}

// lznt1OffsetBits returns the number of bits the LZNT1 token dedicates to the
// back-reference offset when pos bytes have already been produced in the
// current chunk: the smallest b in [4,12] with 2^b >= pos.
func lznt1OffsetBits(pos int) int {
	b := 4
	for (1 << uint(b)) < pos {
		b++
	}
	if b > 12 {
		b = 12
	}
	return b
}

// ---- named data streams (ADS) ----

// StreamReader is the optional capability, satisfied by the real-NTFS reader,
// for enumerating and reading a file's named data streams (alternate data
// streams). The unnamed default stream is reported as "".
//
//	if sr, ok := fs.(ntfs.StreamReader); ok {
//	    names, _ := sr.ListStreams("/notes.txt")   // ["", "author"]
//	    b, _ := sr.ReadStream("/notes.txt", "author")
//	}
type StreamReader interface {
	// ListStreams returns the names of every $DATA stream on the file, with
	// the unnamed default stream represented by "". Names are sorted and
	// de-duplicated.
	ListStreams(path string) ([]string, error)
	// ReadStream returns the full content of the named $DATA stream (name ""
	// selects the default stream), transparently decompressing LZNT1 data.
	ReadStream(path, name string) ([]byte, error)
}

var _ StreamReader = (*realNTFS)(nil)

// ListStreams enumerates the $DATA stream names on a file.
func (r *realNTFS) ListStreams(p string) ([]string, error) {
	_, fr, err := r.resolvePath(p)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var names []string
	for i := range fr.attrs {
		if fr.attrs[i].typeCode != attrData {
			continue
		}
		n := fr.attrs[i].name
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// ReadStream reads a specific named $DATA stream (name "" = default).
func (r *realNTFS) ReadStream(p, name string) ([]byte, error) {
	_, fr, err := r.resolvePath(p)
	if err != nil {
		return nil, err
	}
	for i := range fr.attrs {
		a := &fr.attrs[i]
		if a.typeCode == attrData && a.name == name {
			return r.readAttrData(a)
		}
	}
	return nil, fmt.Errorf("ntfs: %q has no data stream %q", p, name)
}

// ---- IntxLNK symlinks (ntfs-3g / SFU convention) ----

// intxLinkTarget decodes a symlink stored as an ordinary file whose default
// $DATA begins with the "IntxLNK\1" marker followed by the UTF-16LE target.
// ok is false when the file is not an IntxLNK symlink.
func (r *realNTFS) intxLinkTarget(fr *fileRecord) (string, bool, error) {
	data, ok, err := r.dataBytes(fr)
	if err != nil || !ok {
		return "", false, err
	}
	if len(data) < len(intxLnkMagic) || string(data[:len(intxLnkMagic)]) != intxLnkMagic {
		return "", false, nil
	}
	return decodeUTF16(data[len(intxLnkMagic):]), true, nil
}

// ---- $ATTRIBUTE_LIST (0x20) ----

// attrListEntry is one parsed $ATTRIBUTE_LIST record: it names an attribute
// (type + name) and the MFT record (baseRef) that physically holds the
// fragment starting at startVCN.
type attrListEntry struct {
	typeCode uint32
	name     string
	startVCN uint64
	baseRef  uint64 // MFT record number holding this fragment
	attrID   uint16
}

// resolveAttributes follows a base record's $ATTRIBUTE_LIST (if any) and
// rebuilds fr.attrs so that attributes spilled into extension records are
// present, and split non-resident attributes are stitched into a single
// runlist in VCN order. Records with no attribute list are left untouched.
func (r *realNTFS) resolveAttributes(baseRecNo uint64, fr *fileRecord) error {
	var listAttr *attribute
	for i := range fr.attrs {
		if fr.attrs[i].typeCode == attrAttributeList {
			listAttr = &fr.attrs[i]
			break
		}
	}
	if listAttr == nil {
		return nil // common case: everything fits in the base record
	}
	body, err := r.readAttrData(listAttr)
	if err != nil {
		return fmt.Errorf("ntfs: $ATTRIBUTE_LIST: %w", err)
	}
	entries, err := parseAttrList(body)
	if err != nil {
		return err
	}

	// Gather every extension record the list points at (other than the base
	// record, whose attributes we already hold), bounded for safety.
	extRecs := map[uint64]*fileRecord{baseRecNo: fr}
	for _, e := range entries {
		if _, have := extRecs[e.baseRef]; have {
			continue
		}
		if len(extRecs) >= maxAttrListRecords {
			return fmt.Errorf("ntfs: $ATTRIBUTE_LIST references too many records")
		}
		rec, err := r.readFileRecordRaw(e.baseRef)
		if err != nil {
			return fmt.Errorf("ntfs: attribute-list extension record %d: %w", e.baseRef, err)
		}
		extRecs[e.baseRef] = rec
	}

	// Collect all attribute fragments from every gathered record.
	var all []attribute
	for _, rec := range extRecs {
		all = append(all, rec.attrs...)
	}
	fr.attrs = mergeAttributes(all)
	return nil
}

// mergeAttributes coalesces attribute fragments. Resident attributes (which
// are never split) are kept as-is; non-resident attributes sharing a
// (type, name) are merged into one attribute whose runlist is the
// concatenation of the fragments' runs in ascending startVCN order, taking
// realSize / flags / compUnit from the VCN-0 fragment.
func mergeAttributes(all []attribute) []attribute {
	// The $ATTRIBUTE_LIST itself is not part of the reconstructed set; the
	// merged attributes stand on their own.
	type key struct {
		typeCode uint32
		name     string
	}
	var out []attribute
	groups := map[key][]attribute{}
	var order []key
	for _, a := range all {
		if a.typeCode == attrAttributeList {
			continue
		}
		if !a.nonResident {
			out = append(out, a)
			continue
		}
		k := key{a.typeCode, a.name}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], a)
	}
	for _, k := range order {
		frags := groups[k]
		sort.SliceStable(frags, func(i, j int) bool {
			return frags[i].startVCN < frags[j].startVCN
		})
		merged := frags[0] // VCN-0 fragment carries realSize/flags/compUnit
		merged.runs = nil
		for _, f := range frags {
			merged.runs = append(merged.runs, f.runs...)
		}
		out = append(out, merged)
	}
	return out
}

// parseAttrList decodes an $ATTRIBUTE_LIST body into its entries. Each entry
// is at least 0x1A bytes: type(4), recordLength(2), nameLength(1),
// nameOffset(1), startVCN(8), baseFileReference(8), attributeID(2), then an
// optional UTF-16 name.
func parseAttrList(body []byte) ([]attrListEntry, error) {
	var entries []attrListEntry
	off := 0
	guard := safeio.NewLoopGuard(len(body) + 1)
	for off+0x1A <= len(body) {
		if err := guard.Next(); err != nil {
			return nil, fmt.Errorf("ntfs: $ATTRIBUTE_LIST: %w", err)
		}
		typeCode := binary.LittleEndian.Uint32(body[off:])
		if typeCode == attrEnd {
			break
		}
		recLen := int(binary.LittleEndian.Uint16(body[off+0x04:]))
		if recLen < 0x1A || off+recLen > len(body) {
			return nil, fmt.Errorf("ntfs: bad $ATTRIBUTE_LIST entry length %d", recLen)
		}
		nameLen := int(body[off+0x06])
		nameOff := int(body[off+0x07])
		var name string
		if nameLen > 0 {
			if nb, err := safeio.Slice(body[off:off+recLen], nameOff, nameLen*2); err == nil {
				name = decodeUTF16(nb)
			}
		}
		entries = append(entries, attrListEntry{
			typeCode: typeCode,
			name:     name,
			startVCN: binary.LittleEndian.Uint64(body[off+0x08:]),
			baseRef:  binary.LittleEndian.Uint64(body[off+0x10:]) & 0x0000FFFFFFFFFFFF,
			attrID:   binary.LittleEndian.Uint16(body[off+0x18:]),
		})
		off += recLen
	}
	return entries, nil
}
