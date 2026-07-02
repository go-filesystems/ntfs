package filesystem_ntfs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// reparseBuffer hand-builds a REPARSE_DATA_BUFFER for the given tag with a
// substitute name and a print name laid out back-to-back in the trailing
// PathBuffer. A symlink buffer carries the extra 4-byte Flags word that a
// mount-point buffer omits.
func reparseBuffer(tag uint32, substitute, printName string) []byte {
	sub := utf16le(substitute)
	pr := utf16le(printName)
	pathBuf := append(append([]byte(nil), sub...), pr...)

	fields := make([]byte, 8)
	binary.LittleEndian.PutUint16(fields[0:], 0)                // SubstituteNameOffset
	binary.LittleEndian.PutUint16(fields[2:], uint16(len(sub))) // SubstituteNameLength
	binary.LittleEndian.PutUint16(fields[4:], uint16(len(sub))) // PrintNameOffset
	binary.LittleEndian.PutUint16(fields[6:], uint16(len(pr)))  // PrintNameLength
	if tag == reparseTagSymlink {
		fields = append(fields, make([]byte, 4)...) // Flags
	}
	payload := append(fields, pathBuf...)

	buf := make([]byte, reparseHeaderLen+len(payload))
	binary.LittleEndian.PutUint32(buf[0:], tag)
	binary.LittleEndian.PutUint16(buf[4:], uint16(len(payload)))
	copy(buf[reparseHeaderLen:], payload)
	return buf
}

func TestParseReparseTarget_Symlink(t *testing.T) {
	buf := reparseBuffer(reparseTagSymlink, `\??\C:\target.txt`, `C:\target.txt`)
	got, ok, err := parseReparseTarget(buf)
	if err != nil || !ok {
		t.Fatalf("parseReparseTarget: ok=%v err=%v", ok, err)
	}
	if got != `C:\target.txt` {
		t.Errorf("target = %q, want print name %q", got, `C:\target.txt`)
	}
}

func TestParseReparseTarget_MountPoint(t *testing.T) {
	buf := reparseBuffer(reparseTagMountPoint, `\??\C:\mnt`, `C:\mnt`)
	got, ok, err := parseReparseTarget(buf)
	if err != nil || !ok {
		t.Fatalf("parseReparseTarget: ok=%v err=%v", ok, err)
	}
	if got != `C:\mnt` {
		t.Errorf("target = %q, want %q", got, `C:\mnt`)
	}
}

func TestParseReparseTarget_RelativeSymlink(t *testing.T) {
	// A relative symlink has no device prefix on either name.
	buf := reparseBuffer(reparseTagSymlink, `..\sibling`, `..\sibling`)
	got, ok, err := parseReparseTarget(buf)
	if err != nil || !ok {
		t.Fatalf("parseReparseTarget: ok=%v err=%v", ok, err)
	}
	if got != `..\sibling` {
		t.Errorf("target = %q, want %q", got, `..\sibling`)
	}
}

func TestParseReparseTarget_EmptyPrintNameFallsBackToSubstitute(t *testing.T) {
	// Empty print name: the substitute name is used, with its NT namespace
	// prefix stripped.
	buf := reparseBuffer(reparseTagSymlink, `\??\D:\only`, "")
	got, ok, err := parseReparseTarget(buf)
	if err != nil || !ok {
		t.Fatalf("parseReparseTarget: ok=%v err=%v", ok, err)
	}
	if got != `D:\only` {
		t.Errorf("target = %q, want stripped substitute %q", got, `D:\only`)
	}
}

func TestParseReparseTarget_UNCSubstituteFallback(t *testing.T) {
	buf := reparseBuffer(reparseTagMountPoint, `\??\UNC\server\share`, "")
	got, ok, err := parseReparseTarget(buf)
	if err != nil || !ok {
		t.Fatalf("parseReparseTarget: ok=%v err=%v", ok, err)
	}
	if got != `\\server\share` {
		t.Errorf("target = %q, want UNC %q", got, `\\server\share`)
	}
}

func TestParseReparseTarget_UnsupportedTag(t *testing.T) {
	// IO_REPARSE_TAG_DEDUP (0x80000013) names no path target.
	buf := reparseBuffer(0x80000013, "x", "x")
	_, ok, err := parseReparseTarget(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for unsupported reparse tag")
	}
}

func TestParseReparseTarget_ShortHeader(t *testing.T) {
	if _, _, err := parseReparseTarget([]byte{0x0C, 0x00, 0x00}); err == nil {
		t.Error("expected error for short reparse header")
	}
}

func TestParseReparseTarget_ShortPayload(t *testing.T) {
	// Valid symlink tag but a payload too short for the four name fields.
	buf := make([]byte, reparseHeaderLen+4)
	binary.LittleEndian.PutUint32(buf[0:], reparseTagSymlink)
	binary.LittleEndian.PutUint16(buf[4:], 4)
	if _, _, err := parseReparseTarget(buf); err == nil {
		t.Error("expected error for short reparse payload")
	}
}

func TestParseReparseTarget_NoName(t *testing.T) {
	// Zero-length print AND substitute names → no target.
	buf := reparseBuffer(reparseTagSymlink, "", "")
	if _, _, err := parseReparseTarget(buf); err == nil {
		t.Error("expected error when reparse point names no target")
	}
}

func TestParseReparseTarget_OverreportedDataLen(t *testing.T) {
	// ReparseDataLength larger than the buffer must fall back to the bytes
	// that actually follow the header rather than erroring on the slice.
	buf := reparseBuffer(reparseTagSymlink, `\??\E:\x`, `E:\x`)
	binary.LittleEndian.PutUint16(buf[4:], 0xFFFF) // absurd data length
	got, ok, err := parseReparseTarget(buf)
	if err != nil || !ok {
		t.Fatalf("parseReparseTarget: ok=%v err=%v", ok, err)
	}
	if got != `E:\x` {
		t.Errorf("target = %q, want %q", got, `E:\x`)
	}
}

// buildSyntheticNTFSWithReparse writes an image whose root lists a symlink
// file "link" (record 24) and a directory junction "junc" (record 25),
// each carrying a $REPARSE_POINT attribute.
func buildSyntheticNTFSWithReparse(t *testing.T, path string) {
	t.Helper()
	const totalClusters = 64
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
		const mftClusters = 60
		ab.addNonResident(attrData, "", mftClusters*tClusterSize, runlistSingle(mftClusters, tMFTCluster))
		writeRec(tRecMFT, buildFileRecord(false, ab.finish()))
	}

	// Root directory (record 5): lists "link" and "junc".
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, ".", true))
		children := []indexEntry{
			{mftRef: tRecHello, name: "link", isDir: false},
			{mftRef: tRecDir, name: "junc", isDir: true},
			{mftRef: tRecBig, name: "unsup", isDir: false},
			{mftRef: 27, name: "bad", isDir: false},
		}
		ab.addResident(attrIndexRoot, "$I30", indexRootBody(children))
		writeRec(tRecRoot, buildFileRecord(true, ab.finish()))
	}

	// "link" (record 24): a symbolic link (reparse point) file.
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "link", false))
		ab.addResident(attrReparsePoint, "",
			reparseBuffer(reparseTagSymlink, `\??\C:\Windows\notepad.exe`, `C:\Windows\notepad.exe`))
		writeRec(tRecHello, buildFileRecord(false, ab.finish()))
	}

	// "junc" (record 25): a directory junction (mount point).
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "junc", true))
		ab.addResident(attrReparsePoint, "",
			reparseBuffer(reparseTagMountPoint, `\??\C:\Targets\real`, `C:\Targets\real`))
		writeRec(tRecDir, buildFileRecord(true, ab.finish()))
	}

	// "unsup" (record 26): a reparse point with a non-path tag; ReadLink
	// must report it as unsupported.
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "unsup", false))
		ab.addResident(attrReparsePoint, "", reparseBuffer(0x80000013, "x", "x"))
		writeRec(tRecBig, buildFileRecord(false, ab.finish()))
	}

	// "bad" (record 27): a $REPARSE_POINT whose body is too short to parse.
	{
		var ab attrBuilder
		ab.addResident(attrStandardInformation, "", stdInfo())
		ab.addResident(attrFileName, "", fileNameAttrBody(tRecRoot, "bad", false))
		ab.addResident(attrReparsePoint, "", []byte{0x0C, 0x00, 0x00})
		writeRec(27, buildFileRecord(false, ab.finish()))
	}

	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}
}

func TestRealNTFS_ReadLink_Symlink(t *testing.T) {
	img := filepath.Join(t.TempDir(), "reparse.ntfs")
	buildSyntheticNTFSWithReparse(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	got, err := fs.ReadLink("/link")
	if err != nil {
		t.Fatalf("ReadLink(/link): %v", err)
	}
	if got != `C:\Windows\notepad.exe` {
		t.Errorf("ReadLink(/link) = %q, want %q", got, `C:\Windows\notepad.exe`)
	}
}

func TestRealNTFS_ReadLink_Junction(t *testing.T) {
	img := filepath.Join(t.TempDir(), "reparse.ntfs")
	buildSyntheticNTFSWithReparse(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	got, err := fs.ReadLink("/junc")
	if err != nil {
		t.Fatalf("ReadLink(/junc): %v", err)
	}
	if got != `C:\Targets\real` {
		t.Errorf("ReadLink(/junc) = %q, want %q", got, `C:\Targets\real`)
	}
}

func TestRealNTFS_ReadLink_NotASymlink(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if _, err := fs.ReadLink("/hello.txt"); err == nil {
		t.Error("ReadLink on a regular file: expected error")
	}
}

func TestRealNTFS_ReadLink_NotFound(t *testing.T) {
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if _, err := fs.ReadLink("/does-not-exist"); err == nil {
		t.Error("ReadLink on a missing path: expected error")
	}
}

// TestRealNTFS_ReadLink_UnsupportedTag drives fs.ReadLink to the
// unsupported-tag error branch via a reparse point whose tag names no path.
func TestRealNTFS_ReadLink_UnsupportedTag(t *testing.T) {
	img := filepath.Join(t.TempDir(), "reparse.ntfs")
	buildSyntheticNTFSWithReparse(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if _, err := fs.ReadLink("/unsup"); err == nil {
		t.Error("ReadLink on unsupported reparse tag: expected error")
	}
}

// TestRealNTFS_ReadLink_MalformedReparse drives fs.ReadLink to the
// parse-error branch via a $REPARSE_POINT with a truncated body.
func TestRealNTFS_ReadLink_MalformedReparse(t *testing.T) {
	img := filepath.Join(t.TempDir(), "reparse.ntfs")
	buildSyntheticNTFSWithReparse(t, img)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if _, err := fs.ReadLink("/bad"); err == nil {
		t.Error("ReadLink on malformed reparse point: expected error")
	}
}

// TestStripNTNamespacePrefix_NoPrefix covers a substitute name that carries
// no NT device prefix (a relative junction target), returned verbatim.
func TestStripNTNamespacePrefix_NoPrefix(t *testing.T) {
	// Empty print name forces the substitute-name fallback path; the
	// substitute here has no "\??\" prefix so it is returned unchanged.
	buf := reparseBuffer(reparseTagMountPoint, `plain\target`, "")
	got, ok, err := parseReparseTarget(buf)
	if err != nil || !ok {
		t.Fatalf("parseReparseTarget: ok=%v err=%v", ok, err)
	}
	if got != `plain\target` {
		t.Errorf("target = %q, want %q", got, `plain\target`)
	}
}

// TestParseReparseNames_PathBufOffOverrun covers the guard for a payload
// that ends before its PathBuffer would begin.
func TestParseReparseNames_PathBufOffOverrun(t *testing.T) {
	// Symlink pathBufOff is 12 but this payload is only 8 bytes.
	if _, _, err := parseReparseNames(make([]byte, 8), symlinkPathBufOff); err == nil {
		t.Error("expected error for payload shorter than pathBufOff")
	}
}

// TestParseReparseNames_PrintNameOutOfRange covers the branch where the
// print name offset/length overrun the PathBuffer, forcing the substitute
// name fallback.
func TestParseReparseNames_PrintNameOutOfRange(t *testing.T) {
	sub := utf16le(`\??\F:\ok`)
	payload := make([]byte, 8+len(sub))
	binary.LittleEndian.PutUint16(payload[0:], 0)                // SubstituteNameOffset
	binary.LittleEndian.PutUint16(payload[2:], uint16(len(sub))) // SubstituteNameLength
	binary.LittleEndian.PutUint16(payload[4:], 0xFF00)           // PrintNameOffset (OOB)
	binary.LittleEndian.PutUint16(payload[6:], 4)                // PrintNameLength
	copy(payload[8:], sub)
	got, ok, err := parseReparseNames(payload, mountPointPathBufOff)
	if err != nil || !ok {
		t.Fatalf("parseReparseNames: ok=%v err=%v", ok, err)
	}
	if got != `F:\ok` {
		t.Errorf("target = %q, want substitute fallback %q", got, `F:\ok`)
	}
}
