package filesystem_ntfs

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// TestNTFS_RoundTripPersistence exercises Open's "image already has a
// valid header" branch plus loadIndex's metadata, free-list and label
// parsing paths by writing files, setting a label, closing, then
// reopening from disk and verifying the entire on-disk state survives.
func TestNTFS_RoundTripPersistence(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")

	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Populate: regular files, a directory, a symlink and a volume label.
	if err := fs.WriteFile("/a.txt", []byte("AAA"), 0o644); err != nil {
		t.Fatalf("WriteFile /a.txt: %v", err)
	}
	if err := fs.MkDir("/d", 0o755); err != nil {
		t.Fatalf("MkDir /d: %v", err)
	}
	if err := fs.WriteFile("/d/b.txt", []byte("BBB-payload"), 0o600); err != nil {
		t.Fatalf("WriteFile /d/b.txt: %v", err)
	}
	if err := fs.Symlink("/a.txt", "/lnk"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := fs.SetLabel("MYVOLUME"); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}
	// Force a non-empty free-list by deleting then writing a smaller file.
	if err := fs.WriteFile("/scratch", make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("WriteFile /scratch: %v", err)
	}
	if err := fs.DeleteFile("/scratch"); err != nil {
		t.Fatalf("DeleteFile /scratch: %v", err)
	}

	// Snapshot inode of /a.txt before close.
	preInode := fs.(*ntfsFS).meta["/a.txt"].Inode
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen — exercises loadIndex's "valid header" path with metadata,
	// free-list, and label blocks present.
	fs2, err := Open(img, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer fs2.Close()

	got, err := fs2.ReadFile("/a.txt")
	if err != nil {
		t.Fatalf("ReadFile after reopen: %v", err)
	}
	if !bytes.Equal(got, []byte("AAA")) {
		t.Fatalf("content mismatch after reopen: %q", got)
	}
	if got, err := fs2.ReadFile("/d/b.txt"); err != nil || !bytes.Equal(got, []byte("BBB-payload")) {
		t.Fatalf("ReadFile /d/b.txt: %v %q", err, got)
	}
	if tgt, err := fs2.ReadLink("/lnk"); err != nil || tgt != "/a.txt" {
		t.Fatalf("ReadLink after reopen: %q err=%v", tgt, err)
	}
	if lbl := fs2.Label(); lbl != "MYVOLUME" {
		t.Fatalf("label not restored: got %q", lbl)
	}
	if got := fs2.(*ntfsFS).meta["/a.txt"].Inode; got != preInode {
		t.Fatalf("inode for /a.txt not preserved: pre=%d post=%d", preInode, got)
	}
	// freeList should have been persisted (we deleted /scratch above).
	if len(fs2.(*ntfsFS).freeList) == 0 {
		t.Fatalf("expected non-empty freeList after reopen")
	}
}

// TestNTFS_FragmentationStatsAndLayout covers the two analysis helpers
// that ship with the FS interface and that were previously unexercised.
func TestNTFS_FragmentationStatsAndLayout(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	// Three files + one directory; delete the middle file to leave a
	// free extent so largestFree / totalFree are non-zero.
	if err := fs.WriteFile("/f1", make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/f2", make([]byte, 2048), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/f3", make([]byte, 512), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.MkDir("/somedir", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.DeleteFile("/f2"); err != nil {
		t.Fatal(err)
	}

	files, used, freeExtents, totalFree, largestFree := fs.FragmentationStats()
	if files != 2 {
		t.Fatalf("expected 2 files (dirs excluded), got %d", files)
	}
	if used != 1024+512 {
		t.Fatalf("expected used=%d, got %d", 1024+512, used)
	}
	if freeExtents == 0 || totalFree == 0 || largestFree == 0 {
		t.Fatalf("expected non-zero free metrics, got extents=%d total=%d largest=%d",
			freeExtents, totalFree, largestFree)
	}
	if largestFree > totalFree {
		t.Fatalf("largestFree (%d) > totalFree (%d) -- impossible", largestFree, totalFree)
	}

	// Layout: only files appear, sorted by offset, and dirs are skipped.
	layout := fs.Layout()
	if len(layout) != 2 {
		t.Fatalf("expected layout of 2 file blobs, got %d", len(layout))
	}
	for i := 1; i < len(layout); i++ {
		if layout[i].Offset < layout[i-1].Offset {
			t.Fatalf("layout not sorted by offset: %+v", layout)
		}
	}
	// All paths must be files we wrote (no /somedir).
	for _, l := range layout {
		if l.Path == "/somedir" {
			t.Fatalf("dir leaked into Layout: %+v", l)
		}
	}
}

// TestNTFS_MergeFreeListCoalesces exercises mergeFreeList by manually
// installing several adjacent / non-adjacent free extents then triggering
// a delete (which calls mergeFreeList).
func TestNTFS_MergeFreeListCoalesces(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	nf := fs.(*ntfsFS)

	// Install hand-crafted free extents:
	//   [0..100)   [100..200)   [300..400)
	// After coalescing the first two should merge into [0..200) while the
	// third stays disjoint, yielding a 2-extent result.
	nf.freeList = []fileEntry{
		{Offset: 100, Size: 100},
		{Offset: 0, Size: 100},   // out of order on purpose
		{Offset: 300, Size: 100}, // gap before this one
	}
	// Trigger merge via DeleteFile (no-op file, doesn't add anything).
	// We write+delete a 1-byte file to add a 4th extent which is also
	// disjoint so we can verify both branches of the loop.
	if err := fs.WriteFile("/tmp", []byte("z"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Now write+delete to push another free extent into the list, which
	// then triggers mergeFreeList via DeleteFile.
	tmpOff := nf.index["/tmp"].Offset
	if err := fs.DeleteFile("/tmp"); err != nil {
		t.Fatal(err)
	}
	// Verify list is sorted and no two extents are adjacent/overlapping.
	for i := 1; i < len(nf.freeList); i++ {
		prev := nf.freeList[i-1]
		cur := nf.freeList[i]
		if cur.Offset <= prev.Offset+prev.Size {
			t.Fatalf("freeList not properly coalesced: %+v", nf.freeList)
		}
	}
	// And the original [0..100)+[100..200) pair must have merged.
	found := false
	for _, fe := range nf.freeList {
		if fe.Offset == 0 && fe.Size == 200 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected merged extent [0,200) in freeList: %+v", nf.freeList)
	}
	_ = tmpOff

	// Trivial branch: <=1 extents short-circuits.
	nf.freeList = []fileEntry{{Offset: 0, Size: 10}}
	nf.mergeFreeList()
	if len(nf.freeList) != 1 {
		t.Fatalf("single-entry freeList should be untouched, got %v", nf.freeList)
	}
	nf.freeList = nil
	nf.mergeFreeList()
	if nf.freeList != nil {
		t.Fatalf("nil freeList should remain nil, got %v", nf.freeList)
	}
}

// TestNTFS_FormatLabel covers the Format helper, including the branch
// that seeds an initial volume label via FormatConfig.
func TestNTFS_FormatLabel(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")

	fs, err := Format(img, 1<<20, FormatConfig{Label: "FRESH"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	// Round-trip: assert label persisted and the file size matches.
	if lr, ok := fs.(filesystem.LabelReader); ok {
		if lr.Label() != "FRESH" {
			t.Fatalf("Format label not applied: %q", lr.Label())
		}
	} else {
		t.Fatalf("formatted FS does not satisfy LabelReader")
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	info, err := os.Stat(img)
	if err != nil {
		t.Fatalf("stat image: %v", err)
	}
	if info.Size() < 1<<20 {
		t.Fatalf("image smaller than requested: %d", info.Size())
	}

	// Format without a label exercises the no-label branch.
	img2 := filepath.Join(dir, "noLabel.img")
	fs2, err := Format(img2, 1<<20, FormatConfig{})
	if err != nil {
		t.Fatalf("Format no-label: %v", err)
	}
	defer fs2.Close()
	if lr, ok := fs2.(filesystem.LabelReader); ok && lr.Label() != "" {
		t.Fatalf("unexpected label on no-label image: %q", lr.Label())
	}

	// Reject too-long labels (also exercises SetLabel's error branch via Format).
	tooLong := make([]byte, MaxLabelLen+1)
	for i := range tooLong {
		tooLong[i] = 'x'
	}
	if _, err := Format(filepath.Join(dir, "bad.img"), 1<<20, FormatConfig{Label: string(tooLong)}); err == nil {
		t.Fatalf("expected Format with oversized label to fail")
	}
}

// TestNTFS_NormalizePath hits the empty and "." branches that the
// existing tests don't cover, plus the relative-path leading-slash path.
func TestNTFS_NormalizePath(t *testing.T) {
	cases := map[string]string{
		"":         "/",
		".":        "/",
		"/":        "/",
		"foo":      "/foo",
		"foo/bar":  "/foo/bar",
		"/foo/":    "/foo",
		"./foo":    "/foo",
		"/a/../b":  "/b",
		"//a//b//": "/a/b",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q)=%q want %q", in, got, want)
		}
	}
}

// TestNTFS_ErrorPaths covers the "not found" and conflict branches across
// the FS API to lift Stat/ReadFile/ReadLink/MkDir/WriteFile/Rename
// coverage.
func TestNTFS_ErrorPaths(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	nf := fs.(*ntfsFS)

	// missing-entry paths
	if _, err := fs.ReadFile("/nope"); err == nil {
		t.Fatal("expected ReadFile error for missing path")
	}
	if _, err := fs.Stat("/nope"); err == nil {
		t.Fatal("expected Stat error for missing path")
	}
	if _, err := nf.GetMetadata("/nope"); err == nil {
		t.Fatal("expected GetMetadata error for missing path")
	}
	if _, err := fs.ReadLink("/nope"); err == nil {
		t.Fatal("expected ReadLink error for missing path")
	}
	if err := fs.DeleteFile("/nope"); err == nil {
		t.Fatal("expected DeleteFile error for missing path")
	}
	if err := fs.Rename("/nope", "/nope2"); err == nil {
		t.Fatal("expected Rename error for missing source")
	}

	// ReadLink on a non-symlink regular file must fail
	if err := fs.WriteFile("/reg", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadLink("/reg"); err == nil {
		t.Fatal("expected ReadLink to fail on non-symlink")
	}

	// WriteFile onto an existing directory must fail
	if err := fs.MkDir("/somedir", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/somedir", []byte("z"), 0o644); err == nil {
		t.Fatal("expected WriteFile to fail on directory")
	}

	// MkDir onto an existing file must fail; MkDir on existing dir is idempotent
	if err := fs.MkDir("/reg", 0o755); err == nil {
		t.Fatal("expected MkDir to fail when target is a file")
	}
	if err := fs.MkDir("/somedir", 0o755); err != nil {
		t.Fatalf("MkDir on existing dir should be idempotent: %v", err)
	}
	// MkDir at "/" is a no-op
	if err := fs.MkDir("/", 0o755); err != nil {
		t.Fatalf("MkDir / should be no-op: %v", err)
	}

	// Rename: moving a directory into itself must fail
	if err := fs.MkDir("/x", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/x/inner", []byte("i"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.Rename("/x", "/x/sub"); err == nil {
		t.Fatal("expected Rename of dir into itself to fail")
	}

	// Rename of a file over an existing file replaces the destination
	if err := fs.WriteFile("/dst", []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.Rename("/reg", "/dst"); err != nil {
		t.Fatalf("Rename overwriting dst failed: %v", err)
	}
	if got, err := fs.ReadFile("/dst"); err != nil || string(got) != "x" {
		t.Fatalf("after rename overwrite, /dst content wrong: %q err=%v", got, err)
	}

	// In-place overwrite (new data shorter than old) — exercises the
	// in-place WriteFile branch.
	if err := fs.WriteFile("/dst", []byte("a"), 0o644); err != nil {
		t.Fatalf("WriteFile shrink: %v", err)
	}
	if got, _ := fs.ReadFile("/dst"); string(got) != "a" {
		t.Fatalf("in-place shrink content wrong: %q", got)
	}

	// DeleteDir at "/" wipes user content. The root entry is recreated
	// by saveIndex so the only surviving entry should be "/" itself.
	if err := fs.DeleteDir("/"); err != nil {
		t.Fatalf("DeleteDir /: %v", err)
	}
	for k := range nf.index {
		if k != "/" {
			t.Fatalf("DeleteDir / left %q in the index", k)
		}
	}

	// Stat with a custom mode (Chmod-style) exercises the me.Mode != 0
	// branches on both file and dir Stat paths.
	if err := fs.WriteFile("/m", []byte("zz"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fs.MkDir("/dm", 0o700); err != nil {
		t.Fatal(err)
	}
	if st, err := fs.Stat("/m"); err != nil || st.Mode() == 0 {
		t.Fatalf("Stat /m: %v mode=%v", err, st)
	}
	if st, err := fs.Stat("/dm"); err != nil || st.Mode() == 0 {
		t.Fatalf("Stat /dm: %v mode=%v", err, st)
	}
}

// TestNTFS_LoadIndexCornerCases pushes a few harder loadIndex branches:
// reopening an image that already has files (which forces the
// "ensure metadata for entries that lacked it" loop at line 251) and
// reopening one where the saved label survives a re-save round trip.
func TestNTFS_LoadIndexCornerCases(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/k1", []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/k2", []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.SetLabel("PERSIST"); err != nil {
		t.Fatal(err)
	}
	// First reopen — pure read.
	fs.Close()

	fs2, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fs2.Label() != "PERSIST" {
		t.Fatalf("label lost on first reopen: %q", fs2.Label())
	}
	// Touch the FS to force a save, then reopen again.
	if err := fs2.WriteFile("/k3", []byte("v3"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs2.Close()

	fs3, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs3.Close()
	if fs3.Label() != "PERSIST" {
		t.Fatalf("label lost on second reopen: %q", fs3.Label())
	}
	for _, key := range []string{"/k1", "/k2", "/k3"} {
		if _, err := fs3.ReadFile(key); err != nil {
			t.Fatalf("missing %s after second reopen: %v", key, err)
		}
	}

	// Verify Layout returns entries in offset order — second integration
	// of Layout against a reopened image.
	layout := fs3.Layout()
	sorted := make([]uint64, len(layout))
	for i, l := range layout {
		sorted[i] = l.Offset
	}
	if !sort.SliceIsSorted(sorted, func(i, j int) bool { return sorted[i] < sorted[j] }) {
		t.Fatalf("Layout not sorted: %v", sorted)
	}
}
