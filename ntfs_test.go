package filesystem_ntfs

import (
	"bytes"
	"path/filepath"
	"sort"
	"testing"
)

func TestNTFS_ReadWrite(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	data := []byte("hello ntfs")
	if err := fs.WriteFile("/hello.txt", data, 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	got, err := fs.ReadFile("/hello.txt")
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("ReadFile content mismatch: got %q want %q", got, data)
	}
}

func TestNTFS_ListMkDeleteRename(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if err := fs.MkDir("/subdir", 0o755); err != nil {
		t.Fatalf("MkDir failed: %v", err)
	}
	if err := fs.WriteFile("/subdir/file.txt", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	entries, err := fs.ListDir("/subdir")
	if err != nil {
		t.Fatalf("ListDir failed: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "file.txt" {
		t.Fatalf("unexpected entries: %#v", entries)
	}

	if err := fs.Rename("/subdir/file.txt", "/subdir/file2.txt"); err != nil {
		t.Fatalf("Rename failed: %v", err)
	}
	if _, err := fs.ReadFile("/subdir/file2.txt"); err != nil {
		t.Fatalf("ReadFile after rename failed: %v", err)
	}

	if err := fs.DeleteFile("/subdir/file2.txt"); err != nil {
		t.Fatalf("DeleteFile failed: %v", err)
	}
	if err := fs.DeleteDir("/subdir"); err != nil {
		t.Fatalf("DeleteDir failed: %v", err)
	}

	// ensure backing dir exists where expected
	if fp := filepath.Join(dir, ""); fp == "" {
		t.Fatalf("backing dir not found: %s", dir)
	}
}

func TestNTFS_WriteCreatesParents(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if err := fs.WriteFile("/a/b/c.txt", []byte("abc"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := fs.Stat("/a"); err != nil {
		t.Fatalf("parent /a missing: %v", err)
	}
	if _, err := fs.Stat("/a/b"); err != nil {
		t.Fatalf("parent /a/b missing: %v", err)
	}
	b, err := fs.ReadFile("/a/b/c.txt")
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(b) != "abc" {
		t.Fatalf("unexpected content: %q", b)
	}
}

func TestNTFS_RenameDirRecursive(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	if err := fs.MkDir("/a", 0o755); err != nil {
		t.Fatalf("MkDir /a failed: %v", err)
	}
	if err := fs.WriteFile("/a/file1", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := fs.MkDir("/a/sub", 0o755); err != nil {
		t.Fatalf("MkDir /a/sub failed: %v", err)
	}
	if err := fs.WriteFile("/a/sub/file2", []byte("y"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := fs.Rename("/a", "/b"); err != nil {
		t.Fatalf("Rename failed: %v", err)
	}
	if _, err := fs.ReadFile("/b/file1"); err != nil {
		t.Fatalf("expected /b/file1 after rename: %v", err)
	}
	if _, err := fs.ReadFile("/b/sub/file2"); err != nil {
		t.Fatalf("expected /b/sub/file2 after rename: %v", err)
	}
	if _, err := fs.Stat("/a"); err == nil {
		t.Fatalf("old directory /a still exists after rename")
	}
}

func TestNTFS_FreeListReuse(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	// Open returns the public FS interface, but this test inspects
	// internal allocator state — drop down to the concrete driver.
	nf := fs.(*ntfsFS)

	// create a large file
	data := make([]byte, 4096)
	if err := fs.WriteFile("/big", data, 0o644); err != nil {
		t.Fatalf("WriteFile /big failed: %v", err)
	}
	offBig := nf.index["/big"].Offset

	// delete it -> frees space
	if err := fs.DeleteFile("/big"); err != nil {
		t.Fatalf("DeleteFile failed: %v", err)
	}
	// allocate smaller file -> should reuse freed space
	small := make([]byte, 1024)
	if err := fs.WriteFile("/small", small, 0o644); err != nil {
		t.Fatalf("WriteFile /small failed: %v", err)
	}
	offSmall := nf.index["/small"].Offset
	if offSmall != offBig {
		t.Fatalf("expected /small to reuse offset %d, got %d", offBig, offSmall)
	}

	// allocate a larger file than remaining free slot -> should allocate at end
	large := make([]byte, 8192)
	if err := fs.WriteFile("/large", large, 0o644); err != nil {
		t.Fatalf("WriteFile /large failed: %v", err)
	}
	offLarge := nf.index["/large"].Offset
	if offLarge == offSmall {
		t.Fatalf("expected /large to allocate at new location, but reused %d", offSmall)
	}
}

func TestNTFS_CompactAndMetadata(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "image.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	// Drop down to the concrete driver to inspect the internal index /
	// free list and call concrete-only helpers (GetMetadata).
	nf := fs.(*ntfsFS)

	// create several files and a gap
	if err := fs.WriteFile("/f1", make([]byte, 1024), 0o644); err != nil {
		t.Fatalf("WriteFile f1 failed: %v", err)
	}
	if err := fs.WriteFile("/f2", make([]byte, 2048), 0o644); err != nil {
		t.Fatalf("WriteFile f2 failed: %v", err)
	}
	if err := fs.WriteFile("/f3", make([]byte, 512), 0o644); err != nil {
		t.Fatalf("WriteFile f3 failed: %v", err)
	}

	offF2 := nf.index["/f2"].Offset
	// delete middle file to create a hole
	if err := fs.DeleteFile("/f2"); err != nil {
		t.Fatalf("DeleteFile f2 failed: %v", err)
	}
	// allocate a smaller file that should reuse the freed space
	if err := fs.WriteFile("/f4", make([]byte, 1024), 0o644); err != nil {
		t.Fatalf("WriteFile f4 failed: %v", err)
	}
	if nf.index["/f4"].Offset != offF2 {
		t.Fatalf("expected /f4 to reuse offset %d, got %d", offF2, nf.index["/f4"].Offset)
	}

	// record pre-compact offsets
	offs := make([]uint64, 0)
	sizes := make(map[uint64]uint64)
	for k, v := range nf.index {
		if v.IsDir {
			continue
		}
		offs = append(offs, v.Offset)
		sizes[v.Offset] = v.Size
		_ = k
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })

	// compact and verify contiguous layout and metadata preserved
	if err := fs.Compact(); err != nil {
		t.Fatalf("Compact failed: %v", err)
	}

	// after compaction freeList should be at most one tail extent
	if len(nf.freeList) > 1 {
		t.Fatalf("expected <=1 free extent after compact, got %d", len(nf.freeList))
	}

	// check files are contiguous by sorting by offset
	type ent struct{ Off, Size uint64 }
	ents := make([]ent, 0)
	for _, v := range nf.index {
		if v.IsDir {
			continue
		}
		ents = append(ents, ent{Off: v.Offset, Size: v.Size})
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Off < ents[j].Off })
	for i := 1; i < len(ents); i++ {
		if ents[i].Off != ents[i-1].Off+ents[i-1].Size {
			t.Fatalf("non-contiguous after compact: %d followed by %d (prev size %d)", ents[i-1].Off, ents[i].Off, ents[i-1].Size)
		}
	}

	// metadata: ensure inode and timestamps present and symlink works
	if err := fs.WriteFile("/m1", []byte("meta"), 0o600); err != nil {
		t.Fatalf("WriteFile m1 failed: %v", err)
	}
	me, err := nf.GetMetadata("/m1")
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}
	if me.Inode == 0 {
		t.Fatalf("expected inode > 0, got 0")
	}
	if me.Mtime == 0 || me.Atime == 0 {
		t.Fatalf("expected timestamps set, got atime=%d mtime=%d", me.Atime, me.Mtime)
	}

	// symlink
	if err := fs.Symlink("/m1", "/link1"); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}
	tgt, err := fs.ReadLink("/link1")
	if err != nil {
		t.Fatalf("ReadLink failed: %v", err)
	}
	if tgt != "/m1" {
		t.Fatalf("unexpected symlink target: %q", tgt)
	}
}
