package filesystem_ntfs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// Tests for Grow / Shrink / Resize. All target the NTFSIMG1 format
// implemented by this package — they do NOT exercise real NTFS
// on-disk semantics.

// imageSizeOnDisk reads the file size of the backing image from the
// filesystem. Used to verify Grow/Shrink actually changed the
// underlying file's footprint.
func imageSizeOnDisk(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Size()
}

// seedFiles writes a small, deterministic set of files into fs and
// returns a map of path -> content for later verification.
func seedFiles(t *testing.T, fs FS) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 6; i++ {
		sz := 256 + rng.Intn(1024)
		b := make([]byte, sz)
		rng.Read(b)
		p := fmt.Sprintf("/d%d/f%d.bin", i%3, i)
		if err := fs.WriteFile(p, b, 0o644); err != nil {
			t.Fatalf("seed WriteFile %s: %v", p, err)
		}
		out[p] = b
	}
	return out
}

// verifyAll checks every (path, content) pair in want is readable
// from fs and bit-identical.
func verifyAll(t *testing.T, fs FS, want map[string][]byte) {
	t.Helper()
	for p, w := range want {
		got, err := fs.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", p, err)
		}
		if !bytes.Equal(got, w) {
			t.Fatalf("content mismatch on %s (sha got=%x want=%x len got=%d want=%d)",
				p, sha256.Sum256(got), sha256.Sum256(w), len(got), len(w))
		}
	}
}

// TestNTFS_GrowExtendsFile verifies Grow bumps the underlying file
// size and that all previously-written files remain readable.
func TestNTFS_GrowExtendsFile(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "grow.img")

	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	want := seedFiles(t, fs)
	beforeSize := imageSizeOnDisk(t, img)

	const target = int64(headerSize) + 1<<20 // 1 MiB content
	if target <= beforeSize {
		t.Fatalf("test precondition: target %d <= beforeSize %d", target, beforeSize)
	}
	if err := fs.Grow(target); err != nil {
		t.Fatalf("Grow: %v", err)
	}
	afterSize := imageSizeOnDisk(t, img)
	if afterSize != target {
		t.Fatalf("Grow: file size = %d, want %d", afterSize, target)
	}

	// All seeded files survive the grow.
	verifyAll(t, fs, want)

	// And the new tail is exposed as free space.
	_, _, freeExtents, totalFree, _ := fs.FragmentationStats()
	if freeExtents == 0 {
		t.Fatalf("Grow: expected at least one free extent, got 0")
	}
	if totalFree == 0 {
		t.Fatalf("Grow: expected totalFree > 0, got 0")
	}
}

// TestNTFS_GrowPersistsAcrossReopen verifies the new size and the
// updated free-list survive a Close + Open round trip.
func TestNTFS_GrowPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "grow-persist.img")

	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	want := seedFiles(t, fs)
	const target = int64(headerSize) + 256<<10
	if err := fs.Grow(target); err != nil {
		t.Fatalf("Grow: %v", err)
	}
	_, _, freeBefore, totalBefore, _ := fs.FragmentationStats()
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fs2, err := Open(img, 0)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer fs2.Close()
	if got := imageSizeOnDisk(t, img); got != target {
		t.Fatalf("post-reopen size = %d, want %d", got, target)
	}
	verifyAll(t, fs2, want)
	_, _, freeAfter, totalAfter, _ := fs2.FragmentationStats()
	if freeAfter != freeBefore || totalAfter != totalBefore {
		t.Fatalf("free-list changed across reopen: extents %d->%d total %d->%d",
			freeBefore, freeAfter, totalBefore, totalAfter)
	}
}

// TestNTFS_GrowRejectsShrinkRequest verifies Grow refuses to make the
// image smaller (or stay the same size).
func TestNTFS_GrowRejectsShrinkRequest(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "grow-refuse.img")

	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	cur := imageSizeOnDisk(t, img)
	if err := fs.Grow(cur); err == nil {
		t.Fatalf("Grow(equal) succeeded; want error")
	}
	if err := fs.Grow(cur - 1); err == nil {
		t.Fatalf("Grow(smaller) succeeded; want error")
	}
	if err := fs.Grow(0); err == nil {
		t.Fatalf("Grow(0) succeeded; want error")
	}
	if err := fs.Grow(-1); err == nil {
		t.Fatalf("Grow(-1) succeeded; want error")
	}
}

// TestNTFS_ShrinkTrims verifies Shrink reduces the file size and
// keeps live files readable.
func TestNTFS_ShrinkTrims(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "shrink.img")

	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	// Make the image large first so we have headroom to shrink.
	const big = int64(headerSize) + 2<<20
	if err := fs.Grow(big); err != nil {
		t.Fatalf("Grow: %v", err)
	}
	want := seedFiles(t, fs)

	// Highest used offset is small; shrink to header + 256 KiB.
	const small = int64(headerSize) + 256<<10
	if small >= big {
		t.Fatalf("test precondition: small %d >= big %d", small, big)
	}
	if err := fs.Shrink(small); err != nil {
		t.Fatalf("Shrink: %v", err)
	}
	if got := imageSizeOnDisk(t, img); got != small {
		t.Fatalf("Shrink: size = %d, want %d", got, small)
	}
	verifyAll(t, fs, want)
}

// TestNTFS_ShrinkRejectsTooSmall verifies Shrink returns
// ErrShrinkTooSmall when live data extends past the requested size.
func TestNTFS_ShrinkRejectsTooSmall(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "shrink-small.img")

	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	// Lay down a file that consumes content offsets [0, 32 KiB).
	payload := make([]byte, 32<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := fs.WriteFile("/big.bin", payload, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cur := imageSizeOnDisk(t, img)
	if cur <= int64(headerSize)+int64(len(payload)) {
		// allocator may extend exactly; nudge target slightly under
	}

	// Request a shrink that lands inside /big.bin's blob.
	target := int64(headerSize) + int64(len(payload))/2
	err = fs.Shrink(target)
	if err == nil {
		t.Fatalf("Shrink(too small) succeeded; want error")
	}
	if !errors.Is(err, ErrShrinkTooSmall) {
		t.Fatalf("Shrink error = %v, want errors.Is ErrShrinkTooSmall", err)
	}
	// File size on disk MUST be unchanged when shrink refuses.
	if got := imageSizeOnDisk(t, img); got != cur {
		t.Fatalf("Shrink refused but truncated anyway: size %d -> %d", cur, got)
	}
	// File still readable.
	got, err := fs.ReadFile("/big.bin")
	if err != nil {
		t.Fatalf("post-refused-shrink ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("post-refused-shrink content mismatch")
	}
}

// TestNTFS_ShrinkValidationErrors covers the cheap input-validation
// branches of Shrink.
func TestNTFS_ShrinkValidationErrors(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "shrink-val.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	if err := fs.Shrink(0); err == nil {
		t.Fatalf("Shrink(0) succeeded; want error")
	}
	if err := fs.Shrink(-1); err == nil {
		t.Fatalf("Shrink(-1) succeeded; want error")
	}
	if err := fs.Shrink(int64(headerSize) - 1); err == nil {
		t.Fatalf("Shrink(header-1) succeeded; want error")
	}
	// Equal-size or larger shrink is rejected.
	cur := imageSizeOnDisk(t, img)
	if err := fs.Shrink(cur); err == nil {
		t.Fatalf("Shrink(cur) succeeded; want error")
	}
	if err := fs.Shrink(cur + 1); err == nil {
		t.Fatalf("Shrink(cur+1) succeeded; want error")
	}
}

// TestNTFS_ShrinkTrimsFreeList verifies free-list extents past the
// new tail are clipped or dropped on shrink.
func TestNTFS_ShrinkTrimsFreeList(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "shrink-fl.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	// Build a big image and put nothing in it, so the entire content
	// region is free.
	const big = int64(headerSize) + 4<<20
	if err := fs.Grow(big); err != nil {
		t.Fatalf("Grow: %v", err)
	}
	_, _, _, totalBefore, _ := fs.FragmentationStats()
	if totalBefore == 0 {
		t.Fatalf("expected free space after grow; got 0")
	}

	const target = int64(headerSize) + 64<<10
	if err := fs.Shrink(target); err != nil {
		t.Fatalf("Shrink: %v", err)
	}
	_, _, _, totalAfter, _ := fs.FragmentationStats()
	maxAfter := uint64(target - int64(headerSize))
	if totalAfter > maxAfter {
		t.Fatalf("Shrink: free-list total %d > new capacity %d", totalAfter, maxAfter)
	}
}

// TestNTFS_ResizeDispatches verifies Resize calls the right
// underlying operation depending on the requested direction.
func TestNTFS_ResizeDispatches(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "resize.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	want := seedFiles(t, fs)

	// Grow path.
	const big = int64(headerSize) + 1<<20
	if err := fs.Resize(big); err != nil {
		t.Fatalf("Resize(big): %v", err)
	}
	if got := imageSizeOnDisk(t, img); got != big {
		t.Fatalf("after Resize(big) size = %d, want %d", got, big)
	}
	verifyAll(t, fs, want)

	// No-op path.
	if err := fs.Resize(big); err != nil {
		t.Fatalf("Resize(no-op): %v", err)
	}
	if got := imageSizeOnDisk(t, img); got != big {
		t.Fatalf("after Resize(no-op) size = %d, want %d", got, big)
	}

	// Shrink path.
	const small = int64(headerSize) + 128<<10
	if err := fs.Resize(small); err != nil {
		t.Fatalf("Resize(small): %v", err)
	}
	if got := imageSizeOnDisk(t, img); got != small {
		t.Fatalf("after Resize(small) size = %d, want %d", got, small)
	}
	verifyAll(t, fs, want)
}

// TestNTFS_ResizeValidation covers the input-validation branches of
// Resize that aren't reached through Grow/Shrink directly.
func TestNTFS_ResizeValidation(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "resize-val.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	if err := fs.Resize(0); err == nil {
		t.Fatalf("Resize(0) succeeded; want error")
	}
	if err := fs.Resize(-1); err == nil {
		t.Fatalf("Resize(-1) succeeded; want error")
	}
}

// TestNTFS_GrowShrinkCycle exercises a Grow + Shrink cycle paired
// with the corruption-fix regression: between resize ops we churn
// the allocator (write/delete) and verify data integrity, mirroring
// the layout the stress-test suite uses.
func TestNTFS_GrowShrinkCycle(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "cycle.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	rng := rand.New(rand.NewSource(42))
	committed := map[string][]byte{}
	writeOne := func(p string) {
		sz := 256 + rng.Intn(2048)
		b := make([]byte, sz)
		rng.Read(b)
		if err := fs.WriteFile(p, b, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", p, err)
		}
		committed[p] = b
	}

	for i := 0; i < 8; i++ {
		writeOne(fmt.Sprintf("/cycle/a%d.bin", i))
	}

	// Cycle: grow, churn, shrink, churn, repeat.
	sizes := []int64{
		int64(headerSize) + 1<<20,
		int64(headerSize) + 256<<10,
		int64(headerSize) + 2<<20,
		int64(headerSize) + 512<<10,
	}
	for round, target := range sizes {
		cur := imageSizeOnDisk(t, img)
		if target > cur {
			if err := fs.Grow(target); err != nil {
				t.Fatalf("round %d Grow(%d): %v", round, target, err)
			}
		} else if target < cur {
			if err := fs.Shrink(target); err != nil {
				// In a shrink that lands too small we expect
				// ErrShrinkTooSmall — none of these targets
				// should trip that on the seeded payload.
				t.Fatalf("round %d Shrink(%d): %v", round, target, err)
			}
		}
		// Churn: a few writes (some overwrite, some new) and a
		// delete. This stresses the same alloc/free interaction
		// the recent end-of-data fix targeted.
		for i := 0; i < 4; i++ {
			writeOne(fmt.Sprintf("/cycle/r%d_%d.bin", round, i))
		}
		// Overwrite an existing path.
		writeOne("/cycle/a0.bin")
		// Delete a path if we have any.
		var deleteP string
		for p := range committed {
			deleteP = p
			break
		}
		if deleteP != "" {
			if err := fs.DeleteFile(deleteP); err != nil {
				t.Fatalf("DeleteFile %s: %v", deleteP, err)
			}
			delete(committed, deleteP)
		}
		// Verify every still-committed file.
		verifyAll(t, fs, committed)
	}
}

// TestNTFS_GrowToDelegates verifies the filesystem.Grower entrypoint
// works (it's a pass-through to Grow but lives in the public surface).
func TestNTFS_GrowToDelegates(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "growto.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	const target = int64(headerSize) + 64<<10
	if err := fs.(*ntfsFS).GrowTo(target); err != nil {
		t.Fatalf("GrowTo: %v", err)
	}
	if got := imageSizeOnDisk(t, img); got != target {
		t.Fatalf("GrowTo: size = %d, want %d", got, target)
	}
}

// TestNTFS_ShrinkFreeListBoundary covers the free-list trim branches:
// an extent fully past newCap (dropped) AND an extent that straddles
// newCap (clipped). Builds the layout by hand so we know exactly which
// extents to expect.
func TestNTFS_ShrinkFreeListBoundary(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "shrink-bound.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	nf := fs.(*ntfsFS)
	const big = int64(headerSize) + 1<<20
	if err := fs.Grow(big); err != nil {
		t.Fatalf("Grow: %v", err)
	}
	// Replace the auto-installed free list with a hand-built layout
	// covering [0,32 KiB) ; [128 KiB, 192 KiB) ; [512 KiB, 1 MiB).
	nf.freeList = []fileEntry{
		{Offset: 0, Size: 32 << 10},
		{Offset: 128 << 10, Size: 64 << 10},
		{Offset: 512 << 10, Size: 512 << 10},
	}
	if err := nf.saveIndex(); err != nil {
		t.Fatalf("saveIndex: %v", err)
	}

	// Shrink so newCap = 150 KiB. Expected after shrink:
	//   - [0, 32 KiB)        : fully inside, kept.
	//   - [128 KiB, 192 KiB) : straddles, clipped to [128 KiB, 150 KiB).
	//   - [512 KiB, 1 MiB)   : fully past, dropped.
	const newCap = uint64(150 << 10)
	target := int64(headerSize) + int64(newCap)
	if err := fs.Shrink(target); err != nil {
		t.Fatalf("Shrink: %v", err)
	}
	if got := uint64(imageSizeOnDisk(t, img) - int64(headerSize)); got != newCap {
		t.Fatalf("post-shrink cap = %d, want %d", got, newCap)
	}
	if len(nf.freeList) != 2 {
		t.Fatalf("free-list len = %d, want 2: %#v", len(nf.freeList), nf.freeList)
	}
	if nf.freeList[0].Offset != 0 || nf.freeList[0].Size != 32<<10 {
		t.Fatalf("free-list[0] = %#v, want {0, 32 KiB}", nf.freeList[0])
	}
	if nf.freeList[1].Offset != 128<<10 || nf.freeList[1].Size != (150-128)<<10 {
		t.Fatalf("free-list[1] = %#v, want {128 KiB, 22 KiB}", nf.freeList[1])
	}
}

// TestNTFS_GrowOnUnsupportedBackend verifies Grow / Shrink / Resize
// surface a clear error when the backing store doesn't expose
// truncate (i.e. the fault-injection wrapper in stress_test.go).
func TestNTFS_GrowOnUnsupportedBackend(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "unsup.img")
	// Seed with a valid header through the public API.
	{
		fs, err := Open(img, 0)
		if err != nil {
			t.Fatalf("seed Open: %v", err)
		}
		if err := fs.Close(); err != nil {
			t.Fatalf("seed Close: %v", err)
		}
	}
	f, err := os.OpenFile(img, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	frw := newFaultRW(f)
	fs := &ntfsFS{f: frw, partOffset: 0, index: map[string]fileEntry{}}
	if err := fs.loadIndex(); err != nil {
		frw.Close()
		t.Fatalf("loadIndex: %v", err)
	}
	defer fs.Close()

	if err := fs.Grow(int64(headerSize) + 1<<20); err == nil {
		t.Fatalf("Grow on unsupported backend succeeded; want error")
	}
	if err := fs.Shrink(int64(headerSize)); err == nil {
		t.Fatalf("Shrink on unsupported backend succeeded; want error")
	}
	if err := fs.Resize(int64(headerSize) + 1<<20); err == nil {
		t.Fatalf("Resize on unsupported backend succeeded; want error")
	}
}
