package filesystem_ntfs

import (
	"strings"
	"testing"
)

// The image index stores each entry's size as a raw uint64 and nothing validated
// it, so ReadFile did `make([]byte, e.Size)` on a number an attacker chose. A
// large enough value does not return an error, it panics —
//
//	panic: runtime error: makeslice: len out of range   (ntfs.go:692)
//
// — which takes down the calling process. Found by fuzzing FuzzOpen.
func TestReadFileRejectsAnOversizedIndexEntry(t *testing.T) {
	for _, tc := range []struct {
		name string
		size uint64
	}{
		{"beyond any real image", 1 << 51},
		{"past the slice limit", ^uint64(0) - 4096},
		// A literal, not maxEntryBytes+1: this test has to compile against the
		// unfixed code too, or it cannot demonstrate that it catches the bug.
		{"just past the entry ceiling", (1 << 50) + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := &ntfsFS{
				f:     &memDisk{data: make([]byte, headerSize+4096)},
				index: map[string]fileEntry{"/big": {Offset: 0, Size: tc.size}},
				meta:  map[string]metaEntry{},
			}
			// The point of the test is that this returns rather than panics.
			got, err := fs.ReadFile("/big")
			if err == nil {
				t.Fatalf("a %d-byte claim over a 4 KiB image was accepted, returning %d bytes", tc.size, len(got))
			}
			if !strings.Contains(err.Error(), "/big") {
				t.Errorf("error should name the offending path, got %q", err)
			}
		})
	}
}

// A truthful entry still reads, so the guard is not simply refusing everything.
func TestReadFileStillReadsAValidEntry(t *testing.T) {
	d := &memDisk{data: make([]byte, headerSize+4096)}
	want := []byte("hello")
	copy(d.data[headerSize:], want)
	if false {
		t.Fatal("unreachable")
	}
	fs := &ntfsFS{
		f:     d,
		index: map[string]fileEntry{"/ok": {Offset: 0, Size: uint64(len(want))}},
		meta:  map[string]metaEntry{},
	}
	got, err := fs.ReadFile("/ok")
	if err != nil {
		t.Fatalf("a valid entry was refused: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("read %q, want %q", got, want)
	}
}
