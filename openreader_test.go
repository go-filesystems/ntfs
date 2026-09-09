package filesystem_ntfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// makeImage writes an image through the path-based constructor, which is what
// the reader-based one has to agree with.
func makeImage(t *testing.T) string {
	t.Helper()
	img := filepath.Join(t.TempDir(), "disk.img")
	fs, err := Open(img, -1)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/hello.txt", []byte("ntfs through a reader"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.MkDir("/sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	return img
}

// A reader and a path must give the same filesystem, because they are the same
// image.
func TestOpenReaderSeesWhatOpenSees(t *testing.T) {
	img := makeImage(t)
	f, err := os.Open(img)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	through, err := OpenReader(f, info.Size())
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer through.Close()

	if got, err := through.ReadFile("/hello.txt"); err != nil || string(got) != "ntfs through a reader" {
		t.Errorf("read %q, %v", got, err)
	}
	entries, err := through.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the root lists %v, want hello.txt and sub", names)
	}
	// The richer interface is still reachable for a caller that wants it.
	if _, ok := through.(FS); !ok {
		t.Error("what came back is not an FS")
	}
}

// A reader that cannot be written refuses writes by name, rather than
// accepting one and losing it.
func TestOpenReaderRefusesWritesItCannotDo(t *testing.T) {
	img := makeImage(t)
	raw, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	ro, err := OpenReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if got, err := ro.ReadFile("/hello.txt"); err != nil || string(got) != "ntfs through a reader" {
		t.Errorf("reading through a read-only reader: %q, %v", got, err)
	}
	if err := ro.WriteFile("/new.txt", []byte("nope"), 0o644); !errors.Is(err, ErrReadOnlyReader) {
		t.Errorf("writing through a read-only reader = %v, want ErrReadOnlyReader", err)
	}

	rw, err := os.OpenFile(img, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	info, err := rw.Stat()
	if err != nil {
		t.Fatal(err)
	}
	w, err := OpenReader(rw, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFile("/written.txt", []byte("through a writer"), 0o644); err != nil {
		t.Errorf("writing through a writable reader: %v", err)
	}
	if got, err := w.ReadFile("/written.txt"); err != nil || string(got) != "through a writer" {
		t.Errorf("reading it back: %q, %v", got, err)
	}
	w.Close()
}

// Close must not close what the caller opened.
func TestOpenReaderDoesNotCloseTheCallersReader(t *testing.T) {
	img := makeImage(t)
	f, err := os.Open(img)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, _ := f.Stat()
	through, err := OpenReader(f, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := through.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadAt(make([]byte, 8), 0); err != nil {
		t.Errorf("the caller's reader was closed underneath it: %v", err)
	}
}

func TestOpenReaderRefusals(t *testing.T) {
	if _, err := OpenReader(nil, 100); err == nil {
		t.Error("OpenReader accepted no reader at all")
	}
	if _, err := OpenReader(bytes.NewReader(nil), 0); err == nil {
		t.Error("OpenReader accepted a size of zero")
	}
}
