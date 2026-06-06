package filesystem_ntfs

import (
	"path/filepath"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

func openFreshNtfs(t *testing.T) (FS, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "image.img")
	fs, err := Format(p, 4*1024*1024, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	return fs.(FS), p
}

func TestNtfsSetLabel_Roundtrip(t *testing.T) {
	fs, _ := openFreshNtfs(t)
	defer fs.Close()
	if got := fs.Label(); got != "" {
		t.Errorf("default Label() = %q, want empty", got)
	}
	if err := fs.SetLabel("WinVolume"); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}
	if got := fs.Label(); got != "WinVolume" {
		t.Errorf("Label() after SetLabel = %q, want %q", got, "WinVolume")
	}
}

func TestNtfsSetLabel_PersistsAcrossReopen(t *testing.T) {
	fs, img := openFreshNtfs(t)
	if err := fs.SetLabel("PERSIST"); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}
	fs.Close()

	fs2, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs2.Close()
	l, ok := fs2.(filesystem.Labeller)
	if !ok {
		t.Fatal("reopened ntfs does not implement Labeller")
	}
	if got := l.Label(); got != "PERSIST" {
		t.Errorf("after reopen Label() = %q, want %q", got, "PERSIST")
	}
}

func TestNtfsSetLabel_FormatConfigSeedsLabel(t *testing.T) {
	p := filepath.Join(t.TempDir(), "image.img")
	fs, err := Format(p, 4*1024*1024, FormatConfig{Label: "SEEDED"})
	if err != nil {
		t.Fatalf("Format with Label: %v", err)
	}
	defer fs.Close()
	if got := fs.(FS).Label(); got != "SEEDED" {
		t.Errorf("seeded Label() = %q, want %q", got, "SEEDED")
	}
	// And confirm the cfg.Label flows through to disk: reopen and check.
	fs.Close()
	fs2, err := Open(p, 0)
	if err != nil {
		t.Fatalf("Open after seeded Format: %v", err)
	}
	defer fs2.Close()
	if got := fs2.(FS).Label(); got != "SEEDED" {
		t.Errorf("seeded label not persisted: Label() = %q after reopen", got)
	}
}

func TestNtfsSetLabel_RejectsTooLong(t *testing.T) {
	fs, _ := openFreshNtfs(t)
	defer fs.Close()
	before := fs.Label()
	if err := fs.SetLabel(strings.Repeat("x", MaxLabelLen+1)); err == nil {
		t.Error("SetLabel with oversize input unexpectedly succeeded")
	}
	if after := fs.Label(); after != before {
		t.Errorf("Label() changed after rejected SetLabel: %q -> %q", before, after)
	}
}

func TestNtfsSetLabel_EmptyClearsAcrossReopen(t *testing.T) {
	fs, img := openFreshNtfs(t)
	if err := fs.SetLabel("temporary"); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}
	if err := fs.SetLabel(""); err != nil {
		t.Fatalf("SetLabel empty: %v", err)
	}
	fs.Close()

	fs2, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs2.Close()
	if got := fs2.(FS).Label(); got != "" {
		t.Errorf("after clearing label, Label() = %q, want empty", got)
	}
}

func TestNtfsSetLabel_LabelerInterface(t *testing.T) {
	fs, _ := openFreshNtfs(t)
	defer fs.Close()
	var f filesystem.Filesystem = fs
	if _, ok := f.(filesystem.Labeller); !ok {
		t.Error("ntfsFS does not satisfy filesystem.Labeller")
	}
}
