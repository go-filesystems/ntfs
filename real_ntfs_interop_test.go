// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) the go-filesystems/ntfs authors

package filesystem_ntfs

// Gold-standard interoperability tests: these build genuine NTFS images with
// the Linux ntfsprogs / ntfs-3g toolchain (mkntfs + a FUSE mount) and then
// read them back through this package's real-NTFS reader, asserting the
// on-disk structures we decode match exactly what a real NTFS implementation
// wrote. They are skip-gated on the tools being present (and on the mount
// succeeding, which needs /dev/fuse), so CI without the toolchain still passes
// while a developer on a Linux host with ntfs-3g exercises the real path.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ntfs3gEnv locates the ntfsprogs/ntfs-3g tools or skips the test.
type ntfs3gEnv struct {
	mkntfs string
	ntfs3g string
	umount string
}

func requireNtfs3g(t *testing.T) ntfs3gEnv {
	t.Helper()
	var e ntfs3gEnv
	for _, p := range []string{"mkntfs", "/usr/sbin/mkntfs", "/sbin/mkntfs"} {
		if _, err := os.Stat(p); err == nil {
			e.mkntfs = p
			break
		}
	}
	if e.mkntfs == "" {
		if p, err := exec.LookPath("mkntfs"); err == nil {
			e.mkntfs = p
		}
	}
	g, err := exec.LookPath("ntfs-3g")
	if err != nil || e.mkntfs == "" {
		t.Skip("mkntfs/ntfs-3g not available; skipping gold interop test")
	}
	e.ntfs3g = g
	if u, err := exec.LookPath("umount"); err == nil {
		e.umount = u
	} else {
		e.umount = "umount"
	}
	return e
}

// sh runs a command, failing the test on error with combined output.
func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// buildNtfs3gImage formats an image, mounts it via ntfs-3g, runs populate to
// write files, unmounts and returns the image path. It skips (not fails) when
// the FUSE mount cannot be established (e.g. no /dev/fuse in the sandbox).
func buildNtfs3gImage(t *testing.T, e ntfs3gEnv, populate func(mnt string)) string {
	t.Helper()
	dir := t.TempDir()
	img := filepath.Join(dir, "gold.ntfs")
	f, err := os.Create(img)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Truncate(img, 32*1024*1024); err != nil {
		t.Fatal(err)
	}
	sh(t, e.mkntfs, "-F", "-q", "-c", "4096", "-L", "GOLD", img)
	mnt := filepath.Join(dir, "mnt")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(e.ntfs3g, "-o", "streams_interface=windows", img, mnt).CombinedOutput()
	if err != nil {
		t.Skipf("ntfs-3g mount failed (needs /dev/fuse / privileges): %v\n%s", err, out)
	}
	mounted := true
	defer func() {
		if mounted {
			_ = exec.Command(e.umount, mnt).Run()
		}
	}()
	populate(mnt)
	// Flush and unmount so all metadata is on disk before we read it.
	if o, err := exec.Command(e.umount, mnt).CombinedOutput(); err != nil {
		t.Fatalf("umount: %v\n%s", err, o)
	}
	mounted = false
	return img
}

// TestInterop_Compression_Gold proves the LZNT1 decompressor against a file
// genuinely compressed by ntfs-3g. The content is large and compressible so
// ntfs-3g stores it in multiple compression units.
func TestInterop_Compression_Gold(t *testing.T) {
	e := requireNtfs3g(t)
	// ~180 KiB of compressible text spanning several 64 KiB compression units.
	var want bytes.Buffer
	for i := 0; want.Len() < 180*1024; i++ {
		want.WriteString("The quick brown fox jumps over the lazy dog. ")
		if i%7 == 0 {
			want.WriteByte('\n')
		}
	}
	payload := want.Bytes()

	img := buildNtfs3gImage(t, e, func(mnt string) {
		cdir := filepath.Join(mnt, "cdir")
		sh(t, "mkdir", "-p", cdir)
		// Mark the directory compressed so ntfs-3g compresses files inside it.
		sh(t, "setfattr", "-h", "-n", "system.ntfs_attrib_be", "-v", "0x00000800", cdir)
		if err := os.WriteFile(filepath.Join(cdir, "comp.txt"), payload, 0o644); err != nil {
			t.Fatal(err)
		}
	})

	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open gold image: %v", err)
	}
	defer fs.Close()
	got, err := fs.ReadFile("/cdir/comp.txt")
	if err != nil {
		t.Fatalf("ReadFile(/cdir/comp.txt): %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decompressed content mismatch: got %d bytes, want %d bytes; firstdiff shows LZNT1 decode error", len(got), len(payload))
	}
	t.Logf("LZNT1 gold: %d bytes decompressed byte-exact from ntfs-3g image", len(got))
}

// TestInterop_ADS_Gold proves named data streams (ADS) read back byte-exact.
func TestInterop_ADS_Gold(t *testing.T) {
	e := requireNtfs3g(t)
	base := []byte("primary stream content\n")
	adsData := []byte("ALTERNATE-DATA-STREAM-payload")
	img := buildNtfs3gImage(t, e, func(mnt string) {
		if err := os.WriteFile(filepath.Join(mnt, "host.txt"), base, 0o644); err != nil {
			t.Fatal(err)
		}
		// The windows streams interface exposes ADS as "file:stream".
		if err := os.WriteFile(filepath.Join(mnt, "host.txt:author"), adsData, 0o644); err != nil {
			t.Skipf("ADS write not supported by this ntfs-3g: %v", err)
		}
	})
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	sr, ok := fs.(StreamReader)
	if !ok {
		t.Fatalf("real NTFS reader does not implement StreamReader")
	}
	names, err := sr.ListStreams("/host.txt")
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	foundADS := false
	for _, n := range names {
		if n == "author" {
			foundADS = true
		}
	}
	if !foundADS {
		t.Fatalf("ListStreams(/host.txt) = %v, missing \"author\"", names)
	}
	got, err := sr.ReadStream("/host.txt", "author")
	if err != nil {
		t.Fatalf("ReadStream author: %v", err)
	}
	if !bytes.Equal(got, adsData) {
		t.Fatalf("ADS content = %q, want %q", got, adsData)
	}
	// The default stream still reads correctly.
	def, err := fs.ReadFile("/host.txt")
	if err != nil || !bytes.Equal(def, base) {
		t.Fatalf("default stream = %q err=%v, want %q", def, err, base)
	}
}

// TestInterop_Symlink_Gold proves ReadLink resolves an ntfs-3g symlink (which
// ntfs-3g stores in the IntxLNK $DATA convention by default).
func TestInterop_Symlink_Gold(t *testing.T) {
	e := requireNtfs3g(t)
	img := buildNtfs3gImage(t, e, func(mnt string) {
		if err := os.WriteFile(filepath.Join(mnt, "target.txt"), []byte("data\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("target.txt", filepath.Join(mnt, "rel.lnk")); err != nil {
			t.Skipf("symlink create not supported: %v", err)
		}
	})
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()
	got, err := fs.ReadLink("/rel.lnk")
	if err != nil {
		t.Fatalf("ReadLink(/rel.lnk): %v", err)
	}
	if !strings.Contains(got, "target.txt") {
		t.Fatalf("ReadLink(/rel.lnk) = %q, want to contain target.txt", got)
	}
}
