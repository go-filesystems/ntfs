// SPDX-License-Identifier: BSD-3-Clause

package filesystem_ntfs

import (
	"errors"
	iofs "io/fs"
	"path/filepath"
	"testing"
)

// ⛔ The error contract from go-filesystems/interface: a path that is not
// there must satisfy errors.Is(err, fs.ErrNotExist).
//
// Every server in this family classifies with errors.Is, and each keeps a
// fallback table of driver message fragments for the drivers that do not
// answer it. webdav's own comment calls that table "a *last* resort" and says
// the real fix belongs here.
//
// ⭐ This test found a SEPARATE defect, which is the argument for having it:
// ListDir walked the index by prefix and never checked that the directory
// itself existed, so a missing path produced an EMPTY listing and a nil error.
// A server reads that as "the directory is there and is empty" rather than as
// 404. Every other operation here refused the missing path; that one answered
// it.
//
// Six sites, all of them a path lookup. Nothing about internal structure was touched
// -- a driver that says "not found" about its own metadata and gets wrapped
// makes a server answer 404 for a corrupt image, which hides a real fault
// behind a routine one.
func TestMissingPathsSatisfyErrNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fs.img")
	fsys, err := Format(path, 32<<20, FormatConfig{Label: "ERRTEST"})
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()

	for _, tc := range []struct {
		what string
		err  error
	}{
		{"Stat", func() error { _, e := fsys.Stat("/nope.txt"); return e }()},
		{"ReadFile", func() error { _, e := fsys.ReadFile("/nope.txt"); return e }()},
		{"ListDir", func() error { _, e := fsys.ListDir("/nope"); return e }()},
		{"Rename", fsys.Rename("/nope.txt", "/other.txt")},
	} {
		if tc.err == nil {
			t.Errorf("%s on a missing path returned no error at all", tc.what)
			continue
		}
		if !errors.Is(tc.err, iofs.ErrNotExist) {
			t.Errorf("%s: errors.Is(err, fs.ErrNotExist) is false for %q", tc.what, tc.err)
		}
	}
}
