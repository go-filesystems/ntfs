package filesystem_ntfs

import (
	"encoding/binary"
	"errors"
	iofs "io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// 2024-05-17 13:45:30.1234567 UTC as a FILETIME: (1715953530 + 11644473600)
// seconds, times 10^7, plus 1234567 hundred-nanosecond ticks. Written as a
// literal so the test does not use the decoder's own conversion.
const (
	ftSample     = 133604271301234567
	ftSample2    = 133604271311234567 // one second later
	ftSample3    = 133604271321234567 // two seconds later
	ftSample4    = 133604271331234567 // three seconds later
	ftMaxValid   = 1<<63 - 1
	ftBigVolumes = 0xFFFFFFFFFFFFFFFF
)

func filetimes(c, m, ch, a uint64) []byte {
	b := make([]byte, 32)
	for i, v := range []uint64{c, m, ch, a} {
		binary.LittleEndian.PutUint64(b[i*8:], v)
	}
	return b
}

// synthWithRecord builds the synthetic image, then replaces the MFT record of
// /hello.txt with one carrying exactly the given attributes.
func synthWithRecord(t *testing.T, build func(ab *attrBuilder)) *realNTFS {
	t.Helper()
	img := filepath.Join(t.TempDir(), "synth.ntfs")
	buildSyntheticNTFS(t, img)
	var ab attrBuilder
	build(&ab)
	rec := buildFileRecord(false, ab.finish())
	f, err := os.OpenFile(img, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(rec, int64(tMFTCluster)*tClusterSize+int64(tRecHello)*tMFTRecordSize); err != nil {
		t.Fatal(err)
	}
	f.Close()
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fs.Close() })
	return fs.(*realNTFS)
}

func nameBody(name string, ns byte, times []byte) []byte {
	b := fileNameAttrBody(tRecRoot, name, false)
	copy(b[fileNameTimeOff:], times)
	b[0x41] = ns
	return b
}

func TestTimesStandardInformation(t *testing.T) {
	r := synthWithRecord(t, func(ab *attrBuilder) {
		si := append(filetimes(ftSample, ftSample2, ftSample3, ftSample4), make([]byte, 16)...)
		ab.addResident(attrStandardInformation, "", si)
		// $FILE_NAME copies differ and must NOT be used while $SI is present.
		ab.addResident(attrFileName, "", nameBody("hello.txt", fileNameNamespaceWin32, filetimes(1, 1, 1, 1)))
		ab.addResident(attrData, "", []byte("x"))
	})
	ft, err := r.Times("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 5, 17, 13, 45, 30, 123456700, time.UTC)
	for _, c := range []struct {
		name string
		got  filesystem.Timestamp
		want time.Time
	}{
		{"btime", ft.Btime, base},
		{"mtime", ft.Mtime, base.Add(time.Second)},
		{"ctime", ft.Ctime, base.Add(2 * time.Second)},
		{"atime", ft.Atime, base.Add(3 * time.Second)},
	} {
		g, ok := c.got.Get()
		if !ok || !g.Equal(c.want) {
			t.Errorf("%s = %v, want %v", c.name, g, c.want)
		}
		if c.got.Resolution() != 100*time.Nanosecond {
			t.Errorf("%s resolution %v", c.name, c.got.Resolution())
		}
	}
}

func TestTimesAbsentAndSentinels(t *testing.T) {
	r := synthWithRecord(t, func(ab *attrBuilder) {
		ab.addResident(attrStandardInformation, "", append(filetimes(0, ftBigVolumes, 1<<63, ftMaxValid-1<<62), make([]byte, 16)...))
		ab.addResident(attrData, "", []byte("x"))
	})
	ft, err := r.Times("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if ft.Btime.Recorded() {
		t.Errorf("FILETIME 0 decoded to %v", ft.Btime)
	}
	if ft.Mtime.Recorded() || ft.Ctime.Recorded() {
		t.Errorf("0xFFFF... / top-bit values decoded to %v %v", ft.Mtime, ft.Ctime)
	}
	if !ft.Atime.Recorded() {
		t.Error("a valid in-range FILETIME was dropped")
	}
	if !decodeFiletime(ftMaxValid).Recorded() || decodeFiletime(1).Recorded() == false {
		t.Error("boundaries: 1 tick after 1601 and the largest positive value are recorded")
	}
	if g, _ := decodeFiletime(1).Get(); g.Year() != 1601 {
		t.Errorf("1 tick = %v", g)
	}
}

func TestTimesFileNameFallback(t *testing.T) {
	short := func(ab *attrBuilder) {
		ab.addResident(attrStandardInformation, "", make([]byte, 0x1F)) // shorter than 4 times
		ab.addResident(attrFileName, "", nameBody("HELLO~1.TXT", fileNameNamespaceDOS, filetimes(1, 1, 1, 1)))
		ab.addResident(attrFileName, "", nameBody("hello.txt", fileNameNamespaceWin32, filetimes(ftSample, ftSample2, ftSample3, ftSample4)))
		ab.addResident(attrData, "", []byte("x"))
	}
	r := synthWithRecord(t, short)
	ft, err := r.Times("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := ft.Mtime.Get(); !m.Equal(time.Date(2024, 5, 17, 13, 45, 31, 123456700, time.UTC)) {
		t.Errorf("mtime from $FILE_NAME = %v (the Win32 name must win over the DOS alias)", m)
	}
	if b, _ := ft.Btime.Get(); b.Second() != 30 {
		t.Errorf("btime = %v", b)
	}

	none := synthWithRecord(t, func(ab *attrBuilder) { ab.addResident(attrData, "", []byte("x")) })
	ft, err = none.Times("/hello.txt")
	if err != nil || ft != (filesystem.FileTimes{}) {
		t.Fatalf("no time attributes: %+v %v", ft, err)
	}
}

func TestTimesRootAndMissing(t *testing.T) {
	r := openSynthReader(t)
	if _, err := r.Times("/"); err != nil {
		t.Fatalf("root: %v", err)
	}
	// The synthetic $STANDARD_INFORMATION is all zero: nothing recorded.
	if ft, _ := r.Times("/hello.txt"); ft != (filesystem.FileTimes{}) {
		t.Errorf("zero $SI gave %+v", ft)
	}
	if _, err := r.Times("/nope"); !errors.Is(err, iofs.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
	var _ filesystem.TimesReader = r
}

// TestTimesMkntfsImage reads the root directory of an image formatted by the
// reference tool (ntfs-3g mkntfs), which stamps it with the current time. The
// lane that installs ntfs-3g sets NTFS_REQUIRE_PROGS, so this cannot skip there.
func TestTimesMkntfsImage(t *testing.T) {
	require := os.Getenv("NTFS_REQUIRE_PROGS") != ""
	mkntfs, err := exec.LookPath("mkntfs")
	if err != nil {
		if require {
			t.Fatalf("NTFS_REQUIRE_PROGS set but mkntfs missing: %v", err)
		}
		t.Skip("mkntfs not on PATH")
	}
	img := filepath.Join(t.TempDir(), "times.ntfs")
	f, err := os.Create(img)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Truncate(img, 8<<20); err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-time.Minute)
	if out, err := exec.Command(mkntfs, "-F", "-q", "-L", "TIMES", img).CombinedOutput(); err != nil {
		t.Fatalf("mkntfs: %v\n%s", err, out)
	}
	after := time.Now().Add(time.Minute)
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	tr, ok := fs.(filesystem.TimesReader)
	if !ok {
		t.Fatalf("%T is not a TimesReader", fs)
	}
	ft, err := tr.Times("/")
	if err != nil {
		t.Fatal(err)
	}
	for name, ts := range map[string]filesystem.Timestamp{"btime": ft.Btime, "mtime": ft.Mtime, "ctime": ft.Ctime, "atime": ft.Atime} {
		g, ok := ts.Get()
		if !ok {
			t.Errorf("%s not recorded on a freshly formatted root", name)
			continue
		}
		if g.Before(before) || g.After(after) {
			t.Errorf("%s = %v, outside [%v, %v]", name, g, before, after)
		}
		if ts.Resolution() != 100*time.Nanosecond {
			t.Errorf("%s resolution %v", name, ts.Resolution())
		}
	}
	t.Logf("root: %+v", ft)
}

func FuzzDecodeNTFSTimes(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Add(filetimes(ftSample, ftSample2, ftSample3, ftSample4))
	f.Add(filetimes(ftBigVolumes, 1<<63, ftMaxValid, 1))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 32 {
			return
		}
		ft := decodeNTFSTimes(b[:32])
		for _, ts := range []filesystem.Timestamp{ft.Btime, ft.Mtime, ft.Ctime, ft.Atime} {
			if g, ok := ts.Get(); ok && (g.IsZero() || g.Year() < 1601 || ts.Resolution() != 100*time.Nanosecond) {
				t.Fatalf("recorded %v from %x", g, b[:32])
			}
		}
	})
}
