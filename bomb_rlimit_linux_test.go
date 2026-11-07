//go:build linux

package filesystem_ntfs

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The bomb tests that run in-process only show that a refusal happens; they
// cannot show that the host was never asked for the memory. This one runs the
// bomb in a child process whose address space is capped (RLIMIT_AS) and whose
// heap is capped (GOMEMLIMIT), and asserts that the child exits normally having
// REFUSED: an allocation sized by the image would end it with an out-of-memory
// crash instead.
//
// The race detector reserves terabytes of address space, so it cannot run under
// RLIMIT_AS: with -race the parent builds a plain test binary for the child.

const bombChildEnv = "NTFS_BOMB_CHILD"

const bombAddressSpace = 1 << 30 // 1 GiB of address space for the whole child

func TestBomb_UnderAddressSpaceLimit(t *testing.T) {
	if os.Getenv(bombChildEnv) == "1" {
		bombChild()
		return
	}
	bin := os.Args[0]
	if raceEnabled {
		bin = filepath.Join(t.TempDir(), "ntfs.test")
		build := exec.Command("go", "test", "-c", "-o", bin, ".")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("building the child test binary: %v\n%s", err, out)
		}
	}
	cmd := exec.Command(bin, "-test.run=^TestBomb_UnderAddressSpaceLimit$", "-test.v")
	cmd.Env = append(os.Environ(), bombChildEnv+"=1", "GOMEMLIMIT=256MiB")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the child did not exit cleanly under RLIMIT_AS=%d (an out-of-memory crash, or a bomb that was not refused): %v\n%s", bombAddressSpace, err, out)
	}
	for _, want := range []string{"bomb: limit set", "bomb: refused size (ErrTooLarge)", "bomb: refused plain size (ErrTooLarge)", "bomb: refused unit", "bomb: window read ok"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the child never reported %q:\n%s", want, out)
		}
	}
}

func bombChild() {
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "bomb: "+format+"\n", a...)
		os.Exit(1)
	}
	lim := syscall.Rlimit{Cur: bombAddressSpace, Max: bombAddressSpace}
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &lim); err != nil {
		fail("Setrlimit: %v", err)
	}
	var got syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &got); err != nil || got.Cur != bombAddressSpace {
		fail("the limit did not stick: %v %+v", err, got)
	}
	fmt.Println("bomb: limit set")

	r := &realNTFS{f: &memDisk{data: make([]byte, 64*4096)}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 8}}
	// 1 TiB declared and backed by a 1 TiB sparse run: sizing the output by it
	// would be a terabyte.
	runs := []dataRun{{lengthClusters: 1 << 28, sparse: true, startCluster: -1}}
	if _, err := r.readCompressedRuns(runs, 1<<40, 4); !errors.Is(err, ErrTooLarge) {
		fail("readCompressedRuns of 1 TiB = %v, want ErrTooLarge", err)
	}
	fmt.Println("bomb: refused size (ErrTooLarge)")
	if _, err := r.readRunsOpt(runs, 1<<40, true); !errors.Is(err, ErrTooLarge) {
		fail("readRunsOpt of 1 TiB = %v, want ErrTooLarge", err)
	}
	fmt.Println("bomb: refused plain size (ErrTooLarge)")

	big := &realNTFS{f: &memDisk{data: make([]byte, 4096)}, boot: bootSector{bytesPerSector: 512, sectorsPerCluster: 16}}
	if _, err := big.openAttr(&attribute{typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 4, realSize: 1 << 40}); err == nil {
		fail("a 128 KiB compression unit was opened")
	}
	if _, err := r.openAttr(&attribute{typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 31, realSize: 1 << 40}); err == nil {
		fail("a unit exponent of 31 was opened")
	}
	fmt.Println("bomb: refused unit")

	// The same stream is readable by window: the allocation follows the window.
	f, err := r.openAttr(&attribute{typeCode: attrData, nonResident: true, flags: attrFlagCompressed, compUnit: 4, realSize: 1 << 40, runs: runs})
	if err != nil {
		fail("openAttr: %v", err)
	}
	buf := make([]byte, 1<<20)
	if n, err := f.ReadAt(buf, 1<<39); n != len(buf) || err != nil {
		fail("window read = %d, %v", n, err)
	}
	fmt.Println("bomb: window read ok")
}
