package filesystem_ntfs

// Stress-test suite for the in-image NTFSIMG1 driver.
//
// All heavy work is gated behind testing.Short() and the NTFS_STRESS_*
// environment variables documented at the top of each test. A plain
// `go test ./...` (which sets short by default in this repo) runs the
// short configuration in < 30 seconds total. The long configuration is
// reached with `go test -run Stress -timeout 30m` plus the env vars.
//
// IMPORTANT: this driver uses a custom "NTFSIMG1" on-disk format, NOT
// real NTFS. The stress tests target the format the lib actually
// implements; they do not assume real NTFS semantics.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- knobs -----------------------------------------------------------------

var (
	stressWorkers  = flag.Int("stress.workers", 8, "concurrent R/W workers for TestStressConcurrentRW")
	stressDuration = flag.Duration("stress.duration", 0, "duration for TestStressConcurrentRW; 0 = pick default based on -short")
	stressFileMB   = flag.Int("stress.file-mb", 0, "size in MiB for TestStressLargeFile; 0 = pick default based on -short")
	stressFiles    = flag.Int("stress.files", 0, "file count for TestStressManyFiles; 0 = pick default based on -short")
)

// envOr returns the parsed value of env var name, falling back to def on
// missing/invalid input. The returned bool reports whether the env var
// was honored.
func envOrDuration(name string, def time.Duration) (time.Duration, bool) {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d, true
		}
	}
	return def, false
}

func envOrInt(name string, def int) (int, bool) {
	if v := os.Getenv(name); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i, true
		}
	}
	return def, false
}

// resolveDuration picks the active duration in this order:
//  1. -stress.duration if non-zero
//  2. NTFS_STRESS_DURATION if set
//  3. short / long defaults
func resolveDuration(short bool) time.Duration {
	if *stressDuration > 0 {
		return *stressDuration
	}
	def := 3 * time.Hour
	if short {
		def = 3 * time.Second
	}
	d, _ := envOrDuration("NTFS_STRESS_DURATION", def)
	return d
}

func resolveFileMB(short bool) int {
	if *stressFileMB > 0 {
		return *stressFileMB
	}
	def := 4096 // 4 GiB long
	if short {
		def = 64
	}
	v, _ := envOrInt("NTFS_STRESS_FILE_MB", def)
	return v
}

func resolveFiles(short bool) int {
	if *stressFiles > 0 {
		return *stressFiles
	}
	def := 1_000_000
	if short {
		def = 5_000
	}
	v, _ := envOrInt("NTFS_STRESS_FILES", def)
	return v
}

func resolveWorkers() int {
	if *stressWorkers > 0 {
		return *stressWorkers
	}
	v, _ := envOrInt("NTFS_STRESS_WORKERS", 8)
	return v
}

// ---- 1. concurrent R/W stress ----------------------------------------------

// TestStressConcurrentRW spawns N workers, each driving its own image
// (the lib is intentionally single-threaded per FS handle), and runs a
// write+read+verify+delete loop for the configured duration. Each file
// is integrity-checked with sha256 on read-back. Reports ops/sec at the
// end. Skips in -short mode unless NTFS_STRESS_DURATION is set.
func TestStressConcurrentRW(t *testing.T) {
	short := testing.Short()
	// In -short we still run a brief slice (3 s default) to keep the
	// concurrency path covered. Long mode runs the full duration.
	dur := resolveDuration(short)
	workers := resolveWorkers()
	if workers < 1 {
		workers = 1
	}

	t.Logf("stress: workers=%d duration=%s", workers, dur)

	root := t.TempDir()
	var totalOps uint64
	var totalErrs uint64

	deadline := time.Now().Add(dur)

	var wg sync.WaitGroup
	wg.Add(workers)
	start := time.Now()
	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			img := filepath.Join(root, fmt.Sprintf("w%d.img", w))
			fs, err := Open(img, 0)
			if err != nil {
				atomic.AddUint64(&totalErrs, 1)
				t.Errorf("worker %d open: %v", w, err)
				return
			}
			defer fs.Close()

			// Per-worker RNG so workers don't all hammer the same
			// payload pattern.
			rng := rand.New(rand.NewSource(int64(w) + 1))
			// Bounded in-memory checksum index so we can verify
			// content on read-back without re-deriving it.
			sums := map[string][32]byte{}
			// NTFSIMG1's 16 KiB fixed header caps total entries
			// (index + meta) at well under 200. We hold live
			// files well below that with aggressive eviction so
			// writes don't trip the header-overflow ENOSPC.
			const maxLive = 10

			var overflowSkips uint64
			for time.Now().Before(deadline) {
				op := rng.Intn(10)
				name := fmt.Sprintf("/d%d/f%d.bin", rng.Intn(4), rng.Intn(16))
				switch {
				case op < 5: // write
					// Hold under maxLive: if we'd grow past
					// it on a brand-new name, evict first.
					if _, exists := sums[name]; !exists && len(sums) >= maxLive {
						for victim := range sums {
							_ = fs.DeleteFile(victim)
							delete(sums, victim)
							break
						}
					}
					sz := 1 + rng.Intn(8192)
					data := make([]byte, sz)
					rng.Read(data)
					if err := fs.WriteFile(name, data, 0o644); err != nil {
						// Header overflow is a documented
						// format limit, not a corruption
						// bug — treat as soft-skip.
						if isHeaderOverflow(err) {
							overflowSkips++
							// best-effort cleanup
							for victim := range sums {
								_ = fs.DeleteFile(victim)
								delete(sums, victim)
								break
							}
							continue
						}
						atomic.AddUint64(&totalErrs, 1)
						t.Errorf("worker %d write %s: %v", w, name, err)
						return
					}
					sums[name] = sha256.Sum256(data)
				case op < 8: // read + verify
					got, err := fs.ReadFile(name)
					if err != nil {
						// not yet written by this worker, skip
						continue
					}
					want, ok := sums[name]
					if !ok {
						// unknown: just sanity-check it parses
						continue
					}
					if sha256.Sum256(got) != want {
						atomic.AddUint64(&totalErrs, 1)
						t.Errorf("worker %d sha256 mismatch on %s", w, name)
						return
					}
				default: // delete
					_ = fs.DeleteFile(name)
					delete(sums, name)
				}
				atomic.AddUint64(&totalOps, 1)
			}
			if overflowSkips > 0 {
				t.Logf("worker %d: %d soft-skipped writes due to header overflow", w, overflowSkips)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	ops := atomic.LoadUint64(&totalOps)
	errs := atomic.LoadUint64(&totalErrs)
	rate := float64(ops) / elapsed.Seconds()
	t.Logf("stress: ops=%d errs=%d elapsed=%s rate=%.0f ops/sec",
		ops, errs, elapsed, rate)
	if errs > 0 {
		t.Fatalf("stress: %d errors", errs)
	}
	if ops == 0 {
		t.Fatalf("stress: no ops completed")
	}
}

// ---- 2. large-file stress --------------------------------------------------

// TestStressLargeFile writes one large file, reads it back in chunks,
// verifies sha256. Default 64 MiB in -short, 4 GiB in long mode (or
// NTFS_STRESS_FILE_MB). Skips heavy size when -short unless
// NTFS_STRESS_FILE_MB is set explicitly.
func TestStressLargeFile(t *testing.T) {
	short := testing.Short()
	sizeMB := resolveFileMB(short)
	// In -short mode without an explicit override, cap at 64 MiB so
	// the whole short suite stays under 30 s.
	if short && os.Getenv("NTFS_STRESS_FILE_MB") == "" && *stressFileMB == 0 {
		if sizeMB > 64 {
			sizeMB = 64
		}
	}
	t.Logf("large-file: size=%d MiB", sizeMB)

	size := int64(sizeMB) << 20
	dir := t.TempDir()
	img := filepath.Join(dir, "large.img")

	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	// Generate a deterministic, verifiable payload without keeping
	// the entire blob in memory twice. We stream into a hash.Hash and
	// also into a buffer (the WriteFile API takes []byte today; if
	// that ever changes to a streaming API, switch this to that).
	rng := rand.New(rand.NewSource(42))
	buf := make([]byte, size)
	if _, err := io.ReadFull(rng, buf); err != nil {
		t.Fatalf("seed payload: %v", err)
	}
	want := sha256.Sum256(buf)

	start := time.Now()
	if err := fs.WriteFile("/big.bin", buf, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	writeDur := time.Since(start)

	start = time.Now()
	got, err := fs.ReadFile("/big.bin")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	readDur := time.Since(start)

	if sha256.Sum256(got) != want {
		t.Fatalf("sha256 mismatch on /big.bin (size=%d)", len(got))
	}
	t.Logf("large-file: write=%s read=%s size=%d", writeDur, readDur, size)
}

// ---- 3. many-files stress --------------------------------------------------

// TestStressManyFiles creates as many small files as the NTFSIMG1
// format can hold, then verifies them. The intended targets are
// 5,000 (-short) / 1,000,000 (long, or NTFS_STRESS_FILES), but the
// NTFSIMG1 header is a FIXED 16 KiB region (see headerSize). Each
// file consumes one index entry plus one metadata entry, so the lib's
// hard ceiling is on the order of ~100 files regardless of the
// requested target. This test discovers the actual ceiling and
// reports it; reaching the cap before n is NOT a failure — it is a
// finding about the lib's storage format. We DO still fail on any
// other error (panic, corrupt readback, etc.).
func TestStressManyFiles(t *testing.T) {
	short := testing.Short()
	n := resolveFiles(short)
	t.Logf("many-files: requested=%d (lib ceiling ~100 due to 16 KiB header)", n)

	dir := t.TempDir()
	img := filepath.Join(dir, "many.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fs.Close()

	start := time.Now()
	written := 0
	var stopReason string
	for i := 0; i < n; i++ {
		// Compact name scheme to maximize file count before the
		// header overflows: 4 top dirs, files 0..N within each.
		p := fmt.Sprintf("/d%d/f%d", i%4, i)
		var payload [4]byte
		binary.LittleEndian.PutUint32(payload[:], uint32(i))
		if err := fs.WriteFile(p, payload[:], 0o644); err != nil {
			// Header overflow is the documented format limit.
			// Any other error class is still a real failure.
			if !isHeaderOverflow(err) {
				t.Fatalf("WriteFile %s after %d files: %v", p, written, err)
			}
			stopReason = err.Error()
			break
		}
		written++
	}
	createDur := time.Since(start)
	if stopReason == "" {
		t.Logf("many-files: created all %d files (no overflow)", written)
	} else {
		t.Logf("many-files: hit format ceiling at %d files: %s", written, stopReason)
	}
	if written == 0 {
		t.Fatalf("many-files: no files written")
	}

	// Spot-check: read back up to 64 files at random and verify content.
	rng := rand.New(rand.NewSource(7))
	checks := 64
	if checks > written {
		checks = written
	}
	for k := 0; k < checks; k++ {
		i := rng.Intn(written)
		p := fmt.Sprintf("/d%d/f%d", i%4, i)
		got, err := fs.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", p, err)
		}
		if len(got) != 4 || binary.LittleEndian.Uint32(got) != uint32(i) {
			t.Fatalf("content mismatch on %s: got %v", p, got)
		}
	}
	t.Logf("many-files: created=%d in %s checks_ok=%d", written, createDur, checks)
}

// isHeaderOverflow reports whether err is the NTFSIMG1 fixed-header
// capacity error. We pattern-match on the wrapped error text because
// the driver doesn't export a sentinel today.
func isHeaderOverflow(err error) bool {
	return err != nil && strings.Contains(err.Error(), "header overflow")
}

// ---- 4. fsync / re-open semantics ------------------------------------------

// TestStressFsyncReopen exercises the durability contract: every
// successful WriteFile/DeleteFile must be readable after a Close +
// Open round-trip. We don't (and can't, portably) drop the OS page
// cache mid-test, but Close on *os.File flushes outstanding write
// buffers through to the kernel, which is what the NTFSIMG1 driver
// relies on for durability.
//
// We also explicitly model "an op that was attempted but never
// completed" by writing the data to a path, then immediately
// overwriting that path with new data — only the most recently
// committed content must survive the round trip. This catches save
// ordering bugs (e.g. the header pointing at the new offset while
// the data WriteAt was skipped).
func TestStressFsyncReopen(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "sync.img")

	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	committed := map[string][]byte{}
	// First batch: write 64 files of varying sizes.
	rng := rand.New(rand.NewSource(13))
	for i := 0; i < 64; i++ {
		sz := 1 + rng.Intn(4096)
		data := make([]byte, sz)
		rng.Read(data)
		p := fmt.Sprintf("/sync/f%d.bin", i)
		if err := fs.WriteFile(p, data, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", p, err)
		}
		committed[p] = data
	}
	// Overwrite half of them — only the newest content must survive.
	for i := 0; i < 32; i++ {
		sz := 1 + rng.Intn(2048)
		data := make([]byte, sz)
		rng.Read(data)
		p := fmt.Sprintf("/sync/f%d.bin", i)
		if err := fs.WriteFile(p, data, 0o644); err != nil {
			t.Fatalf("overwrite %s: %v", p, err)
		}
		committed[p] = data
	}
	// Delete a few — these must NOT come back.
	deleted := []string{}
	for i := 40; i < 48; i++ {
		p := fmt.Sprintf("/sync/f%d.bin", i)
		if err := fs.DeleteFile(p); err != nil {
			t.Fatalf("DeleteFile %s: %v", p, err)
		}
		delete(committed, p)
		deleted = append(deleted, p)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open and verify.
	fs2, err := Open(img, 0)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer fs2.Close()
	for p, want := range committed {
		got, err := fs2.ReadFile(p)
		if err != nil {
			t.Fatalf("post-reopen ReadFile %s: %v", p, err)
		}
		if sha256.Sum256(got) != sha256.Sum256(want) {
			t.Fatalf("post-reopen content mismatch on %s (want %d B, got %d B)",
				p, len(want), len(got))
		}
	}
	for _, p := range deleted {
		if _, err := fs2.ReadFile(p); err == nil {
			t.Fatalf("deleted file %s reappeared after reopen", p)
		}
	}
}

// ---- 5. parser fuzzing -----------------------------------------------------

// makeSeedImage builds a small, well-formed NTFSIMG1 image to use as a
// fuzz seed. It writes via the real driver so the format is correct by
// construction; the fuzzer then mutates the bytes.
func makeSeedImage(t testing.TB) []byte {
	t.Helper()
	dir := t.TempDir()
	img := filepath.Join(dir, "seed.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("seed Open: %v", err)
	}
	if err := fs.WriteFile("/a/b.txt", []byte("hello"), 0o644); err != nil {
		t.Fatalf("seed WriteFile: %v", err)
	}
	if err := fs.MkDir("/d", 0o755); err != nil {
		t.Fatalf("seed MkDir: %v", err)
	}
	if err := fs.Symlink("/a/b.txt", "/lnk"); err != nil {
		t.Fatalf("seed Symlink: %v", err)
	}
	if err := fs.SetLabel("FUZZ"); err != nil {
		t.Fatalf("seed SetLabel: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("seed Close: %v", err)
	}
	b, err := os.ReadFile(img)
	if err != nil {
		t.Fatalf("seed read: %v", err)
	}
	return b
}

// FuzzOpen feeds mutated NTFSIMG1 images to Open and exercises a few
// follow-on operations. The contract is: no panic, no OOM, no infinite
// loop. Errors are fine; corruption-aware error returns are the desired
// behavior.
func FuzzOpen(f *testing.F) {
	seed := makeSeedImage(f)
	f.Add(seed)
	// A handful of degenerate seeds that have triggered parser bugs
	// in similar codebases.
	f.Add([]byte{})
	f.Add([]byte("NTFSIMG1"))                                              // magic only
	f.Add(append([]byte("NTFSIMG1"), make([]byte, headerSize-len("NTFSIMG1"))...)) // magic+zeros

	f.Fuzz(func(t *testing.T, data []byte) {
		// Bound the input size so the fuzzer doesn't fill /tmp.
		if len(data) > 4<<20 {
			return
		}
		dir := t.TempDir()
		img := filepath.Join(dir, "fuzz.img")
		if err := os.WriteFile(img, data, 0o600); err != nil {
			t.Fatalf("WriteFile (seed): %v", err)
		}
		fs, err := Open(img, 0)
		if err != nil {
			return // expected for malformed inputs
		}
		// Exercise the read paths on the (possibly garbage) index.
		// All of these must return cleanly (error or success), not
		// panic. We discard results entirely.
		_, _ = fs.ListDir("/")
		_, _ = fs.ReadFile("/a/b.txt")
		_, _ = fs.Stat("/")
		_, _ = fs.ReadLink("/lnk")
		_ = fs.Close()
	})
}

// ---- 6. resize stress ------------------------------------------------------

// TestStressResizeCycle pairs the Grow/Shrink resize machinery with
// the same write/read/delete churn that the end-of-data corruption
// fix targeted. The regression it's most directly guarding against:
// the allocator extending the live region into bytes that are about
// to be exposed (after grow) or truncated away (after shrink). If
// either Grow or Shrink leaves the free-list inconsistent with the
// on-disk content region, the subsequent checksum verifications
// (or post-reopen reads) will fail.
func TestStressResizeCycle(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "resize-stress.img")
	fs, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	rng := rand.New(rand.NewSource(99))
	sums := map[string][32]byte{}
	const maxLive = 8 // stays well below the header-overflow ceiling

	writeOne := func(p string, sz int) {
		data := make([]byte, sz)
		rng.Read(data)
		if err := fs.WriteFile(p, data, 0o644); err != nil {
			if isHeaderOverflow(err) {
				return
			}
			t.Fatalf("WriteFile %s: %v", p, err)
		}
		sums[p] = sha256.Sum256(data)
	}

	verify := func(stage string) {
		for p, want := range sums {
			got, err := fs.ReadFile(p)
			if err != nil {
				t.Fatalf("%s: ReadFile %s: %v", stage, p, err)
			}
			if sha256.Sum256(got) != want {
				t.Fatalf("%s: sha256 mismatch on %s", stage, p)
			}
		}
	}

	// Seed.
	for i := 0; i < maxLive; i++ {
		writeOne(fmt.Sprintf("/s%d.bin", i), 256+rng.Intn(2048))
	}
	verify("seed")

	// Cycle through several grow/shrink targets, churning between
	// each step.
	sizes := []int64{
		int64(headerSize) + 1<<20,
		int64(headerSize) + 256<<10,
		int64(headerSize) + 4<<20,
		int64(headerSize) + 128<<10,
		int64(headerSize) + 2<<20,
	}
	for i, target := range sizes {
		st, err := os.Stat(img)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		switch {
		case target > st.Size():
			if err := fs.Grow(target); err != nil {
				t.Fatalf("round %d Grow(%d): %v", i, target, err)
			}
		case target < st.Size():
			if err := fs.Shrink(target); err != nil {
				t.Fatalf("round %d Shrink(%d): %v", i, target, err)
			}
		}
		// Churn: random write/overwrite/delete, then verify.
		for j := 0; j < 8; j++ {
			op := rng.Intn(10)
			name := fmt.Sprintf("/r%d/n%d.bin", i, rng.Intn(maxLive))
			switch {
			case op < 6:
				if len(sums) >= maxLive*2 {
					for victim := range sums {
						_ = fs.DeleteFile(victim)
						delete(sums, victim)
						break
					}
				}
				writeOne(name, 128+rng.Intn(4096))
			case op < 9:
				// Read a known file if any.
				for p := range sums {
					if _, err := fs.ReadFile(p); err != nil {
						t.Fatalf("round %d read %s: %v", i, p, err)
					}
					break
				}
			default:
				for victim := range sums {
					_ = fs.DeleteFile(victim)
					delete(sums, victim)
					break
				}
			}
		}
		verify(fmt.Sprintf("round %d", i))
	}

	// Round-trip: close, reopen, every committed file still matches.
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fs2, err := Open(img, 0)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer fs2.Close()
	for p, want := range sums {
		got, err := fs2.ReadFile(p)
		if err != nil {
			t.Fatalf("post-reopen ReadFile %s: %v", p, err)
		}
		if sha256.Sum256(got) != want {
			t.Fatalf("post-reopen sha256 mismatch on %s", p)
		}
	}
}

// ---- 7. fault injection ----------------------------------------------------

// faultRW wraps a real diskRW and returns the configured error on the
// next ReadAt or WriteAt past the trigger offset. It lives in the
// _test.go file so production code stays dep-free.
type faultRW struct {
	inner       diskRW
	mu          sync.Mutex
	failReadAt  int64 // -1 = never
	failWriteAt int64 // -1 = never
	failErr     error
}

func newFaultRW(inner diskRW) *faultRW {
	return &faultRW{inner: inner, failReadAt: -1, failWriteAt: -1, failErr: errors.New("injected fault")}
}

func (w *faultRW) ReadAt(p []byte, off int64) (int, error) {
	w.mu.Lock()
	trigger := w.failReadAt
	w.mu.Unlock()
	if trigger >= 0 && off >= trigger {
		return 0, w.failErr
	}
	return w.inner.ReadAt(p, off)
}

func (w *faultRW) WriteAt(p []byte, off int64) (int, error) {
	w.mu.Lock()
	trigger := w.failWriteAt
	w.mu.Unlock()
	if trigger >= 0 && off >= trigger {
		return 0, w.failErr
	}
	return w.inner.WriteAt(p, off)
}

func (w *faultRW) Close() error { return w.inner.Close() }

// TestStressFaultInjection wraps the backing store with an I/O-error
// injector and verifies that the driver propagates the error cleanly
// (no panic, no partial-state corruption that survives a re-open).
func TestStressFaultInjection(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "fault.img")

	// Phase 1: seed a valid image, then close it.
	{
		fs, err := Open(img, 0)
		if err != nil {
			t.Fatalf("seed Open: %v", err)
		}
		if err := fs.WriteFile("/seed.txt", []byte("seeded"), 0o644); err != nil {
			t.Fatalf("seed WriteFile: %v", err)
		}
		if err := fs.Close(); err != nil {
			t.Fatalf("seed Close: %v", err)
		}
	}

	// Phase 2: construct an ntfsFS by hand with the fault wrapper so
	// we can trigger errors mid-op. This uses package-internal types
	// (legal because this is _test.go in the same package).
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

	// Inject: next WriteAt past the content region fails.
	frw.mu.Lock()
	frw.failWriteAt = int64(headerSize)
	frw.mu.Unlock()

	werr := fs.WriteFile("/should-fail.txt", []byte("nope"), 0o644)
	if werr == nil {
		t.Fatalf("expected WriteFile to fail under fault injection")
	}

	// Clear the fault, ensure subsequent ops recover.
	frw.mu.Lock()
	frw.failWriteAt = -1
	frw.mu.Unlock()

	// The original /seed.txt must still be readable.
	got, err := fs.ReadFile("/seed.txt")
	if err != nil {
		t.Fatalf("post-fault ReadFile /seed.txt: %v", err)
	}
	if string(got) != "seeded" {
		t.Fatalf("post-fault content mismatch: %q", got)
	}

	// And a fresh write should succeed.
	if err := fs.WriteFile("/ok.txt", []byte("ok"), 0o644); err != nil {
		t.Fatalf("post-fault WriteFile: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open via the public API and ensure on-disk state is sane.
	fs2, err := Open(img, 0)
	if err != nil {
		t.Fatalf("final Open: %v", err)
	}
	defer fs2.Close()
	if _, err := fs2.ReadFile("/seed.txt"); err != nil {
		t.Fatalf("final /seed.txt: %v", err)
	}
	if _, err := fs2.ReadFile("/ok.txt"); err != nil {
		t.Fatalf("final /ok.txt: %v", err)
	}
}
