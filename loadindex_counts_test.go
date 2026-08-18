package filesystem_ntfs

import (
	"encoding/binary"
	"runtime"
	"testing"
)

// loadIndex reads two uint32 counts straight off the image -- the entry count in
// the header, and the free-list count after it. Neither may be used as an
// allocation hint: at 4.29e9 entries of 24 bytes, `make([]fileEntry, 0, n)` asks
// the runtime for roughly 103 GB.
//
// This is not hypothetical. A fuzz corpus entry drove exactly that path in CI:
//
//	fatal error: runtime: out of memory
//	    runtime.sysMapOS(0xc008800000, 0x9c0000000)   // 41.9 GB
//	    ntfs.(*ntfsFS).loadIndex   ntfs.go:184
//
// Both loops already stop at EOF, so the counts are redundant as hints and
// dangerous as promises. The test asserts the parser stays within a sane heap
// while being told there are billions of entries.
func TestLoadIndexIgnoresHostileCounts(t *testing.T) {
	const huge = ^uint32(0) // 4,294,967,295

	for _, tc := range []struct {
		name  string
		build func() []byte
	}{
		{
			name: "hostile entry count",
			build: func() []byte {
				b := make([]byte, headerSize)
				copy(b, headerMagic)
				binary.LittleEndian.PutUint32(b[len(headerMagic):], huge)
				return b
			},
		},
		{
			name: "hostile free-list count",
			build: func() []byte {
				b := make([]byte, headerSize)
				copy(b, headerMagic)
				// zero entries, then a free-list claiming everything
				binary.LittleEndian.PutUint32(b[len(headerMagic):], 0)
				binary.LittleEndian.PutUint32(b[len(headerMagic)+4:], huge)
				return b
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)

			fs := &ntfsFS{f: &memDisk{data: tc.build()}}
			// The contract is "returns", not "succeeds": a truncated image is a
			// legitimate error. What must not happen is a 100 GB reservation.
			_ = fs.loadIndex()

			runtime.ReadMemStats(&after)
			const ceiling = 64 << 20 // 64 MiB is already generous for a 16 KiB image
			if grew := after.TotalAlloc - before.TotalAlloc; grew > ceiling {
				t.Fatalf("loadIndex allocated %d bytes for a %d-byte image; a count off the "+
					"image is being trusted as an allocation hint", grew, headerSize)
			}
		})
	}
}
