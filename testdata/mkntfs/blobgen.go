//go:build ignore

// Tiny helper used by regen.sh to emit the deterministic 1 KiB blob
// referenced by EXPECTED.txt. Kept here so the in-test generator and
// the shell regen path stay in lockstep — both consume math/rand with
// seed=1 and read 1024 bytes.
package main

import (
	"math/rand"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		os.Stderr.WriteString("usage: blobgen <out>\n")
		os.Exit(2)
	}
	r := rand.New(rand.NewSource(1))
	b := make([]byte, 1024)
	r.Read(b)
	if err := os.WriteFile(os.Args[1], b, 0o644); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}
