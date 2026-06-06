package filesystem_ntfs

import (
	"fmt"

	filesystem "github.com/go-filesystems/interface"
)

// MaxLabelLen is the cap we enforce on the volume label. The real NTFS
// limit is 32 UTF-16 code units (~64 on-disk bytes); we use a slightly
// generous byte cap here since this mock driver stores raw bytes — that
// gives users headroom while still rejecting absurdly long input.
const MaxLabelLen = 128

// Compile-time assertion: ntfsFS implements filesystem.Labeller.
var _ filesystem.Labeller = (*ntfsFS)(nil)

// Label returns the current in-memory volume label. Empty when no label
// has been set.
func (fs *ntfsFS) Label() string { return fs.label }

// SetLabel writes a new volume label into the in-memory state and
// persists the header (which carries the optional NTFSLABL block).
func (fs *ntfsFS) SetLabel(label string) error {
	if len(label) > MaxLabelLen {
		return fmt.Errorf("ntfs: label %q is %d bytes, exceeds maximum %d", label, len(label), MaxLabelLen)
	}
	fs.label = label
	return fs.saveIndex()
}
