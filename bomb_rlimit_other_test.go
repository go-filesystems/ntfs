//go:build !linux

package filesystem_ntfs

import "testing"

func TestBomb_UnderAddressSpaceLimit(t *testing.T) {
	t.Skip("RLIMIT_AS is not enforced on this OS (darwin accepts it and ignores it, windows has none); the linux lanes of CI run this test")
}
