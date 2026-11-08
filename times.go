package filesystem_ntfs

import (
	"encoding/binary"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

var _ filesystem.TimesReader = (*realNTFS)(nil)

// ntfsTimeRes is the unit of an NTFS time: a FILETIME counts 100 ns intervals
// since 1601-01-01 UTC (Microsoft, FILETIME structure), and NTFS records it in
// UTC. (Windows may only refresh the access time about once an hour; what is
// stored is still a 100 ns value, and that is the resolution reported.)
const ntfsTimeRes = 100 * time.Nanosecond

// Offsets inside the $STANDARD_INFORMATION body (Linux fs/ntfs3/ntfs.h,
// struct ATTR_STD_INFO): creation, modification, MFT-record change, access.
// $FILE_NAME carries the same four after its 8-byte parent reference.
const (
	stdInfoTimesOff = 0x00
	stdInfoMinLen   = 0x20
	fileNameTimeOff = 0x08
	fileNameMinLen  = 0x28
)

// Times returns the four times recorded for path.
//
//   - Btime is the creation time, Mtime the last data modification, Ctime the
//     last change of the MFT record (NTFS's "ChangeTime"), Atime the last
//     access: all four are 100 ns FILETIMEs, in UTC.
//   - They come from the unnamed $STANDARD_INFORMATION attribute, which
//     Windows keeps current. Only if the record has none (or it is shorter than
//     its four times) are they read from the preferred-namespace $FILE_NAME,
//     whose copies are refreshed only when the name changes and may be stale.
//   - A FILETIME of 0 (1601-01-01, "never set") or one with the top bit set
//     (beyond year 30828, and the 0xFFFFFFFFFFFFFFFF "keep" sentinel of
//     SetFileTime) is reported as not recorded, never as an epoch date.
//   - The NTFSIMG1 test container is a different type and does not provide
//     this.
func (r *realNTFS) Times(p string) (filesystem.FileTimes, error) {
	_, fr, err := r.resolvePath(p)
	if err != nil {
		return filesystem.FileTimes{}, err
	}
	for i := range fr.attrs {
		a := &fr.attrs[i]
		if a.typeCode != attrStandardInformation || a.name != "" || a.nonResident {
			continue
		}
		if len(a.residentData) >= stdInfoMinLen {
			return decodeNTFSTimes(a.residentData[stdInfoTimesOff:]), nil
		}
	}
	best := -1
	var bestBody []byte
	for i := range fr.attrs {
		a := &fr.attrs[i]
		if a.typeCode != attrFileName || a.nonResident || len(a.residentData) < fileNameMinLen {
			continue
		}
		rank := 3
		if len(a.residentData) > 0x41 {
			rank = namespaceRank(a.residentData[0x41])
		}
		if best < 0 || rank < best {
			best, bestBody = rank, a.residentData
		}
	}
	if best >= 0 {
		return decodeNTFSTimes(bestBody[fileNameTimeOff:]), nil
	}
	return filesystem.FileTimes{}, nil
}

// decodeNTFSTimes decodes four consecutive FILETIMEs in the order
// creation, modification, MFT change, access. b must hold 32 bytes.
func decodeNTFSTimes(b []byte) filesystem.FileTimes {
	le := binary.LittleEndian
	return filesystem.FileTimes{
		Btime: decodeFiletime(le.Uint64(b[0:])),
		Mtime: decodeFiletime(le.Uint64(b[8:])),
		Ctime: decodeFiletime(le.Uint64(b[16:])),
		Atime: decodeFiletime(le.Uint64(b[24:])),
	}
}

// filetimeToUnix is the number of seconds from 1601-01-01 to 1970-01-01.
const filetimeToUnix = 11644473600

// decodeFiletime converts a FILETIME to a Timestamp at 100 ns resolution.
func decodeFiletime(ft uint64) filesystem.Timestamp {
	if ft == 0 || ft >= 1<<63 {
		return filesystem.Timestamp{}
	}
	secs := int64(ft/10_000_000) - filetimeToUnix
	nanos := int64(ft%10_000_000) * 100
	return filesystem.NewTimestamp(time.Unix(secs, nanos), ntfsTimeRes)
}
