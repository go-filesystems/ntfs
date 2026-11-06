package filesystem_ntfs

// openfile.go — filesystem.Opener for both NTFS readers: positional reads of a
// file, so that a server answering a READ of a few bytes of a large file (NFS,
// SFTP) does not materialise the whole file through ReadFile for every request.

import (
	"fmt"
	"io"
	iofs "io/fs"
	"sort"
	"sync"

	filesystem "github.com/go-filesystems/interface"
)

var (
	_ filesystem.Opener = (*ntfsFS)(nil)
	_ filesystem.Opener = (*realNTFS)(nil)
)

// OpenFile opens the file at p for positional reads (the image format of this
// package's own writer: a file is one contiguous extent).
func (fs *ntfsFS) OpenFile(p string) (filesystem.File, error) {
	p = normalizePath(p)
	e, ok := fs.index[p]
	if !ok || e.IsDir {
		return nil, fmt.Errorf("ntfs: %q not found: %w", p, iofs.ErrNotExist)
	}
	start, err := fs.entryExtent(p, e)
	if err != nil {
		return nil, err
	}
	return &flatFile{f: fs.f, start: start, size: int64(e.Size)}, nil
}

type flatFile struct {
	f           diskRW
	start, size int64
}

func (f *flatFile) Size() int64  { return f.size }
func (f *flatFile) Close() error { return nil }

func (f *flatFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ntfs: negative offset %d", off)
	}
	if off >= f.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if off+want > f.size {
		want = f.size - off
	}
	n, err := f.f.ReadAt(p[:want], f.start+off)
	if err != nil && err != io.EOF {
		return n, err
	}
	if int64(n) < want {
		return n, io.ErrUnexpectedEOF
	}
	if want < int64(len(p)) {
		return int(want), io.EOF
	}
	return n, nil
}

// OpenFile opens the unnamed $DATA of the file at p for positional reads. A
// resident or plain non-resident stream is read by range (holes as zeros); a
// compressed one (LZNT1) is decompressed whole, once, on the first read, within
// the volume's data ceiling (SetMaxDataSize); an encrypted one is refused.
func (r *realNTFS) OpenFile(p string) (filesystem.File, error) {
	_, fr, err := r.resolvePath(p)
	if err != nil {
		return nil, err
	}
	if fr.isDir() {
		return nil, fmt.Errorf("ntfs: %q is a directory", p)
	}
	for i := range fr.attrs {
		a := &fr.attrs[i]
		if a.typeCode == attrData && a.name == "" {
			return r.openAttr(a)
		}
	}
	return nil, fmt.Errorf("ntfs: %q has no $DATA", p)
}

func (r *realNTFS) openAttr(a *attribute) (filesystem.File, error) {
	if !a.nonResident {
		return &flatBytes{b: a.residentData}, nil
	}
	if a.flags&attrFlagEncrypted != 0 {
		return nil, fmt.Errorf("ntfs: encrypted ($EFS) data is not decodable without keys")
	}
	if a.isCompressed() {
		if a.realSize > 1<<62 {
			return nil, fmt.Errorf("ntfs: data size %d too large", a.realSize)
		}
		return &lazyFile{size: int64(a.realSize), load: func() ([]byte, error) {
			return r.readCompressedRuns(a.runs, a.realSize, a.compUnit)
		}}, nil
	}
	cs := r.boot.clusterSize()
	rf := &runsFile{r: r, runs: a.runs, cs: cs, starts: make([]int64, len(a.runs)+1)}
	// The same size as ReadFile: the declared one, within what the runlist backs.
	var capBytes int64
	for i, run := range a.runs {
		rb, ok := mulCheck(run.lengthClusters, cs)
		if !ok {
			return nil, fmt.Errorf("ntfs: run byte count overflow")
		}
		if capBytes, ok = addCheck(capBytes, rb); !ok {
			return nil, fmt.Errorf("ntfs: run capacity overflow")
		}
		rf.starts[i+1] = capBytes
	}
	if a.realSize > 1<<62 {
		return nil, fmt.Errorf("ntfs: data size %d too large", a.realSize)
	}
	rf.size = int64(a.realSize)
	if rf.size > capBytes {
		rf.size = capBytes
	}
	return rf, nil
}

// flatBytes is a stream held in memory (a resident attribute).
type flatBytes struct{ b []byte }

func (f *flatBytes) Size() int64  { return int64(len(f.b)) }
func (f *flatBytes) Close() error { return nil }

func (f *flatBytes) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ntfs: negative offset %d", off)
	}
	if off >= int64(len(f.b)) {
		return 0, io.EOF
	}
	n := copy(p, f.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// lazyFile is a stream that can only be had whole (compressed): it is loaded
// once, on the first read.
type lazyFile struct {
	size int64
	load func() ([]byte, error)
	once sync.Once
	data *flatBytes
	err  error
}

func (f *lazyFile) Size() int64  { return f.size }
func (f *lazyFile) Close() error { return nil }

func (f *lazyFile) ReadAt(p []byte, off int64) (int, error) {
	f.once.Do(func() {
		b, err := f.load()
		f.data, f.err = &flatBytes{b: b}, err
	})
	if f.err != nil {
		return 0, f.err
	}
	return f.data.ReadAt(p, off)
}

// runsFile is a non-resident stream read by range over its runlist.
type runsFile struct {
	r      *realNTFS
	runs   []dataRun
	starts []int64 // starts[i] is the logical offset of runs[i]; the last is the capacity
	cs     int64
	size   int64
}

func (f *runsFile) Size() int64  { return f.size }
func (f *runsFile) Close() error { return nil }

// ReadAt fills p from off: the runs that overlap the window are read into place
// (each one's last byte must exist in the image, as in ReadFile), sparse runs
// read as zeros.
func (f *runsFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ntfs: negative offset %d", off)
	}
	if off >= f.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if off+want > f.size {
		want = f.size - off
	}
	dst := p[:want]
	clear(dst)
	hi := off + want
	// The first run that ends after off.
	i := sort.Search(len(f.runs), func(i int) bool { return f.starts[i+1] > off })
	for ; i < len(f.runs) && f.starts[i] < hi; i++ {
		run := f.runs[i]
		if run.sparse {
			continue
		}
		lo, top := max(f.starts[i], off), min(f.starts[i+1], hi)
		base, ok := mulCheck(run.startCluster, f.cs)
		if !ok {
			return 0, fmt.Errorf("ntfs: run start overflow")
		}
		abs, ok := addCheck(base, f.r.partOffset)
		if ok {
			abs, ok = addCheck(abs, lo-f.starts[i])
		}
		if !ok || abs < 0 {
			return 0, fmt.Errorf("ntfs: run absolute offset overflow")
		}
		if !f.r.backed(abs, top-lo) {
			return 0, fmt.Errorf("ntfs: run of %d bytes at cluster %d lies past the end of the image", top-lo, run.startCluster)
		}
		if _, err := f.r.f.ReadAt(dst[lo-off:top-off], abs); err != nil && err != io.EOF {
			return 0, err
		}
	}
	if want < int64(len(p)) {
		return int(want), io.EOF
	}
	return int(want), nil
}
