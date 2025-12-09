package run

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
)

// Set it to 4gb
var DefaultMemoryLimit int64 = 2 * 1024 * 1024 * 1024

// For testing
// var DefaultMemoryLimit int64 = 1000000
var DefaultObjectLimit int64 = 100000 // Close to 3-4 gigs? Super guess for this
// var DefaultObjectLimit int64 = 50000 // Close to 1-2 gigs? Super guess for this

var ErrMemoryLimitExceeded = errors.New("filesystem memory limit exceeded")

type limitedMemoryFS struct {
	billy.Filesystem
	maxBytes    int64
	currentSize int64
	mu          sync.Mutex
}

func (fs *limitedMemoryFS) Create(filename string) (billy.File, error) {
	return fs.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (fs *limitedMemoryFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	f, err := fs.Filesystem.OpenFile(filename, flag, perm)
	if err != nil {
		return nil, err
	}

	return &limitedFile{
		File:     f,
		fs:       fs,
		filename: filename,
	}, nil
}

type limitedFile struct {
	billy.File
	fs       *limitedMemoryFS
	filename string
}

func (f *limitedFile) Write(p []byte) (n int, err error) {
	f.fs.mu.Lock()
	// Get current file size before write
	var currentFileSize int64
	if stat, err := f.fs.Filesystem.Stat(f.filename); err == nil {
		currentFileSize = stat.Size()
	}

	// Calculate what the new total filesystem size would be after this write
	projectedFileSize := currentFileSize + int64(len(p))
	projectedTotalSize := f.fs.currentSize - currentFileSize + projectedFileSize

	if projectedTotalSize > f.fs.maxBytes {
		f.fs.mu.Unlock()
		return 0, ErrMemoryLimitExceeded
	}
	f.fs.mu.Unlock()

	n, err = f.File.Write(p)
	if err == nil && n > 0 {
		f.fs.mu.Lock()
		// Get actual file size after write
		if stat, err := f.fs.Filesystem.Stat(f.filename); err == nil {
			newFileSize := stat.Size()
			// Update total by removing old file size and adding new file size
			f.fs.currentSize = f.fs.currentSize - currentFileSize + newFileSize
		}
		f.fs.mu.Unlock()
	}
	return n, err
}

func (fs *limitedMemoryFS) Remove(filename string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if stat, err := fs.Filesystem.Stat(filename); err == nil {
		if err := fs.Filesystem.Remove(filename); err != nil {
			return err
		}
		fs.currentSize -= stat.Size()
		return nil
	}
	return fs.Filesystem.Remove(filename)
}

func (f *limitedFile) Close() error {
	return f.File.Close()
}

// GetCurrentSize returns the current size of the filesystem in bytes
func (fs *limitedMemoryFS) GetCurrentSize() int64 {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.currentSize
}

// GetMaxBytes returns the maximum allowed size of the filesystem in bytes
func (fs *limitedMemoryFS) GetMaxBytes() int64 {
	return fs.maxBytes
}

func NewLimitedMemoryFilesystem(maxBytes int64) billy.Filesystem {
	return &limitedMemoryFS{
		Filesystem:  memfs.New(),
		maxBytes:    maxBytes,
		currentSize: 0,
	}
}

type limitedStorage struct {
	*memory.Storage
	maxObjects  int64
	objectCount int64
	mu          sync.Mutex
}

func (s *limitedStorage) SetEncodedObject(obj plumbing.EncodedObject) (plumbing.Hash, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.objectCount >= s.maxObjects {
		return plumbing.ZeroHash, ErrMemoryLimitExceeded
	}
	if s.objectCount%1000 == 0 {
		fmt.Printf("Current Object Count %v", s.objectCount)
	}

	hash, err := s.Storage.SetEncodedObject(obj)
	if err == nil {
		s.objectCount++
	}
	return hash, err
}

func NewLimitedStorage(maxObjects int64) *limitedStorage {
	return &limitedStorage{
		Storage:    memory.NewStorage(),
		maxObjects: maxObjects,
	}
}
