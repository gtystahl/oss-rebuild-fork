package run

import (
	"testing"

	"github.com/pkg/errors"
)

func TestMemoryCatches(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{
			name: "Run Single Write",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fs := NewLimitedMemoryFilesystem(100)
			file, err := fs.Create("test.txt")
			if err != nil {
				t.Fatalf("Failed to create file: %v", err)
			}
			data := []byte("This is a test data that exceeds the limit.")
			_, err = file.Write(data)
			if err != nil {
				t.Fatalf("Failed to write to file the first time: %v", err)
			}
			_, err = file.Write(data)
			if err != nil {
				t.Fatalf("Failed to write to file the second time: %v", err)
			}
			_, err = file.Write(data)

			if !errors.Is(err, ErrMemoryLimitExceeded) {
				t.Fatalf("Expected ErrMemoryLimitExceeded, got: %v", err)
			}

			file.Close()

			// You can now check currentSize using type assertion if needed
			if lfs, ok := fs.(*limitedMemoryFS); ok {
				currentSize := lfs.GetCurrentSize()
				t.Logf("Current size: %d bytes", currentSize)
			}
		})
	}
}
