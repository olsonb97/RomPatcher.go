//go:build !windows

package rompatcher

import "os"

// A hard link atomically publishes the completed temporary file without ever
// replacing an existing destination. atomicOutput removes the temporary name.
func commitTempNoReplace(temporary, destination string) error {
	return os.Link(temporary, destination)
}
