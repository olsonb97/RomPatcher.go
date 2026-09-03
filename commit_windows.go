//go:build windows

package rompatcher

import (
	"os"
	"syscall"
)

// Prefer a hard link, which supports Go's long-path handling. FAT and exFAT do
// not support hard links, so fall back to MoveFileW: unlike os.Rename on
// Windows, MoveFileW fails when the destination already exists.
func commitTempNoReplace(temporary, destination string) error {
	if err := os.Link(temporary, destination); err == nil || os.IsExist(err) {
		return err
	}
	from, err := syscall.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return syscall.MoveFile(from, to)
}
