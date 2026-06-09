package store

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrAlreadyRunning means another Foundry process holds the drive lock (single-writer:
// two processes re-sealing one blob would corrupt it).
var ErrAlreadyRunning = errors.New("foundry: another instance is already using this drive")

type fileLock struct{ f *os.File }

// atomicWrite writes data to a temp file in the same dir, fsyncs it, and renames it over
// path — so a crash mid-write never leaves a torn blob.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".foundry-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // best-effort dir fsync
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
