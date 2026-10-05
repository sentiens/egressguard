package guard

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// ReadUserFile reads a file the user controls, once: no symlink, only a regular
// file, at most limit bytes (a larger file is refused, not cut). A missing file
// is fs.ErrNotExist.
func ReadUserFile(path string, limit int64) (data []byte, err error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			data, err = nil, closeErr
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

// fileStamp changes whenever the file's content may have: a new modification
// time, size or inode. Reading the file does not change it.
func fileStamp(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	var inode uint64
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		inode = stat.Ino
	}
	return fmt.Sprintf("%d %d %d", info.ModTime().UnixNano(), info.Size(), inode)
}

// WriteAtomically replaces path with data, readable by everyone. A file in a
// directory a user can write must be written as that user, never as root.
func WriteAtomically(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil { // the rename did not happen: the temporary file is ours to remove
			err = errors.Join(err, os.Remove(tmp.Name()))
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Chmod(0o644); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
