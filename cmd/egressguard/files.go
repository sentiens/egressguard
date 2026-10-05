package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// asInvokingUser runs fn as the user who ran sudo (effective user, group and
// groups), so the user's files are made and changed exactly as that user could:
// no path, symlink or swapped directory can lead it anywhere only root may write.
// Without sudo it just runs fn.
func asInvokingUser(fn func() error) error {
	uid, uidErr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if os.Geteuid() != 0 || uidErr != nil || gidErr != nil || uid == 0 {
		return fn()
	}
	groups, err := syscall.Getgroups()
	if err != nil {
		return err
	}
	restore := func() {
		// The real user is still root, so this cannot be refused; if it ever were,
		// carrying on as root could not be trusted.
		if syscall.Seteuid(0) != nil || syscall.Setegid(0) != nil || syscall.Setgroups(groups) != nil {
			panic("cannot become root again")
		}
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return err
	}
	if err := syscall.Setegid(gid); err != nil {
		restore()
		return err
	}
	if err := syscall.Seteuid(uid); err != nil {
		restore()
		return err
	}
	defer restore()
	return fn()
}

// writeUserJSON atomically replaces a file of the user's with value, as the user.
func writeUserJSON(path string, value any) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return err
	}
	return asInvokingUser(func() error {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(dir, "."+strings.TrimSuffix(filepath.Base(path), ".json")+".")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		_, err = tmp.Write(buffer.Bytes())
		if err == nil {
			err = tmp.Chmod(0o644)
		}
		if closeErr := tmp.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		return os.Rename(tmp.Name(), path)
	})
}

// updateUserJSON applies change to the JSON object in a file of the user's and
// writes it back. If the file changes meanwhile (the menu bar app), the change is
// applied again to the new content. A file that is not a JSON object is never
// overwritten. A missing file starts as fallback.
func updateUserJSON(path string, fallback map[string]any, change func(map[string]any)) error {
	// Read as the user too: a path the user controls must not show them what only root may read.
	return asInvokingUser(func() error { return updateJSON(path, fallback, change) })
}

func updateJSON(path string, fallback map[string]any, change func(map[string]any)) error {
	for range 3 {
		before := modified(path)
		value := maps.Clone(fallback)
		if data, err := os.ReadFile(path); err == nil {
			value = nil
			if json.Unmarshal(data, &value) != nil || value == nil {
				return fmt.Errorf("%s is not a JSON object; fix or delete it (nothing was changed)", path)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		change(value)
		if !modified(path).Equal(before) {
			continue
		}
		return writeUserJSON(path, value)
	}
	return fmt.Errorf("%s keeps changing; try again", path)
}

func modified(path string) time.Time {
	if info, err := os.Stat(path); err == nil {
		return info.ModTime()
	}
	return time.Time{}
}

// removeUserFile removes a file of the user's, as the user; a missing file is fine.
func removeUserFile(path string) error {
	return asInvokingUser(func() error {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	})
}

// readUserJSON is the JSON object in a file of the user's, read as the user, or nil.
func readUserJSON(path string) map[string]any {
	var value map[string]any
	asInvokingUser(func() error {
		data, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(data, &value) != nil {
			value = nil
		}
		return nil
	})
	return value
}

// prompter asks questions on a terminal.
type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func newPrompter(in io.Reader, out io.Writer) *prompter { return &prompter{bufio.NewReader(in), out} }

func (p *prompter) line(question, fallback string) string {
	fmt.Fprint(p.out, question)
	answer, _ := p.in.ReadString('\n')
	if answer = strings.TrimSpace(answer); answer != "" {
		return answer
	}
	return fallback
}

func (p *prompter) yes(question string) bool {
	answer := strings.ToLower(p.line(question, "no"))
	return answer == "y" || answer == "yes"
}
