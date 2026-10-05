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

	"github.com/sentiens/egressguard/internal/guard"
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
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return guard.WriteAtomically(path, buffer.Bytes())
	})
}

// updateUserJSON applies change to the JSON object in a file of the user's and
// writes it back. If the file changes meanwhile (the menu bar app), the change is
// applied again to the new content. A file that is not a JSON object is never
// overwritten. A missing file starts as fallback.
func updateUserJSON(path string, fallback map[string]any, change func(map[string]any) error) error {
	// Read as the user too: a path the user controls must not show them what only root may read.
	return asInvokingUser(func() error { return updateJSON(path, fallback, change) })
}

func updateJSON(path string, fallback map[string]any, change func(map[string]any) error) error {
	for range 3 {
		before, err := modified(path)
		if err != nil {
			return err
		}
		value, err := readJSONObject(path)
		if err != nil {
			return fmt.Errorf("%w (nothing was changed)", err)
		}
		if value == nil {
			value = maps.Clone(fallback)
		}
		if err := change(value); err != nil {
			return fmt.Errorf("%s: %w (nothing was changed)", path, err)
		}
		after, err := modified(path)
		if err != nil {
			return err
		}
		if !after.Equal(before) {
			continue
		}
		return writeUserJSON(path, value)
	}
	return fmt.Errorf("%s keeps changing; try again", path)
}

// modified is when path last changed; the zero time if it does not exist.
func modified(path string) (time.Time, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
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

// readUserJSON is the JSON object in a file of the user's, read as the user; nil
// if the file does not exist.
func readUserJSON(path string) (map[string]any, error) {
	var value map[string]any
	err := asInvokingUser(func() error {
		var err error
		value, err = readJSONObject(path)
		return err
	})
	return value, err
}

// readJSONObject is the JSON object in path; nil if the file does not exist.
func readJSONObject(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil || value == nil {
		return nil, fmt.Errorf("%s is not a JSON object; fix or delete it", path)
	}
	return value, nil
}

// prompter asks questions on a terminal.
type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func newPrompter(in io.Reader, out io.Writer) *prompter { return &prompter{bufio.NewReader(in), out} }

// line asks question; an empty answer, or the end of the input, is fallback.
func (p *prompter) line(question, fallback string) (string, error) {
	if _, err := fmt.Fprint(p.out, question); err != nil {
		return "", err
	}
	answer, err := p.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if answer = strings.TrimSpace(answer); answer != "" {
		return answer, nil
	}
	return fallback, nil
}

func (p *prompter) yes(question string) (bool, error) {
	answer, err := p.line(question, "no")
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(answer)
	return answer == "y" || answer == "yes", nil
}
