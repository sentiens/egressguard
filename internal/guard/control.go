package guard

import (
	"encoding/json"
	"errors"
	"io/fs"
	"strconv"
)

// Modes of the switch, as the control file names them.
const (
	ModeOn   = "on"
	ModeOff  = "off"
	ModeLock = "lock" // a self-test: no network counts as trusted
)

// maxLock is the longest self-test the control file may ask for, in seconds.
const maxLock = 600

// Control is the user's choice, from control.json.
type Control struct {
	Mode  string
	Until *int64 // when a timed off or a lock ends (epoch seconds)
	Note  string // why the file was not followed
}

// ReadControl reads the control file at the wall-clock time now. Anything
// missing, stale or malformed means on.
func ReadControl(path string, now float64) Control {
	data, err := ReadUserFile(path, controlLimit)
	if errors.Is(err, fs.ErrNotExist) {
		return Control{Mode: ModeOn}
	}
	var value map[string]any
	if err == nil {
		var parsed any
		if parsed, err = decodeJSON(data); err == nil {
			var ok bool
			if value, ok = parsed.(map[string]any); !ok {
				err = errors.New("not an object")
			}
		}
	}
	if err != nil {
		return Control{Mode: ModeOn, Note: "control file unreadable, treated as on"}
	}
	mode, isText := value["mode"].(string)
	if !isText {
		return Control{Mode: ModeOn, Note: "control file has no mode, treated as on"}
	}
	var until *int64
	if raw, present := value["until"]; present && raw != nil {
		number, isNumber := raw.(json.Number)
		seconds, err := strconv.ParseInt(number.String(), 10, 64)
		if !isNumber || err != nil || seconds <= 0 {
			return Control{Mode: ModeOn, Note: "control file has a bad until, treated as on"}
		}
		until = &seconds
	}
	switch {
	case mode == ModeOff && (until == nil || float64(*until) > now):
		return Control{Mode: ModeOff, Until: until}
	case mode == ModeLock && until != nil && now < float64(*until) && float64(*until) <= now+maxLock:
		return Control{Mode: ModeLock, Until: until}
	case mode != ModeOn && mode != ModeOff && mode != ModeLock:
		return Control{Mode: ModeOn, Note: "control file has an unknown mode, treated as on"}
	}
	return Control{Mode: ModeOn}
}
