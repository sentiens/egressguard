package guard

import (
	"errors"
	"io/fs"
	"os"
	"reflect"
)

// reloadConfig re-reads the administrator's config when it changed; a broken one
// keeps the old one and is reported.
func (d *Daemon) reloadConfig() {
	path := d.sys.ConfigPath
	if path == "" {
		return
	}
	stamp := fileStamp(path)
	if stamp == d.configStamp {
		return
	}
	d.configStamp = stamp
	config, err := d.sys.LoadConfig(path)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.configError = "config not reloaded: " + err.Error()
		logf("%s", d.configError)
		return
	}
	d.admin, d.configError = config, ""
	d.config = Effective(d.admin, d.currentSettings())
	d.breakTrust("config changed")
}

// reloadSettings re-reads the user's settings when the file changed; a bad file
// keeps the last good settings and is reported.
func (d *Daemon) reloadSettings() {
	path := SettingsPath(d.Config())
	stamp := path + " " + fileStamp(path)
	if stamp == d.settingsStamp {
		return
	}
	d.settingsStamp = stamp
	data, err := ReadUserFile(path, settingsLimit)
	if errors.Is(err, fs.ErrNotExist) {
		data, err = []byte("{}"), nil
	}
	var settings Settings
	if err == nil {
		settings, err = ParseSettings(data)
	} else {
		err = configErrorf("settings: %v", err)
	}

	if err == nil {
		d.saveLastGood(data) // exactly what was checked: the path is never opened twice
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.settingsError = err.Error() + " (the last good settings stay in force)"
		if d.settings != nil {
			return
		}
		settings = d.readLastGood()
	} else {
		d.settingsError = ""
	}
	if d.settings != nil && reflect.DeepEqual(settings, *d.settings) {
		return
	}
	first := d.settings == nil
	d.settings = &settings
	d.config = Effective(d.admin, settings)
	if !first {
		d.breakTrust("settings changed")
	}
}

// currentSettings: hold d.mu.
func (d *Daemon) currentSettings() Settings {
	if d.settings == nil {
		return DefaultSettings()
	}
	return *d.settings
}

func (d *Daemon) readLastGood() Settings {
	if d.sys.LastGoodPath == "" {
		return DefaultSettings()
	}
	data, err := os.ReadFile(d.sys.LastGoodPath)
	if err != nil {
		return DefaultSettings()
	}
	settings, err := ParseSettings(data)
	if err != nil {
		return DefaultSettings()
	}
	return settings
}

func (d *Daemon) saveLastGood(data []byte) {
	if d.sys.LastGoodPath == "" {
		return
	}
	if err := writeAtomically(d.sys.LastGoodPath, data); err != nil {
		logf("last good settings not saved: %v", err)
	}
}
