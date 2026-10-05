package guard

import (
	"fmt"
	"slices"
)

// seal closes the network until a full wake; at is the awake time it counts from. Hold d.mu.
func (d *Daemon) seal(at float64) {
	d.sealed, d.sealedAt, d.sealNote, d.sleptSinceSeal = true, at, "", false
	d.sealNetworks = map[string]sealedNetwork{}
	for name, link := range d.uplinks {
		if link.Trusted {
			d.sealNetworks[name] = sealedNetwork{link.Network, link.MAC}
		}
	}
}

// unseal ends a seal (or confirms a wake) and has every uplink checked again. Hold d.mu.
func (d *Daemon) unseal(reason, note string) {
	d.sealed, d.sealNote = false, note
	d.breakTrust(reason)
}

// checkPower seals on a sleep seen on the clocks and unseals on a full wake: the
// notice, or input after the seal. Hold d.mu.
func (d *Daemon) checkPower(events []*Event, now, idle float64, idleKnown bool) {
	slept := d.sys.Asleep()
	if d.clocksRead && slept-d.sleptSeen > sleptAtLeast {
		// Slept, with or without the notice; a dark wake (Power Nap) is not a full
		// wake. Input counts from the last step before the sleep: anything later is
		// after the wake.
		if !d.sealed {
			d.seal(d.lastStep)
		}
		d.sealedAt = max(d.sealedAt, d.lastStep)
		d.sleptSinceSeal = true
		d.breakTrust(fmt.Sprintf("slept %.0f s", slept-d.sleptSeen))
	}
	d.clocksRead, d.sleptSeen, d.lastStep = true, slept, now
	woke := slices.ContainsFunc(events, func(e *Event) bool { return e.Kind == EventWake })
	switch {
	case woke:
		d.unseal("system woke", "")
	case !d.sealed:
	case idleKnown && now-idle > d.sealedAt:
		d.unseal("input after the sleep", "")
	case now-d.sealedAt > sealLimit:
		d.unseal("seal limit", fmt.Sprintf("no full wake seen %.0f s after the seal; checked the network anyway", sealLimit))
	}
}
