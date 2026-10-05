package guard

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <time.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>
#include <CoreFoundation/CoreFoundation.h>

extern void powerEvent(unsigned int kind);

static io_connect_t root_port;

// The kernel waits (up to 30 s) for IOAllowPowerChange before the Mac sleeps: the
// network is sealed first.
static void power_callback(void *refcon, io_service_t service, natural_t kind, void *argument) {
	if (kind == kIOMessageSystemWillSleep || kind == kIOMessageSystemHasPoweredOn)
		powerEvent(kind);
	if (kind == kIOMessageCanSystemSleep || kind == kIOMessageSystemWillSleep)
		IOAllowPowerChange(root_port, (long)argument);
}

static int power_register(void) {
	IONotificationPortRef port;
	io_object_t notifier;
	root_port = IORegisterForSystemPower(NULL, &port, power_callback, &notifier);
	if (!root_port)
		return 0;
	CFRunLoopAddSource(CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(port), kCFRunLoopCommonModes);
	return 1;
}

static void power_run(void) { CFRunLoopRun(); }

static double clock_seconds(clockid_t clock) { return clock_gettime_nsec_np(clock) / 1e9; }
static double uptime_seconds(void) { return clock_seconds(CLOCK_UPTIME_RAW); }
static double continuous_seconds(void) { return clock_seconds(CLOCK_MONOTONIC); }
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
)

// Uptime is the seconds awake since boot (dark wakes count): it stops while the Mac sleeps.
func Uptime() float64 { return float64(C.uptime_seconds()) }

// AsleepSeconds is the seconds spent asleep since boot: continuous minus absolute time.
func AsleepSeconds() float64 {
	return float64(C.continuous_seconds()) - float64(C.uptime_seconds())
}

// IOKit power messages (IOMessage.h).
const (
	willSleep    = 0xE0000280
	hasPoweredOn = 0xE0000300 // a full wake; WillPowerOn comes before it is known whether the wake is full
)

var power struct {
	sync.Mutex
	beforeSleep, woke func()
}

//export powerEvent
func powerEvent(kind C.uint) {
	defer func() {
		if failure := recover(); failure != nil {
			// As for a failed step: launchd starts a new daemon, which closes everything first.
			logf("power notification %#x failed: %v\n%s", uint(kind), failure, debug.Stack())
			os.Exit(1)
		}
	}()
	power.Lock()
	beforeSleep, woke := power.beforeSleep, power.woke
	power.Unlock()
	switch uint(kind) {
	case willSleep:
		beforeSleep()
	case hasPoweredOn:
		woke()
	}
}

// WatchPower reports system sleep and wake from IOKit (IORegisterForSystemPower).
// beforeSleep runs before the acknowledgement that lets the Mac sleep; woke runs on a full
// wake. Dark wakes are not delivered to this API. registered tells whether it works: if not,
// the daemon still sees a sleep on the clocks and a full wake from user input.
func WatchPower(beforeSleep, woke func(), registered func(bool)) {
	power.Lock()
	power.beforeSleep, power.woke = beforeSleep, woke
	power.Unlock()
	go func() {
		runtime.LockOSThread() // the run loop belongs to this thread
		if C.power_register() == 0 {
			logf("IORegisterForSystemPower failed; sleep is seen on the clocks, a full wake from user input")
			registered(false)
			return
		}
		registered(true)
		logf("watching system sleep and wake")
		C.power_run()
		registered(false)
	}()
}

var hidIdle = regexp.MustCompile(`"HIDIdleTime" = (\d+)`)

// HIDIdle is the seconds since the last keyboard, mouse or trackpad input.
func HIDIdle(run Runner) (float64, error) {
	result := run([]string{"ioreg", "-c", "IOHIDSystem", "-r", "-d", "1"}, "", 0)
	if result.Failed() {
		return 0, &Unanswered{Command: "ioreg -c IOHIDSystem", Err: errors.New(result.Error())}
	}
	match := hidIdle.FindStringSubmatch(result.Stdout)
	if match == nil {
		return 0, errors.New("ioreg reports no HIDIdleTime")
	}
	nanoseconds, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0, fmt.Errorf("HIDIdleTime %q: %w", match[1], err)
	}
	return nanoseconds / 1e9, nil
}
