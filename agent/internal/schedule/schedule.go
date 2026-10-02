// Package schedule computes when the schedules of the desired-state document
// run (docs/appliance.md, section 4.6): hourly at a minute, daily at an hour
// and a minute, weekly on a weekday at an hour and a minute, in the machine's
// local time.
//
// A schedule is a set of wall-clock times. Where the local clock is changed
// (daylight saving time), Next applies three rules, chosen so that a nightly
// or weekly job is never lost and never doubled:
//
//   - A wall-clock time that occurs twice (clocks set back) runs once, at its
//     first occurrence. This holds for every kind of schedule: an hourly
//     schedule does not run a second time in the repeated hour.
//   - A daily or weekly time that does not exist that day (clocks set
//     forward) runs at the first instant after the gap, on the same calendar
//     day. In Europe/Paris a job set for 02:30 runs at 03:00 on the last
//     Sunday of March. If the gap swallows the rest of the calendar day, that
//     day has no run.
//   - An hourly schedule has no run for an hour that does not exist; the
//     hours before and after run as usual.
//
// The package only computes times. It does not sleep, start jobs or catch up
// on runs missed while the machine was off.
package schedule

import (
	"errors"
	"fmt"
	"time"
)

// Values of Spec.Every.
const (
	Hourly = "hourly"
	Daily  = "daily"
	Weekly = "weekly"
)

// searchDays bounds the search of Next. A valid schedule has a run within
// eight days in any real time zone; the margin covers a zone that skips whole
// calendar days.
const searchDays = 60

// Spec is the timing part of a schedule entry.
type Spec struct {
	// Every is Hourly, Daily or Weekly.
	Every string
	// Minute is 0 to 59.
	Minute int
	// Hour is 0 to 23; required for Daily and Weekly, nil for Hourly.
	Hour *int
	// Weekday is 0 (Monday) to 6 (Sunday); required for Weekly, nil otherwise.
	Weekday *int
}

// Validate checks the rules of section 4.6: the known frequencies, the
// ranges, and that Hour and Weekday are present exactly when the frequency
// needs them.
func (s Spec) Validate() error {
	switch s.Every {
	case Hourly, Daily, Weekly:
	default:
		return errors.New("every must be hourly, daily or weekly")
	}
	if s.Minute < 0 || s.Minute > 59 {
		return errors.New("minute must be 0 to 59")
	}
	if s.Every == Hourly {
		if s.Hour != nil {
			return errors.New("an hourly schedule has no hour")
		}
	} else {
		if s.Hour == nil {
			return fmt.Errorf("a %s schedule needs an hour", s.Every)
		}
		if *s.Hour < 0 || *s.Hour > 23 {
			return errors.New("hour must be 0 to 23")
		}
	}
	if s.Every == Weekly {
		if s.Weekday == nil {
			return errors.New("a weekly schedule needs a weekday")
		}
		if *s.Weekday < 0 || *s.Weekday > 6 {
			return errors.New("weekday must be 0 (Monday) to 6 (Sunday)")
		}
	} else if s.Weekday != nil {
		return errors.New("only a weekly schedule has a weekday")
	}
	return nil
}

// Next returns the first run strictly after the given instant, computed in
// after.Location() and returned in that location. See the package comment
// for what happens where the local clock changes. An invalid Spec yields the
// zero time.
func (s Spec) Next(after time.Time) time.Time {
	if s.Validate() != nil {
		return time.Time{}
	}
	loc := after.Location()
	year, month, day := after.Date()
	// Start one calendar day early: it costs nothing and makes the result
	// independent of how a clock change maps wall-clock times to instants.
	for offset := -1; offset <= searchDays; offset++ {
		// Calendar arithmetic is done in UTC, where every day exists.
		date := time.Date(year, month, day+offset, 0, 0, 0, 0, time.UTC)
		if s.Every == Weekly && mondayBased(date.Weekday()) != *s.Weekday {
			continue
		}
		if s.Every == Hourly {
			for hour := 0; hour < 24; hour++ {
				if run, ok := resolve(date, hour, s.Minute, loc); ok && run.After(after) {
					return run
				}
			}
			continue
		}
		run, ok := resolve(date, *s.Hour, s.Minute, loc)
		if !ok {
			run, ok = afterGap(date, *s.Hour, s.Minute, loc)
		}
		if ok && run.After(after) {
			return run
		}
	}
	return time.Time{}
}

// mondayBased converts Go's Sunday-based weekday to the contract's: 0 is
// Monday, 6 is Sunday.
func mondayBased(d time.Weekday) int { return (int(d) + 6) % 7 }

// resolve returns the first instant at which the clock of loc reads date's
// day at hour:minute:00. It reports false when the clock never does.
func resolve(date time.Time, hour, minute int, loc *time.Location) (time.Time, bool) {
	// wall is the wanted wall-clock time written as if it were UTC.
	wall := time.Date(date.Year(), date.Month(), date.Day(), hour, minute, 0, 0, time.UTC).Unix()
	guess := time.Date(date.Year(), date.Month(), date.Day(), hour, minute, 0, 0, loc)
	var best time.Time
	for _, offset := range offsetsAround(guess) {
		candidate := time.Unix(wall-int64(offset), 0).In(loc)
		// The candidate is real only if that offset is the one in force at
		// the instant it designates.
		if _, actual := candidate.Zone(); actual != offset {
			continue
		}
		if best.IsZero() || candidate.Before(best) {
			best = candidate
		}
	}
	return best, !best.IsZero()
}

// afterGap returns, for a wall-clock time that does not exist, the first
// instant after the gap it falls in, provided that instant is still on the
// same calendar day.
func afterGap(date time.Time, hour, minute int, loc *time.Location) (time.Time, bool) {
	wall := time.Date(date.Year(), date.Month(), date.Day(), hour, minute, 0, 0, time.UTC).Unix()
	guess := time.Date(date.Year(), date.Month(), date.Day(), hour, minute, 0, 0, loc)
	for _, change := range changesAround(guess) {
		_, before := change.Add(-time.Second).Zone()
		_, afterOffset := change.Zone()
		// The clock jumps from change+before to change+afterOffset: the
		// wall-clock times in between do not exist.
		if change.Unix()+int64(before) <= wall && wall < change.Unix()+int64(afterOffset) {
			y, m, d := change.Date()
			if y != date.Year() || m != date.Month() || d != date.Day() {
				return time.Time{}, false
			}
			return change, true
		}
	}
	return time.Time{}, false
}

// changesAround returns the instants, near t, at which the UTC offset of t's
// location changes: the start of the zone period t is in and of the next one.
// time.Date resolves a wall-clock time within one period of the true instant,
// so these two cover every clock change that can affect it.
func changesAround(t time.Time) []time.Time {
	var changes []time.Time
	start, end := t.ZoneBounds()
	if !start.IsZero() {
		changes = append(changes, start.In(t.Location()))
	}
	if !end.IsZero() {
		changes = append(changes, end.In(t.Location()))
	}
	return changes
}

// offsetsAround returns the UTC offsets in force at t and just before and
// after the clock changes around t.
func offsetsAround(t time.Time) []int {
	_, current := t.Zone()
	offsets := []int{current}
	for _, change := range changesAround(t) {
		for _, instant := range []time.Time{change.Add(-time.Second), change} {
			if _, offset := instant.Zone(); !contains(offsets, offset) {
				offsets = append(offsets, offset)
			}
		}
	}
	return offsets
}

func contains(list []int, v int) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
