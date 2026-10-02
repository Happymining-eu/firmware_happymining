package schedule

import (
	"testing"
	"time"
	_ "time/tzdata" // the tests must not depend on the host's zone database
)

func ptr(n int) *int { return &n }

func hourly(minute int) Spec      { return Spec{Every: Hourly, Minute: minute} }
func daily(hour, minute int) Spec { return Spec{Every: Daily, Hour: ptr(hour), Minute: minute} }
func weekly(day, hour, minute int) Spec {
	return Spec{Every: Weekly, Weekday: ptr(day), Hour: ptr(hour), Minute: minute}
}

func location(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// at parses "2006-01-02 15:04:05 -0700" style instants; the offset makes a
// repeated wall-clock time unambiguous.
func at(t *testing.T, loc *time.Location, text string) time.Time {
	t.Helper()
	parsed, err := time.Parse("2006-01-02 15:04:05 -0700", text)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.In(loc)
}

const layout = "2006-01-02 15:04:05 -0700"

func TestValidate(t *testing.T) {
	good := []Spec{
		hourly(0), hourly(59), daily(0, 0), daily(23, 59), weekly(0, 4, 5), weekly(6, 23, 59),
	}
	for _, s := range good {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	bad := map[string]Spec{
		"no frequency":             {Minute: 1},
		"unknown frequency":        {Every: "minutely", Minute: 1},
		"cron expression":          {Every: "*/5 * * * *", Minute: 1},
		"upper case":               {Every: "Daily", Hour: ptr(1), Minute: 1},
		"minute 60":                hourly(60),
		"minute negative":          hourly(-1),
		"hourly with an hour":      {Every: Hourly, Hour: ptr(3), Minute: 1},
		"hourly with a weekday":    {Every: Hourly, Weekday: ptr(3), Minute: 1},
		"daily without an hour":    {Every: Daily, Minute: 30},
		"daily with a weekday":     {Every: Daily, Hour: ptr(2), Weekday: ptr(1), Minute: 30},
		"daily hour 24":            daily(24, 0),
		"daily hour negative":      daily(-1, 0),
		"weekly without a weekday": {Every: Weekly, Hour: ptr(2), Minute: 30},
		"weekly without an hour":   {Every: Weekly, Weekday: ptr(2), Minute: 30},
		"weekly weekday 7":         weekly(7, 3, 0),
		"weekly weekday negative":  weekly(-1, 3, 0),
		"weekly hour 24":           weekly(1, 24, 0),
	}
	for why, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: must be invalid", why)
		}
		if next := s.Next(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); !next.IsZero() {
			t.Errorf("%s: Next of an invalid schedule = %v, want the zero time", why, next)
		}
	}
}

func TestNextPlainCases(t *testing.T) {
	paris := location(t, "Europe/Paris")
	cases := []struct {
		why   string
		spec  Spec
		after string
		want  string
	}{
		{"hourly, later this hour", hourly(17), "2026-10-02 10:00:00 +0200", "2026-10-02 10:17:00 +0200"},
		{"hourly, strictly after", hourly(17), "2026-10-02 10:17:00 +0200", "2026-10-02 11:17:00 +0200"},
		{"hourly, one nanosecond before", hourly(17), "2026-10-02 10:16:59 +0200", "2026-10-02 10:17:00 +0200"},
		{"hourly, into the next day", hourly(5), "2026-10-02 23:30:00 +0200", "2026-10-03 00:05:00 +0200"},
		{"hourly, into the next month", hourly(0), "2026-01-31 23:00:00 +0100", "2026-02-01 00:00:00 +0100"},
		{"hourly, into the next year", hourly(0), "2026-12-31 23:59:59 +0100", "2027-01-01 00:00:00 +0100"},

		{"daily, later today", daily(2, 30), "2026-10-02 01:00:00 +0200", "2026-10-02 02:30:00 +0200"},
		{"daily, strictly after", daily(2, 30), "2026-10-02 02:30:00 +0200", "2026-10-03 02:30:00 +0200"},
		{"daily, already passed", daily(2, 30), "2026-10-02 14:00:00 +0200", "2026-10-03 02:30:00 +0200"},
		{"daily, midnight", daily(0, 0), "2026-10-02 00:00:00 +0200", "2026-10-03 00:00:00 +0200"},
		{"daily, end of month", daily(2, 30), "2026-04-30 12:00:00 +0200", "2026-05-01 02:30:00 +0200"},
		{"daily, end of February", daily(2, 30), "2026-02-28 12:00:00 +0100", "2026-03-01 02:30:00 +0100"},
		{"daily, leap day", daily(2, 30), "2028-02-28 12:00:00 +0100", "2028-02-29 02:30:00 +0100"},
		{"daily, end of year", daily(23, 59), "2026-12-31 23:59:00 +0100", "2027-01-01 23:59:00 +0100"},

		// 2026-10-02 is a Friday (weekday 4).
		{"weekly, later today", weekly(4, 12, 0), "2026-10-02 10:00:00 +0200", "2026-10-02 12:00:00 +0200"},
		{"weekly, strictly after", weekly(4, 12, 0), "2026-10-02 12:00:00 +0200", "2026-10-09 12:00:00 +0200"},
		{"weekly, Monday is 0", weekly(0, 4, 5), "2026-10-02 10:00:00 +0200", "2026-10-05 04:05:00 +0200"},
		{"weekly, Sunday is 6", weekly(6, 3, 0), "2026-10-02 10:00:00 +0200", "2026-10-04 03:00:00 +0200"},
		{"weekly, yesterday's weekday", weekly(3, 12, 0), "2026-10-02 10:00:00 +0200", "2026-10-08 12:00:00 +0200"},
		{"weekly, across the month", weekly(0, 4, 5), "2026-04-28 10:00:00 +0200", "2026-05-04 04:05:00 +0200"},
		{"weekly, across the year", weekly(4, 6, 0), "2026-12-28 10:00:00 +0100", "2027-01-01 06:00:00 +0100"},
		{"weekly, across a clock change", weekly(0, 4, 5), "2026-10-23 10:00:00 +0200", "2026-10-26 04:05:00 +0100"},
	}
	for _, c := range cases {
		after := at(t, paris, c.after)
		if c.why == "hourly, one nanosecond before" {
			after = after.Add(time.Second - time.Nanosecond)
		}
		got := c.spec.Next(after)
		if got.Format(layout) != c.want {
			t.Errorf("%s: Next(%s) = %s, want %s", c.why, c.after, got.Format(layout), c.want)
		}
		if !got.After(after) {
			t.Errorf("%s: the result is not strictly after", c.why)
		}
		if got.Location() != paris {
			t.Errorf("%s: the result is in %v, want the location of the argument", c.why, got.Location())
		}
		if got.Second() != 0 || got.Nanosecond() != 0 {
			t.Errorf("%s: the result is not on a whole minute: %v", c.why, got)
		}
	}
}

func TestNextUsesTheLocationOfItsArgument(t *testing.T) {
	// The same instant, read in two zones, gives two different "02:30".
	instant := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	utc := daily(2, 30).Next(instant)
	if utc.Format(layout) != "2026-10-03 02:30:00 +0000" {
		t.Errorf("UTC: %s", utc.Format(layout))
	}
	tokyo := daily(2, 30).Next(instant.In(location(t, "Asia/Tokyo")))
	if tokyo.Format(layout) != "2026-10-03 02:30:00 +0900" {
		t.Errorf("Tokyo: %s", tokyo.Format(layout))
	}
	// A zone with a 45-minute offset and one with a fixed offset.
	kathmandu := hourly(0).Next(instant.In(location(t, "Asia/Kathmandu")))
	if kathmandu.Format(layout) != "2026-10-02 18:00:00 +0545" {
		t.Errorf("Kathmandu: %s", kathmandu.Format(layout))
	}
	fixed := weekly(4, 13, 0).Next(instant.In(time.FixedZone("x", -3*3600)))
	if fixed.Format(layout) != "2026-10-02 13:00:00 -0300" {
		t.Errorf("fixed zone: %s", fixed.Format(layout))
	}
}

// In Europe/Paris the clocks go from 02:00 to 03:00 on 2026-03-29 and from
// 03:00 back to 02:00 on 2026-10-25. Both days are Sundays (weekday 6).
func TestClocksSetForwardInParis(t *testing.T) {
	paris := location(t, "Europe/Paris")
	cases := []struct {
		why   string
		spec  Spec
		after string
		want  string
	}{
		// 02:30 does not exist: the run happens at the first instant after
		// the gap, 03:00 summer time, and only once.
		{"daily in the gap", daily(2, 30), "2026-03-28 12:00:00 +0100", "2026-03-29 03:00:00 +0200"},
		{"daily in the gap, just before the change", daily(2, 30), "2026-03-29 01:59:59 +0100", "2026-03-29 03:00:00 +0200"},
		{"daily in the gap, at the change", daily(2, 30), "2026-03-29 03:00:00 +0200", "2026-03-30 02:30:00 +0200"},
		{"daily in the gap, after the change", daily(2, 30), "2026-03-29 03:00:01 +0200", "2026-03-30 02:30:00 +0200"},
		{"daily at the first missing minute", daily(2, 0), "2026-03-28 12:00:00 +0100", "2026-03-29 03:00:00 +0200"},
		{"daily at the last missing minute", daily(2, 59), "2026-03-28 12:00:00 +0100", "2026-03-29 03:00:00 +0200"},
		{"weekly in the gap", weekly(6, 2, 30), "2026-03-23 12:00:00 +0100", "2026-03-29 03:00:00 +0200"},
		{"weekly in the gap, the week after", weekly(6, 2, 30), "2026-03-29 03:00:00 +0200", "2026-04-05 02:30:00 +0200"},
		// Times next to the gap are untouched.
		{"daily just before the gap", daily(1, 59), "2026-03-28 12:00:00 +0100", "2026-03-29 01:59:00 +0100"},
		{"daily just after the gap", daily(3, 0), "2026-03-28 12:00:00 +0100", "2026-03-29 03:00:00 +0200"},
		{"daily later that day", daily(3, 30), "2026-03-29 03:00:00 +0200", "2026-03-29 03:30:00 +0200"},
		// An hourly schedule has no run for the hour that does not exist.
		{"hourly before the gap", hourly(17), "2026-03-29 00:30:00 +0100", "2026-03-29 01:17:00 +0100"},
		{"hourly over the gap", hourly(17), "2026-03-29 01:17:00 +0100", "2026-03-29 03:17:00 +0200"},
		{"hourly at minute 0 over the gap", hourly(0), "2026-03-29 01:00:00 +0100", "2026-03-29 03:00:00 +0200"},
	}
	for _, c := range cases {
		got := c.spec.Next(at(t, paris, c.after))
		if got.Format(layout) != c.want {
			t.Errorf("%s: Next(%s) = %s, want %s", c.why, c.after, got.Format(layout), c.want)
		}
	}
	// Over the gap, an hourly schedule keeps running every real hour.
	before := at(t, paris, "2026-03-29 01:17:00 +0100")
	if gap := hourly(17).Next(before).Sub(before); gap != time.Hour {
		t.Errorf("hourly runs are %v apart over the gap, want 1h", gap)
	}
}

func TestClocksSetBackInParis(t *testing.T) {
	paris := location(t, "Europe/Paris")
	cases := []struct {
		why   string
		spec  Spec
		after string
		want  string
	}{
		// 02:30 occurs twice: the run happens at the first occurrence
		// (summer time) and not again an hour later.
		{"daily in the repeated hour", daily(2, 30), "2026-10-24 12:00:00 +0200", "2026-10-25 02:30:00 +0200"},
		{"daily, between the two occurrences", daily(2, 30), "2026-10-25 02:30:00 +0200", "2026-10-26 02:30:00 +0100"},
		{"daily, in the second pass before 02:30", daily(2, 30), "2026-10-25 02:10:00 +0100", "2026-10-26 02:30:00 +0100"},
		{"daily, at the second occurrence", daily(2, 30), "2026-10-25 02:30:00 +0100", "2026-10-26 02:30:00 +0100"},
		{"weekly in the repeated hour", weekly(6, 2, 30), "2026-10-19 12:00:00 +0200", "2026-10-25 02:30:00 +0200"},
		{"weekly, between the two occurrences", weekly(6, 2, 30), "2026-10-25 02:45:00 +0200", "2026-11-01 02:30:00 +0100"},
		{"daily at the first repeated minute", daily(2, 0), "2026-10-25 01:00:00 +0200", "2026-10-25 02:00:00 +0200"},
		{"daily at the first repeated minute, second pass", daily(2, 0), "2026-10-25 02:00:00 +0200", "2026-10-26 02:00:00 +0100"},
		{"daily right after the repeated hour", daily(3, 0), "2026-10-25 02:59:00 +0200", "2026-10-25 03:00:00 +0100"},
		// The repeated hour runs once for an hourly schedule too.
		{"hourly, first pass", hourly(17), "2026-10-25 01:17:00 +0200", "2026-10-25 02:17:00 +0200"},
		{"hourly, not again in the second pass", hourly(17), "2026-10-25 02:17:00 +0200", "2026-10-25 03:17:00 +0100"},
		{"hourly, asked during the second pass", hourly(17), "2026-10-25 02:05:00 +0100", "2026-10-25 03:17:00 +0100"},
	}
	for _, c := range cases {
		got := c.spec.Next(at(t, paris, c.after))
		if got.Format(layout) != c.want {
			t.Errorf("%s: Next(%s) = %s, want %s", c.why, c.after, got.Format(layout), c.want)
		}
	}
}

// tick is one minute of a watched wall clock.
type tick struct {
	now      time.Time
	wall     time.Time // what the clock reads at now, written as UTC
	prevWall time.Time // what it read a minute earlier
}

// watch reads the wall clock of from's location every minute, starting a few
// days before from so that the reference knows about first occurrences that
// precede the window.
func watch(from, to time.Time) []tick {
	wallOf := func(t time.Time) time.Time {
		return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)
	}
	var ticks []tick
	prev := from.Add(-72 * time.Hour).Truncate(time.Minute)
	for now := prev.Add(time.Minute); !now.After(to); now = now.Add(time.Minute) {
		ticks = append(ticks, tick{now: now, wall: wallOf(now), prevWall: wallOf(prev)})
		prev = now
	}
	return ticks
}

// reference lists the runs of a schedule after from by going through the
// watched minutes. It is slow and obviously follows the rules of the package
// comment; Next must agree with it.
func reference(s Spec, from time.Time, ticks []tick) []time.Time {
	wanted := func(w time.Time) bool {
		if w.Minute() != s.Minute {
			return false
		}
		if s.Every != Hourly && w.Hour() != *s.Hour {
			return false
		}
		return s.Every != Weekly || mondayBased(w.Weekday()) == *s.Weekday
	}
	seen := map[time.Time]bool{}
	var runs []time.Time
	for _, tk := range ticks {
		fire := false
		// A wall-clock time runs the first time the clock shows it.
		if wanted(tk.wall) && !seen[tk.wall] {
			seen[tk.wall] = true
			fire = true
		}
		// The clock jumped forward: a daily or weekly time inside the gap
		// runs now, if now is still the same calendar day.
		if s.Every != Hourly && tk.wall.Sub(tk.prevWall) > time.Minute {
			for skipped := tk.prevWall.Add(time.Minute); skipped.Before(tk.wall); skipped = skipped.Add(time.Minute) {
				if wanted(skipped) && skipped.YearDay() == tk.wall.YearDay() && skipped.Year() == tk.wall.Year() {
					fire = true
				}
			}
		}
		if fire && tk.now.After(from) {
			runs = append(runs, tk.now)
		}
	}
	return runs
}

func TestNextAgreesWithTheMinuteByMinuteReference(t *testing.T) {
	windows := []struct {
		zone     string
		from, to time.Time
	}{
		// Both clock changes of a year in Paris, with margins.
		{"Europe/Paris", time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC), time.Date(2026, 4, 8, 0, 0, 0, 0, time.UTC)},
		{"Europe/Paris", time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)},
		// A change at 02:00 local time on another continent.
		{"America/New_York", time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 12, 0, 0, 0, 0, time.UTC)},
		{"America/New_York", time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)},
		// A half-hour change.
		{"Australia/Lord_Howe", time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC), time.Date(2026, 4, 8, 0, 0, 0, 0, time.UTC)},
		{"Australia/Lord_Howe", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)},
		// A change at midnight: 00:00 to 00:59 did not exist on 2017-10-15.
		{"America/Sao_Paulo", time.Date(2017, 10, 12, 0, 0, 0, 0, time.UTC), time.Date(2017, 10, 18, 0, 0, 0, 0, time.UTC)},
		{"America/Sao_Paulo", time.Date(2018, 2, 15, 0, 0, 0, 0, time.UTC), time.Date(2018, 2, 20, 0, 0, 0, 0, time.UTC)},
		// A whole calendar day that did not exist (2011-12-30).
		{"Pacific/Apia", time.Date(2011, 12, 27, 0, 0, 0, 0, time.UTC), time.Date(2012, 1, 3, 0, 0, 0, 0, time.UTC)},
		// No clock change at all.
		{"UTC", time.Date(2026, 12, 28, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 4, 0, 0, 0, 0, time.UTC)},
		{"Asia/Kathmandu", time.Date(2026, 2, 26, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)},
	}
	var specs []Spec
	for _, minute := range []int{0, 17, 30, 59} {
		specs = append(specs, hourly(minute))
		for _, hour := range []int{0, 1, 2, 3, 23} {
			specs = append(specs, daily(hour, minute))
			for _, day := range []int{5, 6, 0} {
				specs = append(specs, weekly(day, hour, minute))
			}
		}
	}
	for _, w := range windows {
		loc := location(t, w.zone)
		from, to := w.from.In(loc), w.to.In(loc)
		ticks := watch(from, to)
		for _, s := range specs {
			want := reference(s, from, ticks)
			var got []time.Time
			for cursor := from; ; {
				next := s.Next(cursor)
				if next.IsZero() || next.After(to) {
					break
				}
				if !next.After(cursor) {
					t.Fatalf("%s %+v: Next(%v) = %v does not advance", w.zone, s, cursor, next)
				}
				got = append(got, next)
				cursor = next
			}
			if len(got) != len(want) {
				t.Errorf("%s %s: %d runs, the reference has %d\n got: %v\nwant: %v", w.zone, describe(s), len(got), len(want), got, want)
				continue
			}
			for i := range got {
				if !got[i].Equal(want[i]) {
					t.Errorf("%s %s: run %d = %s, the reference has %s", w.zone, describe(s), i,
						got[i].Format(layout), want[i].Format(layout))
					break
				}
			}
			// Asking from any instant between two runs gives the later one.
			for i := 1; i < len(want); i++ {
				middle := want[i-1].Add(want[i].Sub(want[i-1]) / 2)
				if next := s.Next(middle); !next.Equal(want[i]) {
					t.Errorf("%s %s: Next(%s) = %s, want %s", w.zone, describe(s), middle.Format(layout),
						next.Format(layout), want[i].Format(layout))
					break
				}
			}
		}
	}
}

func describe(s Spec) string {
	switch s.Every {
	case Hourly:
		return "hourly at :" + time.Date(0, 1, 1, 0, s.Minute, 0, 0, time.UTC).Format("04")
	case Daily:
		return "daily at " + time.Date(0, 1, 1, *s.Hour, s.Minute, 0, 0, time.UTC).Format("15:04")
	}
	return "weekly on day " + string(rune('0'+*s.Weekday)) + " at " + time.Date(0, 1, 1, *s.Hour, s.Minute, 0, 0, time.UTC).Format("15:04")
}

func TestADayWithoutTheTimeHasNoRun(t *testing.T) {
	// Samoa skipped 2011-12-30 entirely: a daily job has no run that day and
	// a weekly job set for that Friday waits a week.
	apia := location(t, "Pacific/Apia")
	after := time.Date(2011, 12, 29, 12, 0, 0, 0, apia)
	if got := daily(2, 30).Next(after); got.Format("2006-01-02 15:04") != "2011-12-31 02:30" {
		t.Errorf("daily: %v", got)
	}
	if got := weekly(4, 2, 30).Next(after); got.Format("2006-01-02 15:04") != "2012-01-06 02:30" {
		t.Errorf("weekly: %v", got)
	}
}

func TestNextIsDeterministic(t *testing.T) {
	paris := location(t, "Europe/Paris")
	after := at(t, paris, "2026-03-29 01:30:00 +0100")
	first := daily(2, 30).Next(after)
	for i := 0; i < 100; i++ {
		if got := daily(2, 30).Next(after); !got.Equal(first) {
			t.Fatalf("Next changed its answer: %v then %v", first, got)
		}
	}
}
