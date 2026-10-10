package storage

import "time"

// timestampFormat is how timestamps are written: UTC, always three
// fractional-second digits (e.g. "2026-10-01T13:45:00.120Z"), so they sort
// correctly as TEXT. It matches strftime('%Y-%m-%dT%H:%M:%fZ').
const timestampFormat = "2006-01-02T15:04:05.000Z"

// timestampParseFormat also accepts fewer fractional digits.
const timestampParseFormat = "2006-01-02T15:04:05.999Z"

func parseTimestamp(raw string) (time.Time, error) {
	return time.Parse(timestampParseFormat, raw)
}

// parseNullableTimestamp parses raw if non-empty, returning nil otherwise.
func parseNullableTimestamp(raw string, valid bool) (*time.Time, error) {
	if !valid || raw == "" {
		return nil, nil
	}
	t, err := parseTimestamp(raw)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func formatTimestamp(t time.Time) string {
	return t.UTC().Format(timestampFormat)
}

// nowTimestamp is the current time, formatted for storage. Every INSERT
// passes its timestamps explicitly with this rather than relying on column
// defaults, so every row uses the one fixed format (databases carried over
// from the old rqlite store still have frozen defaults in their schema).
func nowTimestamp() string {
	return formatTimestamp(time.Now())
}
