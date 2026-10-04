package storage

import "time"

// timestampFormat matches the TEXT timestamps produced by
// strftime('%Y-%m-%dT%H:%M:%fZ', 'now') in migrations, e.g.
// "2026-10-01T13:45:00.123Z".
const timestampFormat = "2006-01-02T15:04:05.999Z"

func parseTimestamp(raw string) (time.Time, error) {
	return time.Parse(timestampFormat, raw)
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
