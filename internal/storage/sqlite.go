// Package storage provides access to the SQLite database: connection
// management, schema migrations, and repositories that transparently apply
// envelope encryption around secret values.
//
// All ciphertext, nonce, and wrapped-key fields are stored as
// base64-encoded TEXT, not BLOB, so values round-trip as plain strings and
// the file stays portable and easy to inspect.
//
// The database is one file opened by one process. A single connection
// serializes access (this is a small single-user tool, and it keeps
// transactions and foreign-key settings trivially consistent), in WAL mode
// with full synchronous writes so a committed change survives power loss.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver: keeps the binary static (no cgo)
)

// DB is an open SQLite database.
type DB struct {
	sql *sql.DB
}

// Open opens the SQLite database at path, creating the file (mode 0600) and
// its directory if they don't exist. Foreign keys are enforced.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("storage: create database directory: %w", err)
	}
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_txlock", "immediate")
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String()

	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open database: %w", err)
	}
	d.SetMaxOpenConns(1)
	d.SetMaxIdleConns(1)
	d.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := d.PingContext(ctx); err != nil {
		_ = d.Close()
		hint := ""
		if strings.Contains(err.Error(), "readonly") || strings.Contains(err.Error(), "unable to open") {
			hint = fmt.Sprintf(" - the database file and its directory (%s) must be writable by this user, because SQLite creates its -wal and -shm files beside the database", filepath.Dir(path))
		}
		return nil, fmt.Errorf("storage: open database %s: %w%s", path, err, hint)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("storage: restrict database file mode: %w", err)
	}
	return &DB{sql: d}, nil
}

// Close releases the database. Call it before exit so the write-ahead log
// is checkpointed into the main file.
func (db *DB) Close() {
	_ = db.sql.Close()
}

// SQL exposes the underlying handle, for the backup command and for tests
// that inspect tables directly.
func (db *DB) SQL() *sql.DB { return db.sql }

// Statement is one parameterized SQL statement.
type Statement struct {
	Query     string
	Arguments []interface{}
}

// WriteResult is the outcome of one statement in a write.
type WriteResult struct {
	Err          error
	RowsAffected int64
	LastInsertID int64
}

// write runs stmts in order inside one transaction. If any statement fails
// the whole transaction is rolled back, that statement's WriteResult.Err is
// set, and later results are zero. The returned error is for failures of the
// transaction itself (begin, commit), not of a statement.
func (db *DB) write(ctx context.Context, stmts []Statement) ([]WriteResult, error) {
	results := make([]WriteResult, len(stmts))
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	for i, s := range stmts {
		res, err := tx.ExecContext(ctx, s.Query, s.Arguments...)
		if err != nil {
			results[i].Err = err
			_ = tx.Rollback()
			return results, nil
		}
		results[i].RowsAffected, _ = res.RowsAffected()
		results[i].LastInsertID, _ = res.LastInsertId()
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return results, nil
}

// QueryResult holds a query's rows, fully read, so nothing is left open
// holding the single connection.
type QueryResult struct {
	rows [][]any
	pos  int
}

// queryOne runs one query and reads all its rows.
func (db *DB) queryOne(ctx context.Context, s Statement) (*QueryResult, error) {
	rs, err := db.sql.QueryContext(ctx, s.Query, s.Arguments...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rs.Close() }()
	cols, err := rs.Columns()
	if err != nil {
		return nil, err
	}
	qr := &QueryResult{pos: -1}
	for rs.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rs.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = append([]byte(nil), b...)
			}
		}
		qr.rows = append(qr.rows, vals)
	}
	return qr, rs.Err()
}

// queryString is queryOne for a statement with no arguments.
func (db *DB) queryString(ctx context.Context, query string) (*QueryResult, error) {
	return db.queryOne(ctx, Statement{Query: query})
}

// Next advances to the next row, reporting whether there is one.
func (q *QueryResult) Next() bool {
	q.pos++
	return q.pos < len(q.rows)
}

// Scan copies the current row's columns into dest. Supported destinations:
// *int64, *int, *bool, *string, *[]byte, *sql.NullString, *sql.NullInt64
// and *any.
func (q *QueryResult) Scan(dest ...any) error {
	if q.pos < 0 || q.pos >= len(q.rows) {
		return fmt.Errorf("storage: Scan called without a current row")
	}
	row := q.rows[q.pos]
	if len(dest) != len(row) {
		return fmt.Errorf("storage: Scan wants %d values, row has %d", len(dest), len(row))
	}
	for i, d := range dest {
		if err := assign(d, row[i]); err != nil {
			return fmt.Errorf("storage: Scan column %d: %w", i, err)
		}
	}
	return nil
}

func assign(dest, v any) error {
	switch d := dest.(type) {
	case *any:
		*d = v
	case *int64:
		n, ok := asInt(v)
		if !ok {
			return fmt.Errorf("cannot store %T in int64", v)
		}
		*d = n
	case *int:
		n, ok := asInt(v)
		if !ok {
			return fmt.Errorf("cannot store %T in int", v)
		}
		*d = int(n)
	case *bool:
		n, ok := asInt(v)
		if !ok {
			return fmt.Errorf("cannot store %T in bool", v)
		}
		*d = n != 0
	case *string:
		s, ok := asString(v)
		if !ok {
			return fmt.Errorf("cannot store %T in string", v)
		}
		*d = s
	case *[]byte:
		switch x := v.(type) {
		case []byte:
			*d = x
		case string:
			*d = []byte(x)
		default:
			return fmt.Errorf("cannot store %T in []byte", v)
		}
	case *sql.NullString:
		if v == nil {
			*d = sql.NullString{}
			return nil
		}
		s, ok := asString(v)
		if !ok {
			return fmt.Errorf("cannot store %T in NullString", v)
		}
		*d = sql.NullString{String: s, Valid: true}
	case *sql.NullInt64:
		if v == nil {
			*d = sql.NullInt64{}
			return nil
		}
		n, ok := asInt(v)
		if !ok {
			return fmt.Errorf("cannot store %T in NullInt64", v)
		}
		*d = sql.NullInt64{Int64: n, Valid: true}
	default:
		return fmt.Errorf("unsupported destination type %T", dest)
	}
	return nil
}

func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case float64:
		return int64(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	}
	return 0, false
}

func asString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case []byte:
		return string(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	}
	return "", false
}
