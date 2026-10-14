package storage

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSplitStatements(t *testing.T) {
	cases := []struct {
		name, in string
		want     []string
	}{
		{"plain", "CREATE TABLE a (x);\nCREATE TABLE b (y);", []string{"CREATE TABLE a (x)", "CREATE TABLE b (y)"}},
		{"no trailing semicolon", "SELECT 1", []string{"SELECT 1"}},
		{"semicolon in a line comment", "-- loads keys; then more words\nSELECT 1;", []string{"SELECT 1"}},
		{"comment-only file", "-- nothing here; at all\n", []string{}},
		{"trailing comment fragment", "SELECT 1; -- done; really\n", []string{"SELECT 1"}},
		{"semicolon in a block comment", "/* a; b */ SELECT 1;", []string{"SELECT 1"}},
		{"unterminated block comment", "SELECT 1; /* never closed; ever", []string{"SELECT 1"}},
		{"semicolon in a string", "INSERT INTO t VALUES ('a;b');", []string{"INSERT INTO t VALUES ('a;b')"}},
		{"escaped quote in a string", "INSERT INTO t VALUES ('it''s; ok');", []string{"INSERT INTO t VALUES ('it''s; ok')"}},
		{"comment marker in a string", "INSERT INTO t VALUES ('--x;y');", []string{"INSERT INTO t VALUES ('--x;y')"}},
		{"quoted identifier", `SELECT "a;b" FROM t;`, []string{`SELECT "a;b" FROM t`}},
		{"empty", "", []string{}},
	}
	for _, c := range cases {
		got := splitStatements(c.in)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// A comment-only statement used to make the driver return a nil result,
// and write() panicked reading it. It must succeed, and a statement that
// really is bad must come back as an error.
func TestWriteSurvivesCommentOnlyAndReportsBadSQL(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ctx := context.Background()

	results, err := db.write(ctx, []Statement{{Query: "-- just a comment"}, {Query: "CREATE TABLE t (x)"}})
	if err := writeErrAll("comment only", results, err); err != nil {
		t.Fatalf("comment-only statement: %v", err)
	}
	results, err = db.write(ctx, []Statement{{Query: "CREATE TABLE u (x)"}, {Query: "this is not sql"}})
	if err := writeErrAll("bad sql", results, err); err == nil {
		t.Fatal("bad SQL was not reported")
	}
	if _, err := db.sql.ExecContext(ctx, "SELECT 1 FROM u"); err == nil {
		t.Fatal("table u exists: the failed write was not rolled back")
	}
}
