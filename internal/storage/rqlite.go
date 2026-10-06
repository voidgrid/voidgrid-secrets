// Package storage provides access to the single-node rqlite database:
// connection management, schema migrations, and repositories that
// transparently apply envelope encryption around secret values.
//
// All ciphertext, nonce, and wrapped-key fields are stored as
// base64-encoded TEXT, not SQLite BLOB. The gorqlite client does not
// base64-decode BLOB values on read (it only base64-encodes []byte
// arguments going in), so round-tripping binary data through a BLOB column
// via gorqlite silently corrupts it. Storing base64 TEXT explicitly and
// decoding it ourselves avoids relying on that behavior entirely.
package storage

import (
	"fmt"

	"github.com/rqlite/gorqlite"
)

// DB wraps a connection to a single-node rqlite instance.
type DB struct {
	conn *gorqlite.Connection
}

// Open connects to the rqlite instance at addr (e.g. "http://127.0.0.1:4001")
// and configures strong consistency for auth-critical reads. Multi-node
// rqlite deployments can raise or lower the level later via config without
// any other code change.
func Open(addr string) (*DB, error) {
	conn, err := gorqlite.Open(addr)
	if err != nil {
		return nil, fmt.Errorf("storage: open rqlite connection: %w", err)
	}
	if err := conn.SetConsistencyLevel(gorqlite.ConsistencyLevelStrong); err != nil {
		return nil, fmt.Errorf("storage: set consistency level: %w", err)
	}
	return &DB{conn: conn}, nil
}

// Close releases the underlying HTTP client resources.
func (db *DB) Close() {
	db.conn.Close()
}
