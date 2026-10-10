package storage

import (
	"context"
	"fmt"
	"time"
)

// RecoveryCodeRepo provides access to the recovery_codes table: single-use
// account-recovery codes, stored only as a hash (crypto.HashToken), the
// same high-entropy-token hashing already used for machine and session
// tokens.
type RecoveryCodeRepo struct {
	db *DB
}

// NewRecoveryCodeRepo returns a RecoveryCodeRepo backed by db.
func NewRecoveryCodeRepo(db *DB) *RecoveryCodeRepo {
	return &RecoveryCodeRepo{db: db}
}

// ReplaceForUser deletes any existing recovery codes for userID and
// inserts hashedCodes in their place. Called once per user, right after
// a fresh batch is generated and shown - regenerating invalidates any
// previously issued codes, since showing a new batch implies the old one
// is no longer the one the user has saved.
func (r *RecoveryCodeRepo) ReplaceForUser(ctx context.Context, userID int64, hashedCodes []string) error {
	stmts := []Statement{
		{
			Query:     `DELETE FROM recovery_codes WHERE user_id = ?`,
			Arguments: []interface{}{userID},
		},
	}
	for _, h := range hashedCodes {
		stmts = append(stmts, Statement{
			Query:     `INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)`,
			Arguments: []interface{}{userID, h, nowTimestamp()},
		})
	}

	results, err := r.db.write(ctx, stmts)
	if err != nil {
		return fmt.Errorf("storage: replace recovery codes for user %d: %w", userID, err)
	}
	for _, res := range results {
		if res.Err != nil {
			return fmt.Errorf("storage: replace recovery codes for user %d: %w", userID, res.Err)
		}
	}
	return nil
}

// Consume looks up an unused recovery code for userID matching codeHash
// and, if found, marks it used and returns ok=true. The check and the
// mark-as-used happen in one atomic UPDATE (same replay-prevention
// pattern as UserRepo.ConsumeTOTPCode), so concurrent attempts with the
// same code can't race past each other and each code works exactly once.
func (r *RecoveryCodeRepo) Consume(ctx context.Context, userID int64, codeHash string) (ok bool, err error) {
	results, err := r.db.write(ctx, []Statement{
		{
			Query: `UPDATE recovery_codes SET used_at = ?
				WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
			Arguments: []interface{}{formatTimestamp(time.Now()), userID, codeHash},
		},
	})
	if err != nil {
		return false, fmt.Errorf("storage: consume recovery code for user %d: %w", userID, err)
	}
	if results[0].Err != nil {
		return false, fmt.Errorf("storage: consume recovery code for user %d: %w", userID, results[0].Err)
	}
	return results[0].RowsAffected == 1, nil
}
