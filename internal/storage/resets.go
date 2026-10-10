package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
)

// How an account reset was started.
const (
	ResetFromRecoveryCode = "recovery_code"
	ResetFromBreakGlass   = "break_glass"
)

// Reset is an account reset in progress: started by a recovery code or a
// break-glass code, finished by setting new credentials.
type Reset struct {
	Source string
	// PendingTOTPSecret is the new TOTP secret being enrolled, or "".
	PendingTOTPSecret string
}

// ResetRepo stores account resets. Codes and reset tokens are kept only
// as hashes; a pending TOTP secret is encrypted with the root key.
//
// A break-glass code is "issued" by the `recover` command. Redeeming it
// (or a recovery code) "starts" a reset under a fresh reset token, which
// is what the browser or API client then holds until it finishes.
type ResetRepo struct {
	db      *DB
	rootKey []byte
}

// NewResetRepo returns a ResetRepo backed by db.
func NewResetRepo(db *DB, rootKey []byte) *ResetRepo {
	return &ResetRepo{db: db, rootKey: rootKey}
}

// IssueBreakGlass stores a break-glass code that can start one reset
// before expiresAt.
func (r *ResetRepo) IssueBreakGlass(ctx context.Context, codeHash string, expiresAt time.Time) error {
	results, err := r.db.write(ctx, []Statement{{
		Query: `INSERT INTO account_resets (source, code_hash, stage, expires_at, created_at)
			VALUES (?, ?, 'issued', ?, ?)`,
		Arguments: []interface{}{ResetFromBreakGlass, codeHash, formatTimestamp(expiresAt), nowTimestamp()},
	}})
	return writeErr("issue break-glass code", results, err)
}

// RedeemBreakGlass turns an issued, unexpired, unused break-glass code
// into a started reset held under resetHash until expiresAt. It reports
// whether the code was valid; each code works once.
func (r *ResetRepo) RedeemBreakGlass(ctx context.Context, codeHash, resetHash string, expiresAt time.Time) (bool, error) {
	results, err := r.db.write(ctx, []Statement{{
		Query: `UPDATE account_resets SET code_hash = ?, stage = 'started', expires_at = ?
			WHERE code_hash = ? AND source = ? AND stage = 'issued' AND used_at IS NULL AND expires_at > ?`,
		Arguments: []interface{}{resetHash, formatTimestamp(expiresAt), codeHash, ResetFromBreakGlass, nowTimestamp()},
	}})
	if err := writeErr("redeem break-glass code", results, err); err != nil {
		return false, err
	}
	return results[0].RowsAffected == 1, nil
}

// Start records a reset begun with a recovery code (already consumed by
// the caller), held under resetHash until expiresAt.
func (r *ResetRepo) Start(ctx context.Context, resetHash string, expiresAt time.Time) error {
	results, err := r.db.write(ctx, []Statement{{
		Query: `INSERT INTO account_resets (source, code_hash, stage, expires_at, created_at)
			VALUES (?, ?, 'started', ?, ?)`,
		Arguments: []interface{}{ResetFromRecoveryCode, resetHash, formatTimestamp(expiresAt), nowTimestamp()},
	}})
	return writeErr("start reset", results, err)
}

// SetPendingTOTP stores the TOTP secret being enrolled for a started reset.
func (r *ResetRepo) SetPendingTOTP(ctx context.Context, resetHash, secret string) error {
	ciphertext, nonce, err := crypto.Encrypt(r.rootKey, []byte(secret))
	if err != nil {
		return fmt.Errorf("storage: encrypt pending TOTP secret: %w", err)
	}
	results, err := r.db.write(ctx, []Statement{{
		Query: `UPDATE account_resets SET totp_secret_enc = ?, totp_secret_nonce = ?
			WHERE code_hash = ? AND stage = 'started' AND used_at IS NULL`,
		Arguments: []interface{}{b64enc(ciphertext), b64enc(nonce), resetHash},
	}})
	return writeErr("store pending TOTP secret", results, err)
}

// Get returns the started, unexpired, unfinished reset held under
// resetHash, or ok=false.
func (r *ResetRepo) Get(ctx context.Context, resetHash string) (Reset, bool, error) {
	qr, err := r.db.queryOne(ctx, Statement{
		Query: `SELECT source, totp_secret_enc, totp_secret_nonce FROM account_resets
			WHERE code_hash = ? AND stage = 'started' AND used_at IS NULL AND expires_at > ?`,
		Arguments: []interface{}{resetHash, nowTimestamp()},
	})
	if err != nil {
		return Reset{}, false, fmt.Errorf("storage: get reset: %w", err)
	}
	if !qr.Next() {
		return Reset{}, false, nil
	}
	var (
		reset       Reset
		enc, nonceS sql.NullString
	)
	if err := qr.Scan(&reset.Source, &enc, &nonceS); err != nil {
		return Reset{}, false, fmt.Errorf("storage: scan reset: %w", err)
	}
	if enc.Valid && nonceS.Valid {
		ciphertext, err := b64dec(enc.String)
		if err != nil {
			return Reset{}, false, fmt.Errorf("storage: decode pending TOTP secret: %w", err)
		}
		nonce, err := b64dec(nonceS.String)
		if err != nil {
			return Reset{}, false, fmt.Errorf("storage: decode pending TOTP nonce: %w", err)
		}
		plaintext, err := crypto.Decrypt(r.rootKey, ciphertext, nonce)
		if err != nil {
			return Reset{}, false, fmt.Errorf("storage: decrypt pending TOTP secret: %w", err)
		}
		reset.PendingTOTPSecret = string(plaintext)
	}
	return reset, true, nil
}

// Finish marks a started reset used. It reports whether it was still open,
// so two concurrent finishes can't both succeed.
func (r *ResetRepo) Finish(ctx context.Context, resetHash string) (bool, error) {
	results, err := r.db.write(ctx, []Statement{{
		Query: `UPDATE account_resets SET used_at = ?, totp_secret_enc = NULL, totp_secret_nonce = NULL
			WHERE code_hash = ? AND stage = 'started' AND used_at IS NULL AND expires_at > ?`,
		Arguments: []interface{}{nowTimestamp(), resetHash, nowTimestamp()},
	}})
	if err := writeErr("finish reset", results, err); err != nil {
		return false, err
	}
	return results[0].RowsAffected == 1, nil
}
