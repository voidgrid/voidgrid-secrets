package crypto_test

import (
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
)

// FuzzDecrypt exercises the decrypt parsing boundary: arbitrary
// ciphertext/nonce combinations (wrong lengths, truncated, empty) must
// never panic, only return an error.
func FuzzDecrypt(f *testing.F) {
	key := make([]byte, crypto.KeySize)
	validCiphertext, validNonce, err := crypto.Encrypt(key, []byte("seed plaintext"))
	if err != nil {
		f.Fatalf("Encrypt: %v", err)
	}

	f.Add(validCiphertext, validNonce)
	f.Add([]byte{}, []byte{})
	f.Add([]byte("short"), []byte("short"))
	f.Add(validCiphertext, []byte{})
	f.Add([]byte{}, validNonce)
	f.Add(validCiphertext, validNonce[:len(validNonce)-1])
	f.Add(append(append([]byte{}, validCiphertext...), 0xFF), validNonce)

	f.Fuzz(func(t *testing.T, ciphertext, nonce []byte) {
		_, _ = crypto.Decrypt(key, ciphertext, nonce)
	})
}

// FuzzUnwrapDEK exercises the same boundary for unwrapping a DEK.
func FuzzUnwrapDEK(f *testing.F) {
	rootKey := make([]byte, crypto.KeySize)
	dek, err := crypto.GenerateDEK()
	if err != nil {
		f.Fatalf("GenerateDEK: %v", err)
	}
	validWrapped, validNonce, err := crypto.WrapDEK(rootKey, dek)
	if err != nil {
		f.Fatalf("WrapDEK: %v", err)
	}

	f.Add(validWrapped, validNonce)
	f.Add([]byte{}, []byte{})
	f.Add([]byte("short"), []byte("short"))
	f.Add(validWrapped, validNonce[:len(validNonce)-1])

	f.Fuzz(func(t *testing.T, wrapped, nonce []byte) {
		_, _ = crypto.UnwrapDEK(rootKey, wrapped, nonce)
	})
}
