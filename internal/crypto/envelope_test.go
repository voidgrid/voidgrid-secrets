package crypto_test

import (
	"bytes"
	"testing"

	"github.com/voidgrid/voidgrid-secrets/internal/crypto"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	plaintext := []byte("super secret value")
	ciphertext, nonce, err := crypto.Encrypt(dek, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext must not equal plaintext")
	}

	got, err := crypto.Decrypt(dek, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestWrapUnwrapDEKRoundTrip(t *testing.T) {
	rootKey := make([]byte, crypto.KeySize)
	for i := range rootKey {
		rootKey[i] = byte(i)
	}

	dek, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK: %v", err)
	}

	wrapped, nonce, err := crypto.WrapDEK(rootKey, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	got, err := crypto.UnwrapDEK(rootKey, wrapped, nonce)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("got %x, want %x", got, dek)
	}
}

func TestDecryptDetectsTamperedCiphertext(t *testing.T) {
	dek, _ := crypto.GenerateDEK()
	ciphertext, nonce, err := crypto.Encrypt(dek, []byte("tamper me"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := bytes.Clone(ciphertext)
	tampered[0] ^= 0xFF

	if _, err := crypto.Decrypt(dek, tampered, nonce); err == nil {
		t.Fatal("expected Decrypt to fail on tampered ciphertext, got nil error")
	}
}

func TestUnwrapDEKDetectsTamperedWrappedKey(t *testing.T) {
	rootKey := make([]byte, crypto.KeySize)
	dek, _ := crypto.GenerateDEK()
	wrapped, nonce, err := crypto.WrapDEK(rootKey, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	tampered := bytes.Clone(wrapped)
	tampered[0] ^= 0xFF

	if _, err := crypto.UnwrapDEK(rootKey, tampered, nonce); err == nil {
		t.Fatal("expected UnwrapDEK to fail on tampered wrapped key, got nil error")
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	dek1, _ := crypto.GenerateDEK()
	dek2, _ := crypto.GenerateDEK()

	ciphertext, nonce, err := crypto.Encrypt(dek1, []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := crypto.Decrypt(dek2, ciphertext, nonce); err == nil {
		t.Fatal("expected Decrypt to fail with the wrong key, got nil error")
	}
}

func TestEncryptGeneratesUniqueNonces(t *testing.T) {
	dek, _ := crypto.GenerateDEK()
	seen := make(map[string]bool)

	const samples = 1000
	for i := 0; i < samples; i++ {
		_, nonce, err := crypto.Encrypt(dek, []byte("same plaintext every time"))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if len(nonce) != crypto.NonceSize {
			t.Fatalf("nonce length = %d, want %d", len(nonce), crypto.NonceSize)
		}
		key := string(nonce)
		if seen[key] {
			t.Fatalf("duplicate nonce observed after %d samples", i)
		}
		seen[key] = true
	}
}
