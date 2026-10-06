// Package crypto provides the envelope-encryption primitives used to
// protect secret values at rest: each secret gets its own randomly
// generated data-encryption key (DEK), which is itself wrapped by a single
// root key (KEK). Rotating the root key only requires re-wrapping DEKs;
// rotating a single secret only touches that secret's row.
//
// All encryption uses XChaCha20-Poly1305: its 192-bit nonce makes random
// nonce generation safe at any realistic volume, unlike the 96-bit nonces
// used by AES-GCM or standard ChaCha20-Poly1305.
package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the size in bytes of a root key or a data-encryption key.
const KeySize = chacha20poly1305.KeySize

// NonceSize is the size in bytes of an XChaCha20-Poly1305 nonce.
const NonceSize = chacha20poly1305.NonceSizeX

// GenerateDEK returns a new random 32-byte data-encryption key.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("crypto: generate DEK: %w", err)
	}
	return dek, nil
}

// WrapDEK encrypts dek with rootKey, returning the wrapped key and the
// nonce used. Both must be stored alongside the secret so the DEK can later
// be unwrapped.
func WrapDEK(rootKey, dek []byte) (wrapped, nonce []byte, err error) {
	wrapped, nonce, err = seal(rootKey, dek, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: wrap DEK: %w", err)
	}
	return wrapped, nonce, nil
}

// UnwrapDEK decrypts a wrapped DEK using rootKey and the nonce it was
// wrapped with.
func UnwrapDEK(rootKey, wrapped, nonce []byte) ([]byte, error) {
	dek, err := open(rootKey, wrapped, nonce, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap DEK: %w", err)
	}
	return dek, nil
}

// Encrypt encrypts plaintext with dek, returning the ciphertext and the
// nonce used.
func Encrypt(dek, plaintext []byte) (ciphertext, nonce []byte, err error) {
	ciphertext, nonce, err = seal(dek, plaintext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: encrypt: %w", err)
	}
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext with dek and the nonce it was encrypted with.
func Decrypt(dek, ciphertext, nonce []byte) ([]byte, error) {
	plaintext, err := open(dek, ciphertext, nonce, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return plaintext, nil
}

// WrapDEKWithAD is WrapDEK, additionally binding the wrapped key to ad:
// UnwrapDEKWithAD only succeeds with the same ad. Binding a secret's key to
// the secret's identity means a wrapped key copied onto another row can't
// be unwrapped there.
func WrapDEKWithAD(rootKey, dek, ad []byte) (wrapped, nonce []byte, err error) {
	wrapped, nonce, err = seal(rootKey, dek, ad)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: wrap DEK: %w", err)
	}
	return wrapped, nonce, nil
}

// UnwrapDEKWithAD unwraps a key wrapped by WrapDEKWithAD with the same ad.
func UnwrapDEKWithAD(rootKey, wrapped, nonce, ad []byte) ([]byte, error) {
	dek, err := open(rootKey, wrapped, nonce, ad)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap DEK: %w", err)
	}
	return dek, nil
}

// EncryptWithAD is Encrypt, additionally binding the ciphertext to ad.
func EncryptWithAD(dek, plaintext, ad []byte) (ciphertext, nonce []byte, err error) {
	ciphertext, nonce, err = seal(dek, plaintext, ad)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: encrypt: %w", err)
	}
	return ciphertext, nonce, nil
}

// DecryptWithAD decrypts ciphertext from EncryptWithAD with the same ad.
func DecryptWithAD(dek, ciphertext, nonce, ad []byte) ([]byte, error) {
	plaintext, err := open(dek, ciphertext, nonce, ad)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return plaintext, nil
}

// seal encrypts plaintext under key with a freshly generated random nonce,
// optionally authenticating (but not encrypting) additionalData.
func seal(key, plaintext, additionalData []byte) (ciphertext, nonce []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nonce, nil
}

// open decrypts ciphertext under key and nonce, verifying additionalData.
//
// aead.Open panics (rather than returning an error) if nonce is the wrong
// length, which would let a malformed or truncated nonce - from a
// corrupted DB row, for instance - crash the whole process. The explicit
// length check below turns that into an ordinary error.
func open(key, ciphertext, nonce, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size %d, want %d", len(nonce), aead.NonceSize())
	}

	return aead.Open(nil, nonce, ciphertext, additionalData)
}
