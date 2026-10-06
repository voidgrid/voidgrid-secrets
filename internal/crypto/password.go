package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. These follow OWASP's current baseline recommendation
// for interactive login (one thread, 64 MiB memory, 3 iterations); tune
// upward if homelab hardware can comfortably afford it.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	saltSize     = 16
)

// MinPasswordLength is the minimum accepted password length, enforced
// both server-side here (web form handlers, which get no schema
// validation) and via each API input struct's minLength tag (kept as a
// literal there since struct tags can't reference a Go const - keep both
// in sync with this value).
const MinPasswordLength = 14

// argonSlots bounds how many Argon2id computations run at once. Each one
// allocates argonMemory (64 MiB), and login is reachable without
// authentication, so without a cap a burst of parallel login attempts
// could exhaust the host's memory. Excess attempts wait their turn.
var argonSlots = make(chan struct{}, 4)

func argonKey(password, salt []byte, timeCost, memory uint32, threads uint8, keyLen uint32) []byte {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	return argon2.IDKey(password, salt, timeCost, memory, threads, keyLen)
}

// HashPassword returns an encoded Argon2id hash of password, in the form
// "$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>" (base64, unpadded).
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("crypto: generate salt: %w", err)
	}

	hash := argonKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyPassword reports whether password matches the Argon2id hash
// produced by HashPassword, using a constant-time comparison.
func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("crypto: malformed password hash")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("crypto: malformed password hash version: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("crypto: unsupported argon2 version %d", version)
	}

	var memory uint32
	var timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return false, fmt.Errorf("crypto: malformed password hash params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("crypto: malformed password hash salt: %w", err)
	}
	wantHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("crypto: malformed password hash digest: %w", err)
	}
	if len(wantHash) == 0 || len(wantHash) > 1024 {
		return false, fmt.Errorf("crypto: implausible password hash digest length %d", len(wantHash))
	}

	gotHash := argonKey([]byte(password), salt, timeCost, memory, threads, uint32(len(wantHash))) //nolint:gosec // bounds-checked above

	return subtle.ConstantTimeCompare(gotHash, wantHash) == 1, nil
}
