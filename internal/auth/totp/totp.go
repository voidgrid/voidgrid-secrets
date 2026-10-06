// Package totp wraps pquerna/otp for TOTP enrollment and validation, used
// by the password+TOTP web authentication method (TOTP is always required
// for that method; there is no bypass).
package totp

import (
	"fmt"
	"net/url"

	"github.com/pquerna/otp/totp"
)

// Issuer is shown in authenticator apps (Google Authenticator, Authy, ...)
// alongside the account name during enrollment.
const Issuer = "voidgrid-secrets"

// Generate creates a new TOTP secret for accountName (typically the
// username), returning the base32 secret (to store, encrypted, against the
// user) and the otpauth:// provisioning URI (to render as a QR code during
// enrollment).
func Generate(accountName string) (secret, provisioningURI string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      Issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", fmt.Errorf("totp: generate: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// Validate reports whether code is a currently valid TOTP code for secret.
func Validate(code, secret string) bool {
	return totp.Validate(code, secret)
}

// URI rebuilds the otpauth:// provisioning URI for an existing secret, in
// the same form Generate returns (default 6 digits, 30 seconds, SHA-1).
func URI(accountName, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", Issuer)
	return "otpauth://totp/" + url.PathEscape(Issuer+":"+accountName) + "?" + v.Encode()
}
