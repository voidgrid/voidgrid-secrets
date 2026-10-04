package web

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// qrCodeSize is the rendered image's width and height in pixels. The raw
// QR encoding is one pixel per module - far too small to scan - so this
// scales it up to something a phone camera can actually read.
const qrCodeSize = 240

// qrCodeDataURI renders content (here, a TOTP otpauth:// provisioning
// URI) as a PNG QR code and returns it as a data: URI, ready to drop
// straight into an <img src="..."> with no separate asset or endpoint.
func qrCodeDataURI(content string) (string, error) {
	code, err := qr.Encode(content, qr.M, qr.Auto)
	if err != nil {
		return "", fmt.Errorf("web: encode QR code: %w", err)
	}
	code, err = barcode.Scale(code, qrCodeSize, qrCodeSize)
	if err != nil {
		return "", fmt.Errorf("web: scale QR code: %w", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, code); err != nil {
		return "", fmt.Errorf("web: encode QR code as PNG: %w", err)
	}

	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
