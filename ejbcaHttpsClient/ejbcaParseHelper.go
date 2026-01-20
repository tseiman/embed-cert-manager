package ejbcaHttpsClient

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"bytes"
	"time"
)

func parseEJBCAcertData(b []byte) (*x509.Certificate, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("empty certificateData")
	}

	// Try direct DER first
	if b[0] == 0x30 {
		if c, err := x509.ParseCertificate(b); err == nil {
			return c, nil
		}
	}

	// Up to 2 base64 decodes (handles base64(base64(der)))
	decoded := b
	for i := 0; i < 2; i++ {
		s := strings.TrimSpace(string(decoded))
		s = strings.ReplaceAll(s, "\n", "")
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.ReplaceAll(s, " ", "")
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			break
		}
		decoded = der
		if len(decoded) > 0 && decoded[0] == 0x30 {
			c, err := x509.ParseCertificate(decoded)
			if err != nil {
				return nil, fmt.Errorf("x509 parse after %d base64 decode(s): %w", i+1, err)
			}
			return c, nil
		}
	}

	return nil, fmt.Errorf("could not obtain DER from certificateData (may be malformed)")
}

func PickBestValidCert(now time.Time, certs []*x509.Certificate) *x509.Certificate {
	var best *x509.Certificate
	for _, c := range certs {
		if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
			continue
		}
		if best == nil || c.NotAfter.After(best.NotAfter) {
			best = c
		}
	}
	return best
}

// NeedsRenew returns true if cert is nil or expires within changeBefore.
func NeedsRenew(now time.Time, cert *x509.Certificate, changeBefore time.Duration) bool {
	if cert == nil {
		return true
	}
	return cert.NotAfter.Sub(now) <= changeBefore
}


