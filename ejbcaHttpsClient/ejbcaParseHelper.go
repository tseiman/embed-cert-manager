package ejbcaHttpsClient

/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 *  Package ejbcaHttpsClient contains parsing and selection helpers for certificate material returned by EJBCA.
 *  It supports parsing DER and base64-encoded certificate data and provides helper logic for
 *  choosing the best valid certificate and deciding whether renewal is needed.
 *
 */

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"bytes"
	"time"
)


/**
 *  parseEJBCAcertData parses certificate data returned by EJBCA into an x509 certificate.
 *  It attempts multiple decoding strategies commonly seen in EJBCA responses, including:
 *  raw DER, base64(DER), and robust trimming of extra bytes around ASN.1 data.
 *
 *  Params:
 *    - b: raw certificate data bytes (DER or base64-encoded).
 *    - caller: label used for diagnostics/logging context.
 *
 *  Returns:
 *    - *x509.Certificate: parsed certificate.
 *    - error: non-nil if decoding/parsing fails.
 *
 */
func parseEJBCAcertData(b []byte, caller string) (*x509.Certificate, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("empty certificateData")
	}

	// Try direct DER first
	if b[0] == 0x30 {
		if c, err := x509.ParseCertificate(b); err == nil {
			return c, nil   // (c), nil
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

		    c, errCert := x509.ParseCertificate(decoded)
		    if errCert == nil {
		        return c, nil
		    }

		    return nil, fmt.Errorf("DER parse failed: x509=%v; ", errCert)
		}

	}

	return nil, fmt.Errorf("could not obtain DER from certificateData (may be malformed)")
}

/**
 *  PickBestValidCert selects the best currently valid certificate from a list of candidates.
 *  It evaluates validity at the provided point in time and typically prefers the certificate
 *  with the latest expiration (NotAfter) among valid candidates.
 *
 *  Params:
 *    - now: time used to evaluate certificate validity.
 *    - certs: candidate certificates.
 *
 *  Returns:
 *    - *x509.Certificate: best valid certificate, or nil if none are valid.
 *
 */
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


/**
 *  NeedsRenew reports whether a certificate should be renewed based on a "changeBefore" window.
 *  If cert is nil, renewal is required. Otherwise renewal is required when the remaining lifetime
 *  is less than or equal to changeBefore.
 *
 *  Params:
 *    - now: current time used for comparison.
 *    - cert: certificate to evaluate (may be nil).
 *    - changeBefore: renewal window before expiration.
 *
 *  Returns:
 *    - bool: true if renewal should be triggered, false otherwise.
 *
 */
func NeedsRenew(now time.Time, cert *x509.Certificate, changeBefore time.Duration) bool {
	if cert == nil {
		log.Printf("cert=nil -> renew needed")
		return true
	}

	remaining := cert.NotAfter.Sub(now)
	delta := remaining - changeBefore
	needs := remaining <= changeBefore

	log.Printf("cert remaining=%s (%s), renewBefore=%s (%s), delta=%s (%s), needsRenew=%v, NotAfter=%s",
		remaining, humanDur(remaining),
		changeBefore, humanDur(changeBefore),
		delta, humanDur(delta),
		needs,
		cert.NotAfter.Format(time.RFC3339),
	)

	return needs
}

/**
 *  trimToASN1Object attempts to trim input data to a plausible single ASN.1 object.
 *  This is used as a robustness helper when the input contains whitespace or extra bytes
 *  around the DER-encoded certificate.
 *
 *  Params:
 *    - b: input bytes.
 *
 *  Returns:
 *    - []byte: trimmed ASN.1 object bytes.
 *    - error: non-nil if no plausible ASN.1 object could be identified.
 *
 */
func trimToASN1Object(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x30 {
		return b, fmt.Errorf("not a SEQUENCE / too short")
	}

	// DER length decoding (definite form)
	lb := b[1]
	if lb == 0x80 {
		// Indefinite length (BER). Viele Go-Libs mögen das nicht.
		return b, fmt.Errorf("indefinite-length BER (0x80), cannot trim via DER length")
	}

	var hdr int
	var contentLen int

	if lb&0x80 == 0 {
		// short form
		hdr = 2
		contentLen = int(lb)
	} else {
		// long form
		n := int(lb & 0x7f)
		if len(b) < 2+n {
			return b, fmt.Errorf("length bytes truncated")
		}
		hdr = 2 + n
		contentLen = 0
		for i := 0; i < n; i++ {
			contentLen = (contentLen << 8) | int(b[2+i])
		}
	}

	total := hdr + contentLen
	if total <= 0 || total > len(b) {
		return b, fmt.Errorf("computed ASN.1 length invalid: total=%d len=%d", total, len(b))
	}

	if total != len(b) {
		// <- das ist oft der eigentliche Bug
		b = b[:total]
	}
	return b, nil
}

/**
 *  humanDur formats a duration into a compact human-readable form (e.g. "1d 2h 3m 4s").
 *
 *  Params:
 *    - d: duration to format.
 *
 *  Returns:
 *    - string: formatted duration string.
 *
 */
func humanDur(d time.Duration) string {
	neg := d < 0
	if neg {
		d = -d
	}

	sec := int64(d / time.Second)

	const (
		year = 365 * 24 * 3600
		day  = 24 * 3600
		hour = 3600
		min  = 60
	)

	y := sec / year; sec %= year
	dd := sec / day; sec %= day
	h := sec / hour; sec %= hour
	m := sec / min; sec %= min
	s := sec

	var parts []string
	if y > 0 { parts = append(parts, fmt.Sprintf("%dy", y)) }
	if dd > 0 { parts = append(parts, fmt.Sprintf("%dd", dd)) }
	if h > 0 { parts = append(parts, fmt.Sprintf("%dh", h)) }
	if m > 0 { parts = append(parts, fmt.Sprintf("%dm", m)) }
	if s > 0 || len(parts) == 0 { parts = append(parts, fmt.Sprintf("%ds", s)) }

	out := strings.Join(parts, " ")
	if neg {
		out = "-" + out
	}
	return out
}

