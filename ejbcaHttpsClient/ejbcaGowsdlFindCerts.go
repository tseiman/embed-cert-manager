package ejbcaHttpsClient

/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 *  Package ejbcaHttpsClient implements certificate lookup operations against EJBCA using SOAP (gowsdl).
 *  It can query existing certificates for a job, decode returned certificate data, and decide
 *  whether a renewal should be performed.
 *
 */

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"net/http"

	"github.com/hooklift/gowsdl/soap"
	"github.com/tseiman/embed-cert-manager/config"
	"github.com/tseiman/embed-cert-manager/ejbcaws"
)


/**
 *  FindCertsViaGowsdl queries EJBCA for certificates related to a job using the generated gowsdl client.
 *  It calls the EJBCA "findCerts" operation and decodes the returned certificate data into x509 objects.
 *
 *  Params:
 *    - ctx: context controlling cancellation and timeouts for the SOAP call.
 *    - j: job providing identity and CA endpoint configuration.
 *    - hc: HTTP client used by the SOAP client (usually mTLS-configured).
 *    - onlyValid: if true, request only currently valid certificates when supported by the API.
 *
 *  Returns:
 *    - []*x509.Certificate: decoded certificates (may be empty if none exist).
 *    - error: non-nil if SOAP call or decoding fails.
 *
 */
func FindCertsViaGowsdl(ctx context.Context, j *config.Job,hc *http.Client, onlyValid bool) ([]*x509.Certificate, error) {

	sc := soap.NewClient(
		j.Ca.EJBCAApiUrl,
		soap.WithHTTPClient(hc),
	)

	ws := ejbcaws.NewEjbcaWS(sc)

	req := &ejbcaws.FindCerts{
		Arg0: j.Name,
		Arg1: onlyValid,
	}

	resp, err := ws.FindCertsContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("FindCerts SOAP: %w", err)
	}

	var out []*x509.Certificate

	for _, item := range resp.Return_ {
	    if item == nil || len(item.CertificateData) == 0 {
	        continue
	    }
	    b := item.CertificateData
		p := 16
		if len(b) < p { p = len(b) }
//		log.Printf("certData len=%d hex=% x text=%.20q", len(b), b[:p], string(b[:p]))

	    c, err := parseEJBCAcertData(item.CertificateData,"FindCertsViaGowsdl")
	    if err != nil {
	        return nil, fmt.Errorf("x509 parse: %w", err)
	    }
	    out = append(out, c)
	}

	return out, nil
}

/**
 *  decodeEjbcaCertDataToX509 decodes certificate data returned by EJBCA into an x509 certificate.
 *  EJBCA responses may contain base64 DER and, in some cases, nested/double base64 encodings.
 *
 *  Params:
 *    - certData: certificate data string returned by EJBCA.
 *    - caller: label used for diagnostics/logging context.
 *
 *  Returns:
 *    - *x509.Certificate: parsed certificate.
 *    - error: non-nil if decoding or x509 parsing fails.
 *
 */
func decodeEjbcaCertDataToX509(certData string,caller string) (*x509.Certificate, error) {
	s := strings.TrimSpace(certData)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, " ", "")

	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	c, err := parseEJBCAcertData(der,caller)
	if err != nil {
		return nil, fmt.Errorf("x509 parse: %w", err)
	}
	return c, nil
}

/**
 *  ShouldRenewViaGowsdl determines whether a certificate renewal should be performed for a job.
 *  It retrieves existing certificates from EJBCA, selects the best currently valid certificate,
 *  and checks whether it is close enough to expiry to require renewal.
 *
 *  Params:
 *    - ctx: context controlling cancellation and timeouts for the SOAP call(s).
 *    - j: job containing identity and renewal settings.
 *    - hc: HTTP client used by the SOAP client (usually mTLS-configured).
 *
 *  Returns:
 *    - bool: true if renewal should be performed, false if no renewal is needed.
 *    - error: non-nil if lookup or decoding fails.
 *
 */
func ShouldRenewViaGowsdl(ctx context.Context, j *config.Job, hc *http.Client) (bool, error) {
    certs, err := FindCertsViaGowsdl(ctx, j, hc, false)
    if err != nil {
        return false, err
    }
    if len(certs) == 0 {
        return true, nil
    }
    now := time.Now()
    best := PickBestValidCert(now, certs)
    if best == nil {
        return true, nil
    }
    if NeedsRenew(now, best, 14*24*time.Hour) {
        return true, nil
    }
    return false, nil
}
