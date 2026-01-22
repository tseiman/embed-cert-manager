package ejbcaHttpsClient

/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 *  Package ejbcaHttpsClient implements PKCS#10 enrollment/renewal against EJBCA using SOAP (gowsdl).
 *  It converts CSR PEM to base64 DER for SOAP requests and parses the returned certificate data.
 *
 */

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"log"

	"github.com/hooklift/gowsdl/soap"

	"github.com/tseiman/embed-cert-manager/config"
	"github.com/tseiman/embed-cert-manager/ejbcaws"
)

/**
 *  Pkcs10Params holds the inputs required to request a certificate from EJBCA via PKCS#10.
 *  It includes the end-entity username/password and the CSR in PEM form.
 *
 */
type Pkcs10Params struct {
	Username    string
	Password    string // End Entity password / OTP (wenn euer WS das verlangt)
	CSRPEM      []byte // CSR als PEM
}


/**
 *  Pkcs10RequestViaGowsdl submits a PKCS#10 CSR to EJBCA using the generated gowsdl SOAP client.
 *  It builds the SOAP request, performs the call using the provided HTTP client (typically mTLS),
 *  and parses the returned certificate into an x509.Certificate.
 *
 *  Params:
 *    - ctx: context controlling cancellation and timeouts for the SOAP call.
 *    - j: job containing CA endpoint configuration (EJBCA URL, etc.).
 *    - hc: HTTP client used by the SOAP client (usually mTLS-configured).
 *    - p: PKCS#10 request parameters (username/password + CSR PEM).
 *
 *  Returns:
 *    - *x509.Certificate: issued certificate parsed from the SOAP response.
 *    - error: non-nil if request building, SOAP call, or parsing fails.
 *
 */
func Pkcs10RequestViaGowsdl(ctx context.Context, j *config.Job, hc *http.Client, p Pkcs10Params) (*x509.Certificate, error) {
	if hc == nil {
		return nil, fmt.Errorf("http client is nil")
	}

	sc := soap.NewClient(j.Ca.EJBCAApiUrl, soap.WithHTTPClient(hc))
	ws := ejbcaws.NewEjbcaWS(sc)


	csrB64, err := csrPEMToBase64DER(p.CSRPEM)
	if err != nil {
		return nil, err
	}


	if csrB64 == "" {
	    return nil, fmt.Errorf("csrB64 is empty")
	}
	log.Printf("csrB64 len=%d prefix=%q", len(csrB64), csrB64[:min(16,len(csrB64))])

	req := &ejbcaws.Pkcs10Request{
		XmlnsNs1: "http://ws.protocol.core.ejbca.org/",
		Arg0:     p.Username,
		Arg1:     p.Password,
		Arg2:     csrB64,
		Arg3:     "",
		Arg4:     "CERTIFICATE",
	}


	resp, err := ws.Pkcs10RequestContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("Pkcs10Request SOAP: %w", err)
	}
	if resp == nil || resp.Return_ == nil {
		return nil, fmt.Errorf("Pkcs10Request: empty response")
	}

	// CertificateResponse contains CertificateData (often base64, sometimes base64(base64(der)))
	certData := resp.Return_.Data
	if len(certData) == 0 {
	    return nil, fmt.Errorf("Pkcs10Request: empty certificate response data")
	}

	cert, err := parseEJBCAcertData(certData,"Pkcs10RequestViaGowsdl") // dein DER/base64/double-base64 parser
	if err != nil {
	    return nil, err
	}
	return cert, nil
}


/**
 *  csrPEMToBase64DER parses a CSR PEM block, validates its signature, and returns base64-encoded DER.
 *  This is the format required by the EJBCA SOAP PKCS#10 request.
 *
 *  Params:
 *    - csrPEM: CSR in PEM format.
 *
 *  Returns:
 *    - string: base64-encoded CSR DER bytes.
 *    - error: non-nil if PEM decoding, CSR parsing, or signature validation fails.
 *
 */
func csrPEMToBase64DER(csrPEM []byte) (string, error) {
	csrPEM = bytes.TrimSpace(csrPEM)
	if len(csrPEM) == 0 {
		return "", fmt.Errorf("empty CSR PEM")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return "", fmt.Errorf("CSR PEM decode: no PEM block found")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
	    return "", fmt.Errorf("CSR PEM ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
	    return "", fmt.Errorf("CSR signature invalid: %w", err)
	}

	log.Printf("CSR OK: Subject=%s DNSNames=%v IPs=%v SigAlg=%s PubKey=%T",
	    csr.Subject.String(), csr.DNSNames, csr.IPAddresses, csr.SignatureAlgorithm, csr.PublicKey,
	)

	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

