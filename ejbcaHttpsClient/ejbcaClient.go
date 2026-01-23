package ejbcaHttpsClient


/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 *  Package ejbcaHttpsClient implements an mTLS-enabled EJBCA SOAP/HTTPS client.
 *  It handles certificate lookup, enrollment, renewal, and encoding helpers.
 *
 */


import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"time"
	"context"
	"encoding/pem"
	"bytes"
	"github.com/tseiman/embed-cert-manager/config"
	"github.com/tseiman/embed-cert-manager/logger"
)

/**
 *  TestConnection checks whether the EJBCA endpoint is reachable using the provided HTTP client.
 *
 *  Params:
 *    - j: job containing CA configuration.
 *    - c: configured HTTP client.
 *
 *  Returns:
 *    - bool: true if the endpoint is reachable.
 *
 */
func TestConnection(j *config.Job, c *http.Client) bool {

	host := "https://" + j.Ca.Host +"/"
	logger.Infof("EJBCA test connect to EJBCA %s ... ", host)
	// tr can I connect ? first
	// Try some endpoint of EJBCA first - later we use SOAP
	req, _ := http.NewRequest("GET", host, nil)
	resp, err := c.Do(req)
	if err != nil {
		logger.Errorf("EJBCA https client - TestConnection %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 || resp.StatusCode < 200 {
		logger.Errorf("EJBCA https client - TestConnection return code %s Not OK\n", resp.Status)
		return false
	}

	logger.Debugf(" %s\n", resp.Status)

	return true
}


/**
 *  NewMTLSClient creates an HTTP client configured for mutual TLS authentication
 *  against the EJBCA API endpoint.
 *
 *  Params:
 *    - j: job containing TLS credential paths.
 *
 *  Returns:
 *    - *http.Client: mTLS-configured HTTP client.
 *
 */
func NewMTLSClient(j *config.Job) (*http.Client) {

	// 1) load Client-Certificate
	cert, err := tls.LoadX509KeyPair(j.Ca.ClientCert, j.Ca.ClientKey)
	if err != nil {
		logger.Errorf("EJBCA https client - load client cert/key %v\n",  err)
		return nil
	}

	// 2) load CA-Pool for Server-Validation
	caPem, err := os.ReadFile(j.Ca.ServerCertChain)
	if err != nil {
		logger.Errorf("EJBCA https client - read server CA file %v\n",  err)
		return nil
	}
	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caPem); !ok {
		logger.Errorf("EJBCA https client - append server CA PEM: no certs found\n")
		return nil
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},

		// Important: with this we validate the server certificate against my CA
		RootCAs: caPool,

		// Optional often used if the URL contains an IP or dfferent host name
		// but the certificate was issued on a specific host
		ServerName: j.Ca.Host,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}


/**
 *  CheckCertState checks whether a valid certificate already exists on the CA.
 *
 *  Params:
 *    - j: job defining the certificate identity.
 *    - hc: mTLS-configured HTTP client.
 *
 *  Returns:
 *    - bool: true if a valid certificate exists and renewal is not required.
 *
 */
func CheckCertState(j *config.Job, hc *http.Client) bool {
	ctx := context.Background()

	certs, err := FindCertsViaGowsdl(ctx, j, hc, false)
	if err != nil {
		logger.Errorf("find certs: %v\n", err)
	    return true
	}

	if len(certs) == 0 {
	    logger.Infoln("No certificate found for user -> must enroll/renew")
	    return true // renew/enroll nötig
	}

	now := time.Now()
	best := PickBestValidCert(now, certs)
	if best == nil {
	    logger.Infoln("No valid certificate found (all expired/notYetValid?) -> must enroll/renew")
	    return true
	}

	if NeedsRenew(now, best, time.Duration(j.Target.ChangeAfter) * time.Second) {

	    logger.Infoln("Certificate exists but is within renewal window -> renew")
	    return true
	}

	logger.Infoln("Certificate exists and is still valid -> no renew")
	return false

}

/**
 *  EnrollOrRenewCert enrolls or renews a certificate using the provided CSR.
 *
 *  Params:
 *    - j: job providing CA and end-entity configuration.
 *    - hc: mTLS-configured HTTP client.
 *    - csrPEM: CSR in PEM format.
 *
 *  Returns:
 *    - *x509.Certificate: issued certificate.
 *
 */
func EnrollOrRenewCert(j *config.Job, hc *http.Client, csrPEM []byte) (*x509.Certificate) {

	ctx := GetContext()
	// ---- Parameters for PKCS10 ----
	p := Pkcs10Params{
		Username: j.Name,     // End Entity username (host/device name)
		Password: j.Ca.Password,         // oft leer erlaubt; sonst End Entity Password / OTP
		CSRPEM:   csrPEM,     // -----BEGIN CERTIFICATE REQUEST-----
		
		// Optional – in vielen Setups leer lassen:
	//	CertProfile: j.Ca.CertProfile,    	 // z.B. "TLS-Server"
	//	CAName:      j.Ca.CAName,     		 // z.B. "TseiWebCA"
	// ResponseType: 	j.Ca.ResponseType,
	}

	cert, err := Pkcs10RequestViaGowsdl(ctx, j, hc, p)
	if err != nil {
		// SOAP / Auth / Profile / CSR Fehler landen hier
		logger.Errorf("EJBCA pkcs10 enroll failed for %q: %v\n", j.Name, err)
		return nil
	}

	// ---- Sanity checks (optional, aber empfohlen) ----
	if time.Now().After(cert.NotAfter) {
		logger.Errorf("received certificate already expired (%s)\n", cert.NotAfter)
		return nil
	}

	if err := cert.VerifyHostname(j.Name); err != nil {
		// je nach SAN/DNS Setup evtl. nur warnen
		logger.Warnf("hostname verification failed: %v", err)
	}

	logger.Infof(
		"received certificate: CN=%q Serial=%s NotAfter=%s",
		cert.Subject.CommonName,
		cert.SerialNumber.String(),
		cert.NotAfter.Format(time.RFC3339),
	)

	return cert
}


/**
 *  CertToPEM encodes an x509 certificate into PEM format.
 *
 *  Params:
 *    - cert: certificate to encode.
 *
 *  Returns:
 *    - []byte: PEM-encoded certificate.
 *    - error: non-nil if encoding fails.
 *
 */
func CertToPEM(cert *x509.Certificate) ([]byte, error) {
	var buf bytes.Buffer
	err := pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw, // DER
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

