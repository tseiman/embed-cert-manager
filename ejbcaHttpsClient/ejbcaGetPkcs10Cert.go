package ejbcaHttpsClient

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

type Pkcs10Params struct {
	Username    string
	Password    string // End Entity password / OTP (wenn euer WS das verlangt)
	CSRPEM      []byte // CSR als PEM
//	CertProfile string // optional (je nach Setup)
//	CAName      string // optional (je nach Setup)
//	ResponseType string
}

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

