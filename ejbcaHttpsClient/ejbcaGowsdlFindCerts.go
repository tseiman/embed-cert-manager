package ejbcaHttpsClient

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"log"
	"net/http"

	"github.com/hooklift/gowsdl/soap"
	"github.com/tseiman/embed-cert-manager/config"
	"github.com/tseiman/embed-cert-manager/ejbcaws"
)


func FindCertsViaGowsdl(ctx context.Context, j *config.Job,hc *http.Client, onlyValid bool) ([]*x509.Certificate, error) {
	/* hc, err := NewMTLSClient(j)
	if err != nil {
		return nil, err
	}
*/
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
/*	for _, item := range resp.Return_ {
		if item == nil {
			continue
		}

		c, err := decodeEjbcaCertDataToX509(string(item.CertificateData))
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
*/
for _, item := range resp.Return_ {
    if item == nil || len(item.CertificateData) == 0 {
        continue
    }
    b := item.CertificateData
	p := 16
	if len(b) < p { p = len(b) }
	log.Printf("certData len=%d hex=% x text=%.20q", len(b), b[:p], string(b[:p]))

    c, err := parseEJBCAcertData(item.CertificateData)
    if err != nil {
        return nil, fmt.Errorf("x509 parse: %w", err)
    }
    out = append(out, c)
}



	return out, nil
}

func decodeEjbcaCertDataToX509(certData string) (*x509.Certificate, error) {
	s := strings.TrimSpace(certData)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, " ", "")

	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	c, err := parseEJBCAcertData(der)
	if err != nil {
		return nil, fmt.Errorf("x509 parse: %w", err)
	}
	return c, nil
}

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



