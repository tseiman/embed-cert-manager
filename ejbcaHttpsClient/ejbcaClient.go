package ejbcaHttpsClient


import (
	"crypto/tls"
	"crypto/x509"
//	"io"
	"net/http"
	"os"
	"time"
	"log"
	"context"
	"encoding/pem"
	"bytes"
	"github.com/tseiman/embed-cert-manager/config"
)

/*
var soapClient *SOAPClient

// func newMTLSClient(clientCertFile, clientKeyFile, serverCAFile, serverName string) (*http.Client, error) {
*/

func TestConnection(j *config.Job, c *http.Client) bool {

	host := "https://" + j.Ca.Host +"/"
	log.Printf("INFO: EJBCA test connect to EJBCA %s ... ", host)
	// Erstmal nur “kann ich verbinden?” testen:
	// Nimm irgendeinen Endpoint, der bei dir existiert (später EJBCA REST).
	req, _ := http.NewRequest("GET", host, nil)
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("ERROR: EJBCA https client - TestConnection %v\n", err)
		return false
	}
	defer resp.Body.Close()

//	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode > 299 || resp.StatusCode < 200 {
		log.Printf("ERROR: EJBCA https client - TestConnection return code %s Not OK\n", resp.Status)
		return false
	}
//	log.Println(string(body))


	log.Printf(" %s\n", resp.Status)

	return true

}


func NewMTLSClient(j *config.Job) (*http.Client) {

	// 1) Client-Zertifikat laden
//	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	cert, err := tls.LoadX509KeyPair(j.Ca.ClientCert, j.Ca.ClientKey)
	if err != nil {
		log.Printf("ERROR: EJBCA https client - load client cert/key %v\n",  err)
		return nil
	}

	// 2) CA-Pool für Server-Validierung laden
	caPem, err := os.ReadFile(j.Ca.ServerCertChain)
	if err != nil {
		log.Printf("ERROR: EJBCA https client - read server CA file %v\n",  err)
		return nil
	}
	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caPem); !ok {
		log.Printf("ERROR: EJBCA https client - append server CA PEM: no certs found\n")
		return nil
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},

		// Wichtig: damit validierst du das Server-Zertifikat sauber gegen deine CA
		RootCAs: caPool,

		// Optional/oft nötig: wenn die URL ein IP/anderer Hostname ist,
		// aber das Zertifikat auf einen bestimmten Namen ausgestellt ist.
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

func CheckCertState(j *config.Job, hc *http.Client) bool {
	ctx := context.Background()

	certs, err := FindCertsViaGowsdl(ctx, j, hc, false)
	if err != nil {
		log.Printf("ERROR: find certs: %v\n", err)
	    return true
	}

	if len(certs) == 0 {
	    log.Println("INFO: No certificate found for user -> must enroll/renew")
	    return true // renew/enroll nötig
	}

	now := time.Now()
	best := PickBestValidCert(now, certs)
	if best == nil {
	    log.Println("INFO: No valid certificate found (all expired/notYetValid?) -> must enroll/renew")
	    return true
	}

//	if NeedsRenew(now, best, 14*24*time.Hour) {
	if NeedsRenew(now, best, time.Duration(j.Target.ChangeAfter) * time.Second) {

	    log.Println("INFO: Certificate exists but is within renewal window -> renew")
	    return true
	}

	log.Println("INFO: Certificate exists and is still valid -> no renew")
	return false

}


func EnrollOrRenewCert(j *config.Job, hc *http.Client, csrPEM []byte) (*x509.Certificate) {

	ctx := GetContext()
	// ---- Parameter für PKCS10 ----
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
		log.Printf("ERROR: EJBCA pkcs10 enroll failed for %q: %v\n", j.Name, err)
		return nil
	}

	// ---- Sanity checks (optional, aber empfohlen) ----
	if time.Now().After(cert.NotAfter) {
		log.Printf("ERROR: received certificate already expired (%s)\n", cert.NotAfter)
		return nil
	}

	if err := cert.VerifyHostname(j.Name); err != nil {
		// je nach SAN/DNS Setup evtl. nur warnen
		log.Printf("WARN: hostname verification failed: %v", err)
	}

	log.Printf(
		"INFO: received certificate: CN=%q Serial=%s NotAfter=%s",
		cert.Subject.CommonName,
		cert.SerialNumber.String(),
		cert.NotAfter.Format(time.RFC3339),
	)

	return cert
}


// cert ist *x509.Certificate
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

