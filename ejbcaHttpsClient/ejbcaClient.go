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

	if NeedsRenew(now, best, 14*24*time.Hour) {
	    log.Println("INFO: Certificate exists but is within renewal window -> renew")
	    return true
	}

	log.Println("INFO: Certificate exists and is still valid -> no renew")
	return false

}
