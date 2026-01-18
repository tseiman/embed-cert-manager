package ejbcaHttpsClient


import (
	"crypto/tls"
	"crypto/x509"
//	"io"
	"net/http"
	"os"
	"time"
	"log"

	"github.com/tseiman/embed-cert-manager/config"
)


// func newMTLSClient(clientCertFile, clientKeyFile, serverCAFile, serverName string) (*http.Client, error) {

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


/*
func main() {
	// Beispiel: EJBCA host
	baseURL := "https://pki.tsei.mdn:8443"

	// Pfade anpassen
	clientCert := "/etc/ejbca-rest/client.crt"
	clientKey := "/etc/ejbca-rest/client.key"
	serverCA := "/etc/ejbca-rest/server-ca.crt"

	// serverName muss zum Zertifikat passen (CN/SAN des EJBCA-Servers)
	serverName := "pki.tsei.mdn"

	c, err := newMTLSClient(clientCert, clientKey, serverCA, serverName)
	if err != nil {
		panic(err)
	}

	// Erstmal nur “kann ich verbinden?” testen:
	// Nimm irgendeinen Endpoint, der bei dir existiert (später EJBCA REST).
	req, _ := http.NewRequest("GET", baseURL+"/", nil)
	resp, err := c.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println("HTTP status:", resp.Status)
	fmt.Println(string(body))
}

*/