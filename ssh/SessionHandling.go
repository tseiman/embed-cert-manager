package ssh

import (
	"log"
	"bytes"
	"crypto/x509"
	"encoding/pem"
)


type SessionReturn struct {
	StdOut 		bytes.Buffer
	StdErr 		bytes.Buffer
	CertCSR		string
}


var csrTypes = map[string]bool{
	"CERTIFICATE REQUEST":      true,
	"NEW CERTIFICATE REQUEST":  true, // kommt bei manchen OpenSSL-Ausgaben vor
}


func (s *SessionReturn) ParseCSRFromString() *string {
	rest := s.StdOut.Bytes()

	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			log.Println("no more PEM blocks found in stdout")
			break
		}

		if !csrTypes[block.Type] {
			log.Printf("ignoring PEM block type %q\n", block.Type)
			continue
		}

		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			log.Printf("invalid CSR in PEM block %q: %v\n", block.Type, err)
			continue
		}

		if err := csr.CheckSignature(); err != nil {
			log.Printf("CSR signature invalid: %v\n", err)
			continue
		}

		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  block.Type,
			Bytes: block.Bytes,
		})
		if pemBytes == nil {
			log.Println("failed to encode CSR PEM")
			return nil
		}

		csrStr := string(pemBytes)

		// Ergebnis im Struct ablegen
		s.CertCSR = csrStr

		// und gleichzeitig zurückgeben
		return &s.CertCSR
	}

	log.Println("no valid CSR found in stdout")
	return nil
}
