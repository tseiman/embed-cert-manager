package ejbcaws

/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 *  Fix code for the auto generated WSDL functions
 * 
 * */


import (
	"encoding/xml"
	"io"
)

// Accept <return>...</return> elements and extract certificateData into Certificate.CertificateData ([]byte).
func (r *FindCertsResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	r.XMLName = start.Name
	r.Return_ = nil

	for {
		tok, err := d.Token()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "return" {
				var tmp struct {
					CertificateData string `xml:"certificateData"`
				}

				if err := d.DecodeElement(&tmp, &t); err != nil {
					return err
				}

				r.Return_ = append(r.Return_, &Certificate{
					CertificateData: []byte(tmp.CertificateData), // <-- FIX
				})
			} else {
				if err := d.Skip(); err != nil {
					return err
				}
			}

		case xml.EndElement:
			if t.Name == start.Name {
				return nil
			}
		}
	}
}
