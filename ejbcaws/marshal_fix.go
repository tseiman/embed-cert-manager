package ejbcaws

import "encoding/xml"

// Fix for EJBCA: elementFormDefault="unqualified" + expected arg order arg1, arg0.
// We emit a prefixed wrapper (no default xmlns), and unqualified child elements.
func (t *FindCerts) MarshalXML(enc *xml.Encoder, _ xml.StartElement) error {
	start := xml.StartElement{
		Name: xml.Name{Local: "tns:findCerts"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns:tns"}, Value: "http://ws.protocol.core.ejbca.org/"},
		},
	}

	// <tns:findCerts ...>
	if err := enc.EncodeToken(start); err != nil {
		return err
	}

	// IMPORTANT: order: arg1 then arg0
	if err := enc.EncodeElement(t.Arg1, xml.StartElement{Name: xml.Name{Local: "arg1"}}); err != nil {
		return err
	}
	if err := enc.EncodeElement(t.Arg0, xml.StartElement{Name: xml.Name{Local: "arg0"}}); err != nil {
		return err
	}

	// </tns:findCerts>
	if err := enc.EncodeToken(start.End()); err != nil {
		return err
	}
	return enc.Flush()
}
