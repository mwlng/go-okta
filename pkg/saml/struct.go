package saml

import "encoding/xml"

type SAMLAssertion struct {
	Resp    Response
	RawData []byte
}

type Response struct {
	Assertion    Assertion `xml:"Assertion"`
	Destination  string    `xml:"Destination,attr"`
	ID           string    `xml:"ID,attr"`
	InResponseTo string    `xml:"InResponseTo,attr"`
	IssueInstant string    `xml:"IssueInstant,attr"`
	SAML         string    `xml:"xmlns:saml,attr"`
	SAMLP        string    `xml:"xmlns:samlp,attr"`
	SAMLSIG      string    `xml:"xmlns:samlsig,attr"`
	Status       Status    `xml:"Status"`
	Version      string    `xml:"Version,attr"`
	XMLName      xml.Name

	originalString string
}

type Assertion struct {
	AttributeStatement AttributeStatement
	Conditions         Conditions
	ID                 string `xml:"ID,attr"`
	IssueInstant       string `xml:"IssueInstant,attr"`
	SAML               string `xml:"saml,attr"`
	Subject            Subject
	Version            string `xml:"Version,attr"`
	XS                 string `xml:"xmlns:xs,attr"`
	XSI                string `xml:"xmlns:xsi,attr"`
	XMLName            xml.Name
}

type AttributeStatement struct {
	Attributes []Attribute `xml:"Attribute"`
	XMLName    xml.Name
}

type Attribute struct {
	AttributeValues []AttributeValue `xml:"AttributeValue"`
	FriendlyName    string           `xml:",attr"`
	Name            string           `xml:",attr"`
	NameFormat      string           `xml:",attr"`
	XMLName         xml.Name
}

type AttributeValue struct {
	Type    string `xml:"xsi:type,attr"`
	Value   string `xml:",innerxml"`
	XMLName xml.Name
}

type Conditions struct {
	NotBefore    string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	XMLName      xml.Name
}

type Subject struct {
	NameID              NameID
	SubjectConfirmation SubjectConfirmation
	XMLName             xml.Name
}

type NameID struct {
	Format  string `xml:",attr"`
	Value   string `xml:",innerxml"`
	XMLName xml.Name
}

type SubjectConfirmation struct {
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
	XMLName                 xml.Name
}

type SubjectConfirmationData struct {
	InResponseTo string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

type Status struct {
	StatusCode StatusCode `xml:"StatusCode"`
	XMLName    xml.Name
}

type StatusCode struct {
	Value   string `xml:",attr"`
	XMLName xml.Name
}
