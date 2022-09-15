package okta

import (
	"net/http"
	"net/url"

	"github.com/mwlng/go-okta/pkg/mfa"
)

type OktaClient struct {
	AppPath   string
	BaseURL   *url.URL
	CookieJar http.CookieJar
	MFAConfig *mfa.Config
	Username  string
	UserAuth  *OktaUserAuthn
}

/*type OktaCreds struct {
	Username string
	Password string
	//OktaAppLink string
}*/

type OktaCookies struct {
	Session     string
	DeviceToken string
}

// http://developer.okta.com/docs/api/resources/authn.html
type OktaUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type OktaStateToken struct {
	StateToken string `json:"stateToken"`
	PassCode   string `json:"passCode"`
}

type OktaUserAuthn struct {
	Embedded     OktaUserAuthnEmbedded `json:"_embedded"`
	FactorResult string                `json:"factorResult"`
	ExpiresAt    string                `json:"expiresAt"`
	SessionToken string                `json:"sessionToken"`
	StateToken   string                `json:"stateToken"`
	Status       string                `json:"status"`
}

type OktaUserAuthnEmbedded struct {
	Factors []OktaUserAuthnFactor `json:"factors"`
	Factor  OktaUserAuthnFactor   `json:"factor"`
}

type OktaUserAuthnFactor struct {
	Embedded   OktaUserAuthnFactorEmbedded `json:"_embedded"`
	FactorType string                      `json:"factorType"`
	Id         string                      `json:"id"`
	Provider   string                      `json:"provider"`
	Profile    OktaUserAuthnFactorProfile  `json:"profile"`
}

type OktaUserAuthnFactorProfile struct {
	AppId        string `json:"appId"`
	CredentialId string `json:"credentialId"`
	Version      string `json:"version"`
}

type OktaUserAuthnFactorEmbedded struct {
	Challenge    OktaUserAuthnFactorEmbeddedChallenge    `json:"challenge"`
	Verification OktaUserAuthnFactorEmbeddedVerification `json:"verification"`
}

type OktaUserAuthnFactorEmbeddedChallenge struct {
	Challenge       string `json:"challenge"`
	Nonce           string `json:"nonce"`
	TimeoutSeconnds int    `json:"timeoutSeconds"`
}

type OktaUserAuthnFactorEmbeddedVerification struct {
	FactorResult string                                       `json:"factorResult"`
	Host         string                                       `json:"host"`
	Links        OktaUserAuthnFactorEmbeddedVerificationLinks `json:"_links"`
	Signature    string                                       `json:"signature"`
}

type OktaUserAuthnFactorEmbeddedVerificationLinks struct {
	Complete OktaUserAuthnFactorEmbeddedVerificationLinksComplete `json:"complete"`
}

type OktaUserAuthnFactorEmbeddedVerificationLinksComplete struct {
	Href string `json:"href"`
}

///
type OktaLoginFormData struct {
	Username string           `json:"username"`
	Password string           `jon:"password"`
	Options  OktaLoginOptions `json:"options,omitempty"`
}

type OktaLoginOptions struct {
	WarnBeforePasswordExpired bool `json:"warnBeforePasswordExpired"`
	MultiOptionalFactorEnroll bool `json:"multiOptionalFactorEnroll"`
}
