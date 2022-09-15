package okta

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/mwlng/go-okta/pkg/mfa"
	"github.com/mwlng/go-okta/pkg/saml"
	"github.com/mwlng/go-okta/pkg/utils"

	log "github.com/sirupsen/logrus"
)

const (
	Timeout = time.Duration(60 * time.Second)
)

// Set debug log level
//func init() {
//	log.SetLevel(log.DebugLevel)
//}

func NewClientWithCookies(username, oktaAppUrl, sessionCookie string, mfaConfig *mfa.Config) (*OktaClient, error) {
	var cookies OktaCookies
	cookies.Session = sessionCookie

	return NewClient(username, oktaAppUrl, cookies, mfaConfig)
}

func NewClient(username, oktaAppUrl string, cookies OktaCookies, mfaConfig *mfa.Config) (*OktaClient, error) {
	appUrl, err := url.Parse(oktaAppUrl)
	if err != nil {
		return nil, err
	}

	oktaBaseUrl, _ := url.Parse(fmt.Sprintf("%s://%s", appUrl.Scheme, appUrl.Host))

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}

	if cookies.Session != "" {
		jar.SetCookies(appUrl, []*http.Cookie{
			{
				Name:  "sid",
				Value: cookies.Session,
			},
		})
	}
	if cookies.DeviceToken != "" {
		jar.SetCookies(appUrl, []*http.Cookie{
			{
				Name:  "DT",
				Value: cookies.DeviceToken,
			},
		})
	}

	return &OktaClient{
		Username:  username,
		CookieJar: jar,
		BaseURL:   oktaBaseUrl,
		MFAConfig: mfaConfig,
		AppPath:   strings.TrimLeft(appUrl.Path, "/"),
	}, nil
}

func (oc *OktaClient) AuthenticateUser(password string) error {
	var oktaUserAuthn OktaUserAuthn

	user := OktaUser{
		Username: oc.Username,
		Password: password,
	}

	payload, err := json.Marshal(user)
	if err != nil {
		return err
	}

	log.Debug("Step 1: Basic authentication")
	err = oc.get("POST", "api/v1/authn", payload, &oktaUserAuthn, "json")
	if err != nil {
		return fmt.Errorf("failed to basic authenticate with okta: %#v", err)
	}

	oc.UserAuth = &oktaUserAuthn
	log.Debug("Step 2: Challenge MFA if required")
	if oc.UserAuth.Status == "MFA_REQUIRED" {
		log.Info("Requesting MFA. Please complete two-factor authentication with your second device")
		if err = oc.challengeMFA(); err != nil {
			return err
		}
	}

	if oc.UserAuth.SessionToken == "" {
		return fmt.Errorf("authentication failed for %s", oc.Username)
	}

	return nil
}

func (oc *OktaClient) challengeMFA() (err error) {
	var oktaFactorProvider string
	var oktaFactorId string
	var payload []byte
	var oktaFactorType string

	factor, err := oc.selectMFADevice()
	if err != nil {
		log.Debug("Failed to select MFA device")
		return
	}

	oktaFactorProvider = factor.Provider
	if oktaFactorProvider == "" {
		return
	}

	oktaFactorId, err = GetFactorId(factor)
	if err != nil {
		return
	}

	oktaFactorType = factor.FactorType
	if oktaFactorId == "" {
		return
	}

	log.Debugf("Okta Factor Provider: %s", oktaFactorProvider)
	log.Debugf("Okta Factor ID: %s", oktaFactorId)
	log.Debugf("Okta Factor Type: %s", oktaFactorType)

	payload, err = oc.preChallenge(oktaFactorId, oktaFactorType)
	if err != nil {
		return
	}

	err = oc.get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify?rememberDevice=true",
		payload, &oc.UserAuth, "json",
	)
	if err != nil {
		return
	}

	// Handle Push Notification
	err = oc.postChallenge(payload, oktaFactorProvider, oktaFactorId)
	if err != nil {
		return err
	}
	return
}

func (oc *OktaClient) selectMFADevice() (*OktaUserAuthnFactor, error) {
	factors := oc.UserAuth.Embedded.Factors
	if len(factors) == 0 {
		return nil, errors.New("no available mfa factors")
	} else if len(factors) == 1 {
		return &factors[0], nil
	}

	factor, err := selectMFADeviceFromConfig(oc)
	if err != nil {
		return nil, err
	}

	if factor != nil {
		return factor, nil
	}

	log.Info("Select a MFA from the following list")
	for i, f := range factors {
		log.Infof("%d: %s (%s)", i, f.Provider, f.FactorType)
	}

	i, err := utils.Prompt("Select MFA method", false)
	if i == "" {
		return nil, errors.New("invalid selection - Please use an option that is listed")
	}
	if err != nil {
		return nil, err
	}
	factorIdx, err := strconv.Atoi(i)
	if err != nil {
		return nil, err
	}
	if factorIdx > (len(factors) - 1) {
		return nil, errors.New("invalid selection - Please use an option that is listed")
	}
	return &factors[factorIdx], nil
}

func selectMFADeviceFromConfig(o *OktaClient) (*OktaUserAuthnFactor, error) {
	log.Debugf("MFA Config: %v\n", o.MFAConfig)
	if o.MFAConfig.Provider == "" || o.MFAConfig.FactorType == "" {
		return nil, nil
	}

	for _, f := range o.UserAuth.Embedded.Factors {
		log.Debugf("%v\n", f)
		if strings.EqualFold(f.Provider, o.MFAConfig.Provider) && strings.EqualFold(f.FactorType, o.MFAConfig.FactorType) {
			log.Debugf("Using matching factor \"%v %v\" from config\n", f.Provider, f.FactorType)
			return &f, nil
		}
	}

	return nil, fmt.Errorf("failed to select MFA device with Provider = \"%s\", FactorType = \"%s\"", o.MFAConfig.Provider, o.MFAConfig.FactorType)
}

func (oc *OktaClient) preChallenge(oktaFactorId, oktaFactorType string) ([]byte, error) {
	var mfaCode string
	var err error

	// Software and Hardware based OTP Tokens
	if strings.Contains(oktaFactorType, "token") {
		log.Debug("Token MFA")
		mfaCode, err = utils.Prompt("Enter MFA Code", false)
		if err != nil {
			return nil, err
		}
	} else if strings.Contains(oktaFactorType, "sms") {
		log.Debug("SMS MFA")
		payload, err := json.Marshal(OktaStateToken{
			StateToken: oc.UserAuth.StateToken,
		})
		if err != nil {
			return nil, err
		}
		var sms interface{}
		log.Debug("Requesting SMS Code")
		err = oc.get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify",
			payload, &sms, "json",
		)
		if err != nil {
			return nil, err
		}
		mfaCode, err = utils.Prompt("Enter MFA Code from SMS", false)
		if err != nil {
			return nil, err
		}
	}

	payload, err := json.Marshal(OktaStateToken{
		StateToken: oc.UserAuth.StateToken,
		PassCode:   mfaCode,
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func (oc *OktaClient) postChallenge(payload []byte, oktaFactorProvider string, oktaFactorId string) error {
	// Initiate Push Notification
	if oc.UserAuth.Status == "MFA_CHALLENGE" {
		f := oc.UserAuth.Embedded.Factor
		errChan := make(chan error, 1)

		if oktaFactorProvider == "DUO" {
			// Contact the Duo to initiate Push notification
			if f.Embedded.Verification.Host != "" {
				duoClient := &mfa.DuoClient{
					Host:       f.Embedded.Verification.Host,
					Signature:  f.Embedded.Verification.Signature,
					Callback:   f.Embedded.Verification.Links.Complete.Href,
					Device:     oc.MFAConfig.Device,
					StateToken: oc.UserAuth.StateToken,
					FactorID:   f.Id,
				}

				log.Debugf("Host:%s\nSignature:%s\nStateToken:%s\n",
					f.Embedded.Verification.Host, f.Embedded.Verification.Signature,
					oc.UserAuth.StateToken)

				go func() {
					log.Debug("challenge u2f")
					log.Info("Sending Push Notification...")
					err := duoClient.ChallengeU2f(f.Embedded.Verification.Host)
					if err != nil {
						errChan <- err
					}
				}()
			}
		} else if oktaFactorProvider == "FIDO" {
			f := oc.UserAuth.Embedded.Factor

			log.Debug("FIDO WebAuthn Details:")
			log.Debug("  ChallengeNonce: ", f.Embedded.Challenge.Challenge)
			log.Debug("  CredentialId: ", f.Profile.CredentialId)
			log.Debug("  StateToken: ", oc.UserAuth.StateToken)

			fidoClient, err := mfa.NewFidoClient(f.Embedded.Challenge.Challenge,
				"None",
				f.Profile.CredentialId,
				oc.UserAuth.StateToken)
			if err != nil {
				return err
			}

			signedAssertion, err := fidoClient.ChallengeU2f()
			if err != nil {
				return err
			}

			// re-assign the payload to provide U2F responses.
			payload, err = json.Marshal(signedAssertion)
			if err != nil {
				return err
			}
		}
		// Poll Okta until authentication has been completed
		for oc.UserAuth.Status != "SUCCESS" {
			select {
			case duoErr := <-errChan:
				log.Printf("Err: %s", duoErr)
				if duoErr != nil {
					return fmt.Errorf("failed Duo challenge. Err: %s", duoErr)
				}
			default:
				err := oc.get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify",
					payload, &oc.UserAuth, "json",
				)
				if err != nil {
					return fmt.Errorf("failed authn verification for okta. Err: %s", err)
				}
			}
			time.Sleep(2 * time.Second)
		}
	}

	return nil
}

func (oc *OktaClient) get(method string, path string, data []byte, recv interface{}, format string) (err error) {
	var res *http.Response
	var header http.Header
	var client http.Client

	url, err := url.Parse(fmt.Sprintf("%s/%s", oc.BaseURL, path))
	if err != nil {
		return err
	}

	if format == "json" {
		header = http.Header{
			"Accept":        []string{"application/json"},
			"Content-Type":  []string{"application/json"},
			"Cache-Control": []string{"no-cache"},
		}
	} else {
		// disable gzip encoding; it was causing spurious EOFs
		header = http.Header{
			"Accept-Encoding": []string{"identity"},
		}
	}

	transCfg := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: Timeout,
	}

	client = http.Client{
		Transport: transCfg,
		Timeout:   Timeout,
		Jar:       oc.CookieJar,
	}

	req := &http.Request{
		Method:        method,
		URL:           url,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          ioutil.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
	}

	if res, err = client.Do(req); err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s %v: %s", method, url, res.Status)
	} else if recv != nil {
		switch format {
		case "json":
			err = json.NewDecoder(res.Body).Decode(recv)
		default:
			var rawData []byte
			rawData, err = ioutil.ReadAll(res.Body)
			if err != nil {
				return
			}
			if err := ParseSAML(rawData, recv.(*saml.SAMLAssertion)); err != nil {
				fmt.Printf("%s\n", rawData)
				return fmt.Errorf("okta user %s does not have the app added to their account. Please contact your Okta admin to make sure things are configured properly", oc.Username)
			}
		}
	}

	return
}

func GetFactorId(f *OktaUserAuthnFactor) (id string, err error) {
	switch f.FactorType {
	case "web":
		id = f.Id
	case "token":
		if f.Provider == "SYMANTEC" {
			id = f.Id
		} else {
			err = fmt.Errorf("provider %s with factor token not supported", f.Provider)
		}
	case "token:software:totp":
		id = f.Id
	case "token:hardware":
		id = f.Id
	case "sms":
		id = f.Id
	case "u2f", "webauthn":
		id = f.Id
	case "push":
		if f.Provider == "OKTA" || f.Provider == "DUO" {
			id = f.Id
		} else {
			err = fmt.Errorf("provider %s with factor push not supported", f.Provider)
		}
	default:
		err = fmt.Errorf("factor %s not supported", f.FactorType)
	}
	return
}
