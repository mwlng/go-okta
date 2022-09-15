package mfa

type Config struct {
	Provider   string // Which MFA provider to use when presented with an MFA challenge
	FactorType string // Which of the factor types of the MFA provider to use
	Device     string // MFA device
}
