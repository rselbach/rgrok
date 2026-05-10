package protocol

type DeviceStartResponse struct {
	ID              string `json:"id"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	PollSecret      string `json:"poll_secret,omitempty"`
}

type DevicePollResponse struct {
	Status string `json:"status"`
	Token  string `json:"token,omitempty"`
	Login  string `json:"login,omitempty"`
	Error  string `json:"error,omitempty"`
}
