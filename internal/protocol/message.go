package protocol

import "net/http"

const MaxBodyBytesDefault = 32 << 20

const (
	TypeRegisterTunnel   = "register_tunnel"
	TypeTunnelRegistered = "tunnel_registered"
	TypeRequest          = "request"
	TypeResponse         = "response"
	TypePing             = "ping"
	TypePong             = "pong"
)

type Message struct {
	Type string `json:"type"`

	TunnelID  string `json:"tunnel_id,omitempty"`
	PublicURL string `json:"public_url,omitempty"`

	RequestedID string `json:"requested_id,omitempty"`
	AuthToken   string `json:"auth_token,omitempty"`
	LocalPort   int    `json:"local_port,omitempty"`

	StreamID uint64      `json:"stream_id,omitempty"`
	Method   string      `json:"method,omitempty"`
	Path     string      `json:"path,omitempty"`
	Host     string      `json:"host,omitempty"`
	Scheme   string      `json:"scheme,omitempty"`
	Header   http.Header `json:"header,omitempty"`
	Body     []byte      `json:"body,omitempty"`

	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}
