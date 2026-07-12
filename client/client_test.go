package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/rgrok/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestStartReturnsApplicationTunnel(t *testing.T) {
	r := require.New(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		r.NoError(err)
		defer func() { r.NoError(conn.Close()) }()

		var registration protocol.Message
		r.NoError(conn.ReadJSON(&registration))
		r.Empty(registration.AuthToken)
		r.Equal("0123456789abcdef0123456789abcdef", registration.ApplicationProfileID)
		r.Equal("installation-1", registration.InstanceID)

		challenge := "greendale-challenge"
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:      protocol.TypeApplicationChallenge,
			Challenge: challenge,
		}))
		var response protocol.Message
		r.NoError(conn.ReadJSON(&response))
		payload := protocol.ApplicationChallengePayload(registration.ApplicationProfileID, registration.InstanceID, challenge)
		r.True(ed25519.Verify(publicKey, payload, response.Signature))
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:      protocol.TypeTunnelRegistered,
			TunnelID:  "human-timeline-club",
			PublicURL: "https://human-timeline-club.example.com",
		}))

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tun, err := Start(ctx, Config{
		ServerURL:             wsURL,
		ApplicationProfileID:  "0123456789abcdef0123456789abcdef",
		InstanceID:            "installation-1",
		ApplicationPrivateKey: privateKey,
		LocalPort:             3000,
	})
	r.NoError(err)
	r.Equal("human-timeline-club", tun.ID)
	r.NoError(tun.Close())
}

func TestStartReturnsRegisteredTunnel(t *testing.T) {
	r := require.New(t)

	upgrader := websocket.Upgrader{}
	registered := make(chan protocol.Message, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		r.NoError(err)
		defer conn.Close()

		var msg protocol.Message
		r.NoError(conn.ReadJSON(&msg))
		registered <- msg
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:      protocol.TypeTunnelRegistered,
			TunnelID:  "demo",
			PublicURL: "https://demo.example.com",
		}))

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tun, err := Start(ctx, Config{
		ServerURL: wsURL,
		Token:     "secret-token",
		Name:      "demo",
		LocalPort: 3000,
	})
	r.NoError(err)
	r.Equal("demo", tun.ID)
	r.Equal("https://demo.example.com", tun.PublicURL)

	msg := <-registered
	r.Equal(protocol.TypeRegisterTunnel, msg.Type)
	r.Equal("secret-token", msg.AuthToken)
	r.Equal("demo", msg.RequestedID)
	r.Equal(3000, msg.LocalPort)

	r.NoError(tun.Close())
	r.NoError(tun.Close())
}

func TestStartUsesRGROKAPITokenEnv(t *testing.T) {
	r := require.New(t)
	t.Setenv("RGROK_API_TOKEN", "env-token")

	upgrader := websocket.Upgrader{}
	registered := make(chan protocol.Message, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		r.NoError(err)
		defer conn.Close()

		var msg protocol.Message
		r.NoError(conn.ReadJSON(&msg))
		registered <- msg
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:      protocol.TypeTunnelRegistered,
			TunnelID:  "demo",
			PublicURL: "https://demo.example.com",
		}))
		<-req.Context().Done()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tun, err := Start(ctx, Config{
		ServerURL: wsURL,
		LocalPort: 3000,
	})
	r.NoError(err)
	defer tun.Close()

	msg := <-registered
	r.Equal("env-token", msg.AuthToken)
}

func TestConnectURLFromBase(t *testing.T) {
	tests := map[string]string{
		"https://rgrok.example.com":  "wss://rgrok.example.com/api/connect",
		"http://localhost:7000/":     "ws://localhost:7000/api/connect",
		"rgrok.rselbach.com":         "wss://rgrok.rselbach.com/api/connect",
		"https://example.com/root//": "wss://example.com/root/api/connect",
	}

	for base, want := range tests {
		t.Run(base, func(t *testing.T) {
			require.Equal(t, want, ConnectURLFromBase(base))
		})
	}
}
