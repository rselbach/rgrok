package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStartDeviceFlowRequiresClientID(t *testing.T) {
	r := require.New(t)
	c := GitHubClient{}
	_, err := c.StartDeviceFlow(context.Background())
	r.Error(err)
	r.Contains(err.Error(), "client id is required")
}

func TestPollDeviceFlowRequiresClientID(t *testing.T) {
	r := require.New(t)
	c := GitHubClient{}
	_, err := c.PollDeviceFlow(context.Background(), DeviceCode{ExpiresIn: 900})
	r.Error(err)
	r.Contains(err.Error(), "client id is required")
}

func TestPollDeviceFlowOnceRequiresClientID(t *testing.T) {
	r := require.New(t)
	c := GitHubClient{}
	_, err := c.PollDeviceFlowOnce(context.Background(), "code")
	r.Error(err)
	r.Contains(err.Error(), "client id is required")
}

func TestExchangeWebCodeRequiresCredentials(t *testing.T) {
	r := require.New(t)
	c := GitHubClient{ClientID: "id"}
	_, err := c.ExchangeWebCode(context.Background(), "code", "")
	r.Error(err)
	r.Contains(err.Error(), "client id and secret are required")
}

func TestUserRequiresToken(t *testing.T) {
	r := require.New(t)
	c := GitHubClient{}
	_, err := c.User(context.Background(), "")
	r.Error(err)
	r.Contains(err.Error(), "token is required")
}

func TestStartDeviceFlow(t *testing.T) {
	r := require.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal(http.MethodPost, req.Method)
		r.Equal("/device/code", req.URL.Path)

		err := req.ParseForm()
		r.NoError(err)
		r.Equal("test-client-id", req.PostForm.Get("client_id"))
		r.Equal("read:user", req.PostForm.Get("scope"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DeviceCode{
			DeviceCode:      "dc123",
			UserCode:        "uc456",
			VerificationURI: "https://github.com/login/device",
			ExpiresIn:       900,
			Interval:        5,
		})
	}))
	defer server.Close()

	c := GitHubClient{
		ClientID:      "test-client-id",
		HTTPClient:    server.Client(),
		deviceCodeURL: server.URL + "/device/code",
		tokenURL:      server.URL + "/access_token",
	}

	device, err := c.StartDeviceFlow(context.Background())
	r.NoError(err)
	r.Equal("dc123", device.DeviceCode)
	r.Equal("uc456", device.UserCode)
	r.Equal("https://github.com/login/device", device.VerificationURI)
	r.Equal(5, device.Interval)
}

func TestPollDeviceFlowOnce(t *testing.T) {
	r := require.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal(http.MethodPost, req.Method)
		r.Equal("/access_token", req.URL.Path)

		err := req.ParseForm()
		r.NoError(err)
		r.Equal("test-client-id", req.PostForm.Get("client_id"))
		r.Equal("dc123", req.PostForm.Get("device_code"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "token123",
			TokenType:   "bearer",
		})
	}))
	defer server.Close()

	c := GitHubClient{
		ClientID:   "test-client-id",
		HTTPClient: server.Client(),
		tokenURL:   server.URL + "/access_token",
	}

	token, err := c.PollDeviceFlowOnce(context.Background(), "dc123")
	r.NoError(err)
	r.Equal("token123", token.AccessToken)
}

func TestPollDeviceFlowOnceEmptyToken(t *testing.T) {
	r := require.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			Error: "authorization_pending",
		})
	}))
	defer server.Close()

	c := GitHubClient{
		ClientID:   "test-client-id",
		HTTPClient: server.Client(),
		tokenURL:   server.URL + "/access_token",
	}

	token, err := c.PollDeviceFlowOnce(context.Background(), "dc123")
	r.NoError(err)
	r.Equal("authorization_pending", token.Error)
}

func TestExchangeWebCode(t *testing.T) {
	r := require.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal(http.MethodPost, req.Method)
		r.Equal("/access_token", req.URL.Path)

		err := req.ParseForm()
		r.NoError(err)
		r.Equal("test-client-id", req.PostForm.Get("client_id"))
		r.Equal("test-secret", req.PostForm.Get("client_secret"))
		r.Equal("authcode", req.PostForm.Get("code"))
		r.Equal("https://example.com/callback", req.PostForm.Get("redirect_uri"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "token123",
			TokenType:   "bearer",
		})
	}))
	defer server.Close()

	c := GitHubClient{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		HTTPClient:   server.Client(),
		tokenURL:     server.URL + "/access_token",
	}

	token, err := c.ExchangeWebCode(context.Background(), "authcode", "https://example.com/callback")
	r.NoError(err)
	r.Equal("token123", token.AccessToken)
}

func TestUser(t *testing.T) {
	r := require.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal(http.MethodGet, req.Method)
		r.Equal("/user", req.URL.Path)
		r.Equal("Bearer token123", req.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(GitHubUser{
			ID:        42,
			Login:     "troybarnes",
			Name:      "Troy Barnes",
			AvatarURL: "https://example.com/avatar.png",
		})
	}))
	defer server.Close()

	c := GitHubClient{
		HTTPClient: server.Client(),
		userURL:    server.URL + "/user",
	}

	user, err := c.User(context.Background(), "token123")
	r.NoError(err)
	r.Equal("troybarnes", user.Login)
	r.Equal("Troy Barnes", user.Name)
}

func TestUserEmptyLogin(t *testing.T) {
	r := require.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(GitHubUser{
			ID:    42,
			Login: "",
		})
	}))
	defer server.Close()

	c := GitHubClient{
		HTTPClient: server.Client(),
		userURL:    server.URL + "/user",
	}

	_, err := c.User(context.Background(), "token123")
	r.Error(err)
	r.Contains(err.Error(), "empty login")
}

func TestAuthorizeURL(t *testing.T) {
	r := require.New(t)
	c := GitHubClient{ClientID: "test-id"}
	url := c.AuthorizeURL("state123", "https://example.com/callback")
	r.True(strings.HasPrefix(url, GitHubAuthorizeURL))
	r.Contains(url, "client_id=test-id")
	r.Contains(url, "state=state123")
	r.Contains(url, "redirect_uri=https%3A%2F%2Fexample.com%2Fcallback")
}

func TestAuthorizeURLOmitsEmptyRedirect(t *testing.T) {
	r := require.New(t)
	c := GitHubClient{ClientID: "test-id"}
	url := c.AuthorizeURL("state123", "")
	r.NotContains(url, "redirect_uri")
}
