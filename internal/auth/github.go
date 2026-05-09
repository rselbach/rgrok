package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	GitHubAuthorizeURL  = "https://github.com/login/oauth/authorize"
	GitHubDeviceCodeURL = "https://github.com/login/device/code"
	GitHubTokenURL      = "https://github.com/login/oauth/access_token"
	GitHubUserURL       = "https://api.github.com/user"
)

type GitHubClient struct {
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

type GitHubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type DeviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func (c GitHubClient) StartDeviceFlow(ctx context.Context) (DeviceCode, error) {
	if c.ClientID == "" {
		return DeviceCode{}, errors.New("github client id is required")
	}

	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("scope", "read:user")

	var out DeviceCode
	if err := c.postForm(ctx, GitHubDeviceCodeURL, form, &out); err != nil {
		return DeviceCode{}, err
	}
	if out.Interval <= 0 {
		out.Interval = 5
	}
	return out, nil
}

func (c GitHubClient) PollDeviceFlow(ctx context.Context, device DeviceCode) (TokenResponse, error) {
	deadline := time.Now().Add(time.Duration(device.ExpiresIn) * time.Second)
	interval := time.Duration(device.Interval) * time.Second

	for {
		if time.Now().After(deadline) {
			return TokenResponse{}, errors.New("device code expired")
		}

		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return TokenResponse{}, ctx.Err()
		}

		form := url.Values{}
		form.Set("client_id", c.ClientID)
		if c.ClientSecret != "" {
			form.Set("client_secret", c.ClientSecret)
		}
		form.Set("device_code", device.DeviceCode)
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

		var token TokenResponse
		if err := c.postForm(ctx, GitHubTokenURL, form, &token); err != nil {
			return TokenResponse{}, err
		}
		switch token.Error {
		case "":
			if token.AccessToken == "" {
				return TokenResponse{}, errors.New("github returned an empty access token")
			}
			return token, nil
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		default:
			if token.Description != "" {
				return TokenResponse{}, fmt.Errorf("%s: %s", token.Error, token.Description)
			}
			return TokenResponse{}, errors.New(token.Error)
		}
	}
}

func (c GitHubClient) PollDeviceFlowOnce(ctx context.Context, deviceCode string) (TokenResponse, error) {
	if c.ClientID == "" {
		return TokenResponse{}, errors.New("github client id is required")
	}
	if deviceCode == "" {
		return TokenResponse{}, errors.New("device code is required")
	}

	form := url.Values{}
	form.Set("client_id", c.ClientID)
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	form.Set("device_code", deviceCode)
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	var token TokenResponse
	if err := c.postForm(ctx, GitHubTokenURL, form, &token); err != nil {
		return TokenResponse{}, err
	}
	return token, nil
}

func (c GitHubClient) ExchangeWebCode(ctx context.Context, code, redirectURI string) (TokenResponse, error) {
	if c.ClientID == "" || c.ClientSecret == "" {
		return TokenResponse{}, errors.New("github client id and secret are required")
	}

	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	form.Set("code", code)
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}

	var token TokenResponse
	if err := c.postForm(ctx, GitHubTokenURL, form, &token); err != nil {
		return TokenResponse{}, err
	}
	if token.Error != "" {
		if token.Description != "" {
			return TokenResponse{}, fmt.Errorf("%s: %s", token.Error, token.Description)
		}
		return TokenResponse{}, errors.New(token.Error)
	}
	if token.AccessToken == "" {
		return TokenResponse{}, errors.New("github returned an empty access token")
	}
	return token, nil
}

func (c GitHubClient) User(ctx context.Context, token string) (GitHubUser, error) {
	if token == "" {
		return GitHubUser{}, errors.New("github access token is required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, GitHubUserURL, nil)
	if err != nil {
		return GitHubUser{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "rgrok")

	resp, err := c.client().Do(req)
	if err != nil {
		return GitHubUser{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return GitHubUser{}, fmt.Errorf("github user request failed: %s: %s", resp.Status, bytes.TrimSpace(body))
	}

	var user GitHubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return GitHubUser{}, err
	}
	if user.Login == "" {
		return GitHubUser{}, errors.New("github returned an empty login")
	}
	return user, nil
}

func (c GitHubClient) AuthorizeURL(state, redirectURI string) string {
	q := url.Values{}
	q.Set("client_id", c.ClientID)
	q.Set("scope", "read:user")
	q.Set("state", state)
	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}
	return GitHubAuthorizeURL + "?" + q.Encode()
}

func (c GitHubClient) postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Set("User-Agent", "rgrok")

	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("github request failed: %s: %s", resp.Status, bytes.TrimSpace(body))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c GitHubClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}
