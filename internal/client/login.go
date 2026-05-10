package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rselbach/rgrok/internal/protocol"
)

type LoginConfig struct {
	ServerBaseURL string
	HTTPClient    *http.Client
}

func StartLogin(ctx context.Context, cfg LoginConfig) (protocol.DeviceStartResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.ServerBaseURL, "/")+"/api/login/device/start", nil)
	if err != nil {
		return protocol.DeviceStartResponse{}, err
	}
	resp, err := loginHTTPClient(cfg).Do(req)
	if err != nil {
		return protocol.DeviceStartResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.DeviceStartResponse{}, fmt.Errorf("login start failed: %s", resp.Status)
	}
	var out protocol.DeviceStartResponse
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

func PollLogin(ctx context.Context, cfg LoginConfig, id string, interval int) (FileConfig, error) {
	if interval <= 0 {
		interval = 5
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	fmt.Fprintln(os.Stderr, "Waiting for GitHub authorization...")

	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return FileConfig{}, ctx.Err()
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.ServerBaseURL, "/")+"/api/login/device/poll?id="+id, nil)
		if err != nil {
			return FileConfig{}, err
		}
		resp, err := loginHTTPClient(cfg).Do(req)
		if err != nil {
			return FileConfig{}, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return FileConfig{}, fmt.Errorf("login poll failed: %s", resp.Status)
		}
		var poll protocol.DevicePollResponse
		err = json.NewDecoder(resp.Body).Decode(&poll)
		_ = resp.Body.Close()
		if err != nil {
			return FileConfig{}, err
		}

		if poll.Status != "pending" {
			fmt.Fprintf(os.Stderr, "Server poll status: %s\n", poll.Status)
		}
		switch poll.Status {
		case "pending":
			continue
		case "complete":
			if poll.Token == "" {
				return FileConfig{}, errors.New("server returned an empty rgrok token")
			}
			return FileConfig{Token: poll.Token, Login: poll.Login, ServerBaseURL: cfg.ServerBaseURL}, nil
		case "denied":
			return FileConfig{}, fmt.Errorf("GitHub user %s is not whitelisted", poll.Login)
		case "expired":
			return FileConfig{}, errors.New("login code expired")
		case "error":
			if poll.Error != "" {
				return FileConfig{}, errors.New(poll.Error)
			}
			return FileConfig{}, errors.New("login failed")
		default:
			return FileConfig{}, fmt.Errorf("unexpected login status %q", poll.Status)
		}
	}
}

func loginHTTPClient(cfg LoginConfig) *http.Client {
	if cfg.HTTPClient != nil {
		return cfg.HTTPClient
	}
	return http.DefaultClient
}
