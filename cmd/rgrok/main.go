package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rselbach/rgrok/internal/client"
	"github.com/rselbach/rgrok/internal/protocol"
	"github.com/rselbach/rgrok/internal/server"
)

func main() {
	log := newLogger(false, "text")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:], log)
	case "login":
		err = runLogin(os.Args[2:], log)
	case "logout":
		err = runLogout()
	case "connect":
		err = runConnect(os.Args[2:], log)
	case "status":
		err = runStatus()
	case "-h", "--help", "help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runServer(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", ":7000", "HTTP listen address")
	domain := fs.String("domain", "localhost:7000", "public tunnel domain, without scheme")
	publicScheme := fs.String("scheme", "http", "public URL scheme")
	behindProxy := fs.Bool("behind-proxy", false, "server is behind a trusted reverse proxy")
	trustedProxyCIDRs := fs.String("trusted-proxy-cidrs", "127.0.0.0/8,::1/128", "comma-separated proxy CIDRs trusted for X-Forwarded-* when --behind-proxy is set")
	connectPath := fs.String("connect-path", "/api/connect", "WebSocket tunnel path")
	dataPath := fs.String("data", "rgrok.json", "path to persistent server data")
	githubClientID := fs.String("github-client-id", os.Getenv("RGROK_GITHUB_CLIENT_ID"), "GitHub OAuth app client ID")
	githubClientSecret := fs.String("github-client-secret", os.Getenv("RGROK_GITHUB_CLIENT_SECRET"), "GitHub OAuth app client secret")
	maxBody := fs.Int64("max-body", protocol.MaxBodyBytesDefault, "maximum request or response body bytes")
	maxTunnelsPerUser := fs.Int("max-tunnels-per-user", 0, "maximum tunnels per user (0 = default 5)")
	maxRequestsPerTunnel := fs.Int("max-requests-per-tunnel", 0, "maximum concurrent public requests per tunnel (0 = default 64)")
	showLogs := fs.Bool("logs", false, "show server logs")
	logFormat := fs.String("log-format", "text", "log format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	log = newLogger(*showLogs, *logFormat)

	s, err := server.New(server.Config{
		Addr:                 *addr,
		Domain:               *domain,
		PublicScheme:         *publicScheme,
		ConnectPath:          *connectPath,
		DataPath:             *dataPath,
		GitHubClientID:       *githubClientID,
		GitHubClientSecret:   *githubClientSecret,
		MaxBodyBytes:         *maxBody,
		MaxTunnelsPerUser:    *maxTunnelsPerUser,
		MaxRequestsPerTunnel: *maxRequestsPerTunnel,
		BehindProxy:          *behindProxy,
		TrustedProxyCIDRs:    strings.Split(*trustedProxyCIDRs, ","),
		Logger:               log,
	})
	if err != nil {
		return err
	}
	return s.Run()
}

func runLogin(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	serverBaseURL := fs.String("server", "https://rgrok.rselbach.com", "rgrok server base URL")
	showLogs := fs.Bool("logs", false, "show login logs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log = newLogger(*showLogs, "text")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	loginCfg := client.LoginConfig{ServerBaseURL: *serverBaseURL}
	device, err := client.StartLogin(ctx, loginCfg)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Open %s and enter code %s\n", device.VerificationURI, device.UserCode)
	cfg, err := client.PollLogin(ctx, loginCfg, device.ID, device.Interval)
	if err != nil {
		return err
	}

	if err := client.SaveFileConfig(cfg); err != nil {
		return err
	}

	path, _ := client.ConfigPath()
	log.Info("saved rgrok login", "path", path, "github_user", cfg.Login)
	fmt.Fprintf(os.Stdout, "Logged in as %s\n", cfg.Login)
	return nil
}

func runLogout() error {
	path, err := client.ConfigPath()
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}

	fmt.Fprintf(os.Stdout, "logged out, removed config at %s\n", path)
	return nil
}

func wsURLFromBase(base string) string {
	base = strings.TrimRight(base, "/")
	switch {
	case strings.HasPrefix(base, "https://"):
		return "wss://" + strings.TrimPrefix(base, "https://") + "/api/connect"
	case strings.HasPrefix(base, "http://"):
		return "ws://" + strings.TrimPrefix(base, "http://") + "/api/connect"
	default:
		return "wss://" + base + "/api/connect"
	}
}

func runConnect(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	serverURL := fs.String("server", "", "rgrok server WebSocket URL")
	name := fs.String("name", "", "requested tunnel subdomain/name")
	token := fs.String("token", "", "API token override")
	localHost := fs.String("local-host", "127.0.0.1", "local host to forward to")
	preserveHost := fs.Bool("preserve-host", false, "send the public Host header to the local app")
	maxBody := fs.Int64("max-body", protocol.MaxBodyBytesDefault, "maximum request or response body bytes")
	maxConcurrentRequests := fs.Int("max-concurrent-requests", 32, "maximum concurrent requests forwarded to the local app")
	showLogs := fs.Bool("logs", false, "show client logs")

	var portArg string
	parseArgs := args
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		portArg = args[0]
		parseArgs = args[1:]
	}

	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	log = newLogger(*showLogs, "text")
	if portArg == "" {
		if fs.NArg() != 1 {
			connectUsage()
			return fmt.Errorf("missing local port")
		}
		portArg = fs.Arg(0)
	} else if fs.NArg() != 0 {
		connectUsage()
		return fmt.Errorf("unexpected arguments after port")
	}

	srvURL := *serverURL
	if srvURL == "" {
		if cfg, err := client.LoadFileConfig(); err == nil && cfg.ServerBaseURL != "" {
			srvURL = wsURLFromBase(cfg.ServerBaseURL)
		}
		if srvURL == "" {
			srvURL = "wss://rgrok.rselbach.com/api/connect"
		}
	}

	localPort, err := strconv.Atoi(portArg)
	if err != nil || localPort <= 0 || localPort > 65535 {
		return fmt.Errorf("invalid local port %q", portArg)
	}

	authToken := *token
	if authToken == "" {
		authToken = os.Getenv("RGROK_API_TOKEN")
	}
	if authToken == "" {
		cfg, err := client.LoadFileConfig()
		if err != nil {
			return err
		}
		authToken = cfg.Token
	}
	if authToken == "" {
		return fmt.Errorf("not logged in; set RGROK_API_TOKEN or run `rgrok login --server <server-url>` first")
	}

	c := client.New(client.Config{
		ServerURL:             srvURL,
		RequestedID:           *name,
		AuthToken:             authToken,
		LocalHost:             *localHost,
		LocalPort:             localPort,
		PreserveHost:          *preserveHost,
		MaxBodyBytes:          *maxBody,
		MaxConcurrentRequests: *maxConcurrentRequests,
		Logger:                log,
	})
	return c.Run(context.Background())
}

func runStatus() error {
	path, err := client.ConfigPath()
	if err != nil {
		return err
	}

	cfg, err := client.LoadFileConfig()
	if err != nil {
		return err
	}

	if cfg.Token == "" {
		fmt.Fprintln(os.Stdout, "Not logged in. Run: rgrok login")
		return nil
	}

	fmt.Fprintf(os.Stdout, "Logged in as %s. Token last updated: %s. Config: %s\n", cfg.Login, cfg.UpdatedAt, path)

	serverURL := "https://rgrok.rselbach.com"
	if cfg.ServerBaseURL != "" {
		serverURL = cfg.ServerBaseURL
	}
	if len(os.Args) > 2 {
		fs := flag.NewFlagSet("status", flag.ContinueOnError)
		serverFlag := fs.String("server", serverURL, "rgrok server base URL")
		_ = fs.Parse(os.Args[2:])
		serverURL = *serverFlag
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Server unreachable: %s\n", err)
		return nil
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Server unreachable: %s\n", err)
		return nil
	}
	_ = resp.Body.Close()
	fmt.Fprintf(os.Stdout, "Server reachable at %s\n", serverURL)
	return nil
}

func newLogger(enabled bool, format string) *slog.Logger {
	if !enabled {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func connectUsage() {
	fmt.Fprintln(os.Stderr, `Usage: rgrok connect [flags] <local-port>
Flags:
  -server string     rgrok server WebSocket URL (default from login config or wss://rgrok.rselbach.com/api/connect)
  -name string       requested tunnel subdomain
  -token string      API token override (or set RGROK_API_TOKEN)
  -local-host string local host to forward to (default 127.0.0.1)
  -preserve-host            send public Host header to local app
  -logs                     show client logs
  -max-body int             max body bytes (default 33554432)
  -max-concurrent-requests  max concurrent local requests (default 32)`)
}

func usage() {
	fmt.Fprintln(os.Stderr, `rgrok

Usage:
  rgrok server [flags]
  rgrok login [flags]
  rgrok logout
  rgrok connect [flags] <local-port>
  rgrok status

Examples:
  rgrok server --addr :7000 --domain localhost:7000
  rgrok login --server https://rgrok.example.com
  rgrok connect 1234 --server ws://localhost:7000/api/connect
  rgrok connect 1234 --server wss://rgrok.example.com/api/connect --name demo`)
}
