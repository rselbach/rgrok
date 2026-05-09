package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/rselbach/rgrok/internal/client"
	"github.com/rselbach/rgrok/internal/server"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

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
	case "connect":
		err = runConnect(os.Args[2:], log)
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
	connectPath := fs.String("connect-path", "/api/connect", "WebSocket tunnel path")
	dataPath := fs.String("data", "rgrok.json", "path to persistent server data")
	githubClientID := fs.String("github-client-id", os.Getenv("RGROK_GITHUB_CLIENT_ID"), "GitHub OAuth app client ID")
	githubClientSecret := fs.String("github-client-secret", os.Getenv("RGROK_GITHUB_CLIENT_SECRET"), "GitHub OAuth app client secret")
	maxBody := fs.Int64("max-body", 32<<20, "maximum request or response body bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := server.New(server.Config{
		Addr:               *addr,
		Domain:             *domain,
		PublicScheme:       *publicScheme,
		ConnectPath:        *connectPath,
		DataPath:           *dataPath,
		GitHubClientID:     *githubClientID,
		GitHubClientSecret: *githubClientSecret,
		MaxBodyBytes:       *maxBody,
		Logger:             log,
	})
	if err != nil {
		return err
	}
	return s.Run()
}

func runLogin(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	serverBaseURL := fs.String("server", "https://rgrok.rselbach.com", "rgrok server base URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

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

func runConnect(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	serverURL := fs.String("server", "wss://rgrok.rselbach.com/api/connect", "rgrok server WebSocket URL")
	name := fs.String("name", "", "requested tunnel subdomain/name")
	token := fs.String("token", "", "GitHub access token override")
	localHost := fs.String("local-host", "127.0.0.1", "local host to forward to")
	preserveHost := fs.Bool("preserve-host", false, "send the public Host header to the local app")
	maxBody := fs.Int64("max-body", 32<<20, "maximum request or response body bytes")

	var portArg string
	parseArgs := args
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		portArg = args[0]
		parseArgs = args[1:]
	}

	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	if portArg == "" {
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: rgrok connect [flags] <local-port>")
		}
		portArg = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return fmt.Errorf("usage: rgrok connect [flags] <local-port>")
	}

	localPort, err := strconv.Atoi(portArg)
	if err != nil || localPort <= 0 || localPort > 65535 {
		return fmt.Errorf("invalid local port %q", portArg)
	}

	authToken := *token
	if authToken == "" {
		cfg, err := client.LoadFileConfig()
		if err != nil {
			return err
		}
		authToken = cfg.Token
	}
	if authToken == "" {
		return fmt.Errorf("not logged in; run rgrok login first")
	}

	c := client.New(client.Config{
		ServerURL:    *serverURL,
		RequestedID:  *name,
		AuthToken:    authToken,
		LocalHost:    *localHost,
		LocalPort:    localPort,
		PreserveHost: *preserveHost,
		MaxBodyBytes: *maxBody,
		Logger:       log,
	})
	return c.Run()
}

func usage() {
	fmt.Fprintln(os.Stderr, `rgrok

Usage:
  rgrok server [flags]
  rgrok login [flags]
  rgrok connect [flags] <local-port>

Examples:
  rgrok server --addr :7000 --domain localhost:7000
  rgrok login --server https://rgrok.example.com
  rgrok connect 1234 --server ws://localhost:7000/api/connect
  rgrok connect 1234 --server wss://rgrok.example.com/api/connect --name demo`)
}
