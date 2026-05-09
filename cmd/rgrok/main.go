package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"

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
	authToken := fs.String("auth-token", "", "optional shared auth token")
	maxBody := fs.Int64("max-body", 32<<20, "maximum request or response body bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s := server.New(server.Config{
		Addr:         *addr,
		Domain:       *domain,
		PublicScheme: *publicScheme,
		ConnectPath:  *connectPath,
		AuthToken:    *authToken,
		MaxBodyBytes: *maxBody,
		Logger:       log,
	})
	return s.Run()
}

func runConnect(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	serverURL := fs.String("server", "ws://localhost:7000/api/connect", "rgrok server WebSocket URL")
	name := fs.String("name", "", "requested tunnel subdomain/name")
	token := fs.String("token", "", "shared auth token")
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

	c := client.New(client.Config{
		ServerURL:    *serverURL,
		RequestedID:  *name,
		AuthToken:    *token,
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
  rgrok connect [flags] <local-port>

Examples:
  rgrok server --addr :7000 --domain localhost:7000
  rgrok connect 1234 --server ws://localhost:7000/api/connect
  rgrok connect 1234 --server wss://rgrok.example.com/api/connect --name demo`)
}
