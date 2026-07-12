# rgrok

`rgrok` is a small HTTP tunneling tool. The client connects outward to the server
over WebSocket, then the server forwards public HTTP requests through that tunnel
to a local port.

## Local quick start

Start the server:

```sh
go run ./cmd/rgrok server --addr :7000 --domain localhost:7000 --github-client-id "$RGROK_GITHUB_CLIENT_ID" --github-client-secret "$RGROK_GITHUB_CLIENT_SECRET"
```

Log in with GitHub:

```sh
go run ./cmd/rgrok login --server http://localhost:7000
```

Connect a local app:

```sh
go run ./cmd/rgrok connect 1234 --server ws://localhost:7000/api/connect
```

With a named tunnel:

```sh
go run ./cmd/rgrok connect 1234 --server ws://localhost:7000/api/connect --name demo
```

Then open:

```text
http://demo.localhost:7000
```

## Behind Caddy and Cloudflare

Create a GitHub OAuth app with:

- Homepage URL: `https://rgrok.rselbach.com`
- Authorization callback URL: `https://rgrok.rselbach.com/auth/github/callback`
- Device flow enabled

Run the rgrok server on a private local port:

```sh
rgrok server --addr 127.0.0.1:7000 --domain rgrok.rselbach.com --scheme https --behind-proxy --data /var/lib/rgrok/rgrok.json --github-client-id "$RGROK_GITHUB_CLIENT_ID" --github-client-secret "$RGROK_GITHUB_CLIENT_SECRET"
```

`--behind-proxy` makes the server trust `X-Forwarded-*` headers from the
proxy so rate limiting and forwarded headers see real client addresses. The
trusted proxy addresses default to loopback; adjust with
`--trusted-proxy-cidrs` if Caddy runs elsewhere.

Use a Caddy site that forwards the apex and wildcard tunnel hosts:

```caddyfile
rgrok.rselbach.com, *.rgrok.rselbach.com {
	reverse_proxy 127.0.0.1:7000
}
```

Log in once on the client:

```sh
rgrok login --server https://rgrok.rselbach.com
```

Connect a client:

```sh
rgrok connect 1234 --server wss://rgrok.rselbach.com/api/connect
```

You can also create named API tokens from the dashboard and pass one directly to
the client. API tokens expire after at most 90 days and are stored as hashes on
the server.

```sh
RGROK_API_TOKEN=... rgrok connect 1234 --server wss://rgrok.rselbach.com/api/connect
```

Go applications can manage their own tunnel with the public client package:

```go
import rgrokclient "github.com/rselbach/rgrok/client"

tun, err := rgrokclient.Start(ctx, rgrokclient.Config{
	ServerBaseURL: "https://rgrok.rselbach.com",
	Token:         os.Getenv("RGROK_API_TOKEN"),
	Name:          "my-app-dev",
	LocalPort:     1234,
})
if err != nil {
	return err
}
defer tun.Close()

publicBaseURL := tun.PublicURL
```

Admins can also create application profiles in the dashboard for tools that do
not have a user account. An application profile contains an Ed25519 OpenSSH
public key, allowed method/path templates, and per-tunnel request limits. Paths
support full-segment parameters such as `{slug}`.

Application clients prove possession of the corresponding private key and
receive a random tunnel name. `InstanceID` is a stable, client-generated value
used to reuse that random name when it is available. Admins can inspect and
remove these reserved names from the dashboard.

```go
tun, err := rgrokclient.Start(ctx, rgrokclient.Config{
	ServerBaseURL:         "https://rgrok.rselbach.com",
	ApplicationProfileID: "0123456789abcdef0123456789abcdef",
	InstanceID:           installationID,
	ApplicationPrivateKey: privateKey,
	LocalPort:             1234,
})
```

`ApplicationPrivateKey` is an `ed25519.PrivateKey`; loading an encrypted or
unencrypted OpenSSH private-key file is the embedding tool's responsibility.
Existing API-token clients continue to use the original registration flow.

For service-style clients, set `RGROK_CONFIG` while running `rgrok login` to
write the token to a predictable file:

```sh
sudo env RGROK_CONFIG=/etc/rgrok/rgrok-client@demo.json rgrok login --server https://rgrok.rselbach.com
sudo chown root:root /etc/rgrok/rgrok-client@demo.json
sudo chmod 0600 /etc/rgrok/rgrok-client@demo.json
```

The server stores its whitelist, sessions, application profiles, and default
admin user in the JSON file passed with `--data`. The initial whitelist
contains `rselbach` as an admin. The dashboard is available at
`https://rgrok.rselbach.com/dashboard`.

Sample deployment files for `rgrok.rselbach.com` live in `deploy/`:

- `deploy/Caddyfile`
- `deploy/caddy-cloudflare.env`
- `deploy/rgrok-server.service`
- `deploy/rgrok-server.env`
- `deploy/rgrok-client@.service`
- `deploy/rgrok-client@.env`

## Current limits

The first implementation forwards one complete HTTP request and response per
tunnel message. That keeps the MVP simple, but it means very large or streaming
bodies are capped by `--max-body`. Raw TCP forwarding and chunked streaming can
be added on top of the same protocol.
