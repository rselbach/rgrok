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
rgrok server --addr 127.0.0.1:7000 --domain rgrok.rselbach.com --scheme https --data /var/lib/rgrok/rgrok.json --github-client-id "$RGROK_GITHUB_CLIENT_ID" --github-client-secret "$RGROK_GITHUB_CLIENT_SECRET"
```

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

For service-style clients, set `RGROK_CONFIG` while running `rgrok login` to
write the token to a predictable file:

```sh
sudo env RGROK_CONFIG=/etc/rgrok/rgrok-client@demo.json rgrok login --server https://rgrok.rselbach.com
sudo chown root:root /etc/rgrok/rgrok-client@demo.json
sudo chmod 0600 /etc/rgrok/rgrok-client@demo.json
```

The server stores its whitelist, sessions, and default admin user in the JSON
file passed with `--data`. The initial whitelist contains `rselbach` as an
admin. The dashboard is available at `https://rgrok.rselbach.com/dashboard`.

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
