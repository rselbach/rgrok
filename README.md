# rgrok

`rgrok` is a small HTTP tunneling tool. The client connects outward to the server
over WebSocket, then the server forwards public HTTP requests through that tunnel
to a local port.

## Local quick start

Start the server:

```sh
go run ./cmd/rgrok server --addr :7000 --domain localhost:7000
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

Run the rgrok server on a private local port:

```sh
rgrok server --addr 127.0.0.1:7000 --domain rgrok.example.com --scheme https --auth-token "$RGROK_TOKEN"
```

Use a Caddy site that forwards the apex and wildcard tunnel hosts:

```caddyfile
rgrok.example.com, *.rgrok.example.com {
	reverse_proxy 127.0.0.1:7000
}
```

Connect a client:

```sh
rgrok connect 1234 --server wss://rgrok.example.com/api/connect --token "$RGROK_TOKEN"
```

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
