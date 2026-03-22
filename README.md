# KoroneProxy

A reverse proxy for [pekora.zip](https://www.pekora.zip) with automatic CSRF
token handling, cookie forwarding, and retry logic. Built for self-hosting on
Render or any Go-capable platform.

## Features

- **Flexible URL formats** — two ways to specify the target:
  - Full URL: `https://your-proxy.com/https://www.pekora.zip/apisite/privatemessages/v1/messages/unread/count`
  - Relative path: `https://your-proxy.com/apisite/privatemessages/v1/messages/unread/count`
- **Automatic CSRF handling** — if the upstream returns `403` with an
  `x-csrf-token` header, the proxy automatically retries with the new token
- **Cookie forwarding** — all cookies from the client (including
  `.ROBLOSECURITY` / session cookies) are forwarded to upstream; `Set-Cookie`
  headers (including `rbxcsrf4`) are forwarded back
- **Configurable retries and timeouts**
- **API key protection** — optionally require a `PROXYKEY` header
- **Chrome-like User-Agent** to avoid blocks

## Usage

### Request Examples

```bash
# Format 1: Full URL
curl -H "PROXYKEY: your-secret-key" \
     -H "Cookie: .ROBLOSECURITY=your_cookie_here" \
     "https://your-proxy.com/https://www.pekora.zip/apisite/privatemessages/v1/messages/unread/count"

# Format 2: Relative path
curl -H "PROXYKEY: your-secret-key" \
     -H "Cookie: .ROBLOSECURITY=your_cookie_here" \
     "https://your-proxy.com/apisite/privatemessages/v1/messages/unread/count"

# POST with CSRF token
curl -X POST \
     -H "PROXYKEY: your-secret-key" \
     -H "Cookie: .ROBLOSECURITY=your_cookie_here" \
     -H "x-csrf-token: your_token_here" \
     -H "Content-Type: application/json" \
     -d '{"some":"data"}' \
     "https://your-proxy.com/apisite/some/post/endpoint"