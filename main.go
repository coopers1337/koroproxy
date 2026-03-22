package main

import (
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var (
	timeout, _ = strconv.Atoi(getEnvDefault("TIMEOUT", "10"))
	retries, _ = strconv.Atoi(getEnvDefault("RETRIES", "5"))
	port       = getEnvDefault("PORT", "8080")
	client     *fasthttp.Client
)

const (
	baseDomain    = "pekora.zip"
	baseHost      = "www.pekora.zip"
	userAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	redirectTarget = "https://www.pekora.zip/"
)

func getEnvDefault(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

func main() {
	if retries < 1 {
		retries = 1
	}

	client = &fasthttp.Client{
		ReadTimeout:         time.Duration(timeout) * time.Second,
		WriteTimeout:        time.Duration(timeout) * time.Second,
		MaxIdleConnDuration: 60 * time.Second,
		MaxConnsPerHost:     512,
	}

	log.Printf("PekoraProxy starting on port %s (timeout=%ds, retries=%d)", port, timeout, retries)

	if err := fasthttp.ListenAndServe(":"+port, requestHandler); err != nil {
		log.Fatalf("Error in ListenAndServe: %s", err)
	}
}

// isPekoraDomain checks if a hostname belongs to pekora.zip (any subdomain).
func isPekoraDomain(host string) bool {
	host = strings.ToLower(host)
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host == baseDomain || strings.HasSuffix(host, "."+baseDomain)
}

// resolveTargetURL takes the raw request URI and builds the upstream URL.
//
// Supported formats:
//
//  1. Full URL with any pekora.zip subdomain:
//     /https://apis.pekora.zip/endpoint
//     /https://assetgame.pekora.zip/v1/something
//     /https://www.pekora.zip/apisite/privatemessages/v1/messages/unread/count
//     /http://economy.pekora.zip/v2/something
//
//  2. Subdomain-prefixed relative path (RoProxy style):
//     /apis/privatemessages/v1/messages/unread/count
//     → https://apis.pekora.zip/privatemessages/v1/messages/unread/count
//
//  3. Direct path (no subdomain prefix, defaults to www):
//     /apisite/privatemessages/v1/messages/unread/count
//     → tries as subdomain first; if the first segment looks like a known
//       pattern it uses www.pekora.zip/apisite/...
//
// The function returns the target URL and a boolean indicating success.
func resolveTargetURL(rawURI string) (string, bool) {
	if len(rawURI) < 2 {
		return "", false
	}

	pathAfterSlash := rawURI[1:]

	// Format 1: Full URL
	if strings.HasPrefix(pathAfterSlash, "https://") || strings.HasPrefix(pathAfterSlash, "http://") {
		parsed, err := url.Parse(pathAfterSlash)
		if err != nil {
			return "", false
		}
		// Always force HTTPS
		parsed.Scheme = "https"
		// If host is empty or not a pekora domain, default to baseHost
		if parsed.Host == "" || !isPekoraDomain(parsed.Host) {
			parsed.Host = baseHost
		}
		return parsed.String(), true
	}

	// Format 2 & 3: Relative path
	// Split into first segment and the rest
	// e.g. "apis/privatemessages/v1/..." → ["apis", "privatemessages/v1/..."]
	// e.g. "apisite/privatemessages/v1/..." → ["apisite", "privatemessages/v1/..."]
	parts := strings.SplitN(pathAfterSlash, "/", 2)
	firstSegment := parts[0]
	remainingPath := ""
	if len(parts) > 1 {
		remainingPath = parts[1]
	}

	if firstSegment == "" {
		return "", false
	}

	// Build URL: treat first segment as subdomain of pekora.zip
	// e.g. apis → apis.pekora.zip
	// e.g. assetgame → assetgame.pekora.zip
	// e.g. www → www.pekora.zip
	// e.g. economy → economy.pekora.zip
	subdomain := strings.ToLower(firstSegment)
	host := subdomain + "." + baseDomain

	targetURL := "https://" + host + "/" + remainingPath

	return targetURL, true
}

// requestHandler is the main HTTP handler.
//
// Supports:
//   - PROXYKEY authentication
//   - All pekora.zip subdomains (apis, assetgame, economy, www, etc.)
//   - Full URL and relative path formats
//   - CSRF token auto-refresh on 403
//   - Cookie forwarding (including .ROBLOSECURITY, rbxcsrf4, etc.)
//   - 404 redirect to https://www.pekora.zip/
func requestHandler(ctx *fasthttp.RequestCtx) {
	// --- Authentication ---
	val, ok := os.LookupEnv("KEY")
	if ok && val != "" && string(ctx.Request.Header.Peek("PROXYKEY")) != val {
		ctx.SetStatusCode(407)
		ctx.SetBody([]byte("Missing or invalid PROXYKEY header."))
		return
	}

	// --- Build target URL ---
	rawURI := string(ctx.Request.Header.RequestURI())

	// Handle root path
	if rawURI == "/" || rawURI == "" {
		ctx.Redirect(redirectTarget, fasthttp.StatusFound)
		return
	}

	targetURL, valid := resolveTargetURL(rawURI)
	if !valid {
		ctx.Redirect(redirectTarget, fasthttp.StatusFound)
		return
	}

	// --- Make the proxied request with CSRF retry logic ---
	csrfToken := string(ctx.Request.Header.Peek("x-csrf-token"))
	response := makeRequestWithCSRF(ctx, targetURL, csrfToken, 1)
	defer fasthttp.ReleaseResponse(response)

	// --- Handle 404: redirect to pekora.zip ---
	if response.StatusCode() == 404 {
		ctx.Redirect(redirectTarget, fasthttp.StatusFound)
		return
	}

	// --- Copy response back to client ---
	ctx.SetStatusCode(response.StatusCode())

	// Copy all response headers
	response.Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		switch strings.ToLower(keyStr) {
		case "transfer-encoding", "connection", "content-length":
			return
		}
		ctx.Response.Header.Set(keyStr, string(value))
	})

	// Copy Set-Cookie headers properly (there can be multiple)
	response.Header.VisitAllCookie(func(key, value []byte) {
		ctx.Response.Header.AddBytesKV([]byte("Set-Cookie"), value)
	})

	ctx.SetBody(response.Body())
}

// makeRequestWithCSRF performs the upstream HTTP request with automatic
// CSRF token refresh handling.
//
// Flow:
//  1. Build request with all client headers, cookies, and CSRF token
//  2. Send to upstream pekora.zip subdomain
//  3. If 403 + new x-csrf-token in response → retry with new token
//  4. On network error → retry up to max retries
//  5. Return final response
func makeRequestWithCSRF(ctx *fasthttp.RequestCtx, targetURL string, csrfToken string, attempt int) *fasthttp.Response {
	if attempt > retries {
		resp := fasthttp.AcquireResponse()
		resp.SetBody([]byte("Proxy failed to connect after maximum retries. Please try again."))
		resp.SetStatusCode(500)
		return resp
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	// Set method and URL
	req.Header.SetMethod(string(ctx.Method()))
	req.SetRequestURI(targetURL)

	// Set body
	req.SetBody(ctx.Request.Body())

	// Parse the target URL to get the correct host for the Host header
	parsed, err := url.Parse(targetURL)
	if err != nil {
		resp := fasthttp.AcquireResponse()
		resp.SetBody([]byte("Invalid target URL."))
		resp.SetStatusCode(400)
		return resp
	}
	targetHost := parsed.Host

	// Copy all headers from original request
	ctx.Request.Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		keyLower := strings.ToLower(keyStr)

		// Skip proxy-specific and hop-by-hop headers
		switch keyLower {
		case "proxykey", "host", "connection", "transfer-encoding":
			return
		}
		req.Header.Set(keyStr, string(value))
	})

	// Set required headers
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Host", targetHost)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", "https://www.pekora.zip/")
	req.Header.Set("Origin", "https://www.pekora.zip")

	// Forward cookies from client request
	clientCookie := string(ctx.Request.Header.Peek("Cookie"))
	if clientCookie != "" {
		req.Header.Set("Cookie", clientCookie)
	}

	// Set CSRF token if we have one
	if csrfToken != "" {
		req.Header.Set("x-csrf-token", csrfToken)
	}

	// Remove identifying headers
	req.Header.Del("Roblox-Id")
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Real-Ip")

	resp := fasthttp.AcquireResponse()
	err = client.Do(req, resp)

	if err != nil {
		fasthttp.ReleaseResponse(resp)
		log.Printf("Attempt %d failed for %s: %s", attempt, targetURL, err)
		return makeRequestWithCSRF(ctx, targetURL, csrfToken, attempt+1)
	}

	// --- CSRF handling ---
	// pekora.zip (like Roblox) returns 403 with a fresh x-csrf-token
	// when the token is missing or expired. We grab it and retry.
	if resp.StatusCode() == 403 {
		newToken := string(resp.Header.Peek("x-csrf-token"))
		if newToken != "" && newToken != csrfToken {
			log.Printf("CSRF token refresh on attempt %d for %s (token: %s...)",
				attempt, targetURL, truncate(newToken, 12))
			fasthttp.ReleaseResponse(resp)
			return makeRequestWithCSRF(ctx, targetURL, newToken, attempt+1)
		}
	}

	return resp
}

// truncate returns the first n characters of s, or s if shorter.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}