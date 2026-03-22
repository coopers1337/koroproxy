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
	baseDomain     = "pekora.zip"
	baseHost       = "www.pekora.zip"
	userAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

var knownSubdomains = map[string]bool{
	"apis":            true,
	"assetgame":       true,
	"economy":         true,
	"auth":            true,
	"catalog":         true,
	"inventory":       true,
	"friends":         true,
	"thumbnails":      true,
	"games":           true,
	"users":           true,
	"presence":        true,
	"chat":            true,
	"contacts":        true,
	"groups":          true,
	"badges":          true,
	"avatar":          true,
	"develop":         true,
	"forums":          true,
	"locale":          true,
	"metrics":         true,
	"notifications":   true,
	"points":          true,
	"premiumfeatures": true,
	"publish":         true,
	"trades":          true,
	"www":             true,
}

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

	if port == "" {
		port = "8080"
	}

	client = &fasthttp.Client{
		ReadTimeout:         time.Duration(timeout) * time.Second,
		WriteTimeout:        time.Duration(timeout) * time.Second,
		MaxIdleConnDuration: 60 * time.Second,
		MaxConnsPerHost:     512,
	}

	log.Printf("KoroneProxy starting on port %s (timeout=%ds, retries=%d)", port, timeout, retries)

	if err := fasthttp.ListenAndServe(":"+port, requestHandler); err != nil {
		log.Fatalf("Error in ListenAndServe: %s", err)
	}
}

func isPekoraDomain(host string) bool {
	host = strings.ToLower(host)
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host == baseDomain || strings.HasSuffix(host, "."+baseDomain)
}

func resolveTargetURL(rawURI string) (string, bool) {
	if len(rawURI) < 2 {
		return "", false
	}

	pathAfterSlash := rawURI[1:]

	if strings.HasPrefix(pathAfterSlash, "https://") || strings.HasPrefix(pathAfterSlash, "http://") {
		parsed, err := url.Parse(pathAfterSlash)
		if err != nil {
			return "", false
		}
		parsed.Scheme = "https"
		if parsed.Host == "" || !isPekoraDomain(parsed.Host) {
			parsed.Host = baseHost
		}
		return parsed.String(), true
	}

	parts := strings.SplitN(pathAfterSlash, "/", 2)
	firstSegment := strings.ToLower(parts[0])
	remainingPath := ""
	if len(parts) > 1 {
		remainingPath = parts[1]
	}

	if firstSegment == "" {
		return "", false
	}

	if knownSubdomains[firstSegment] {
		host := firstSegment + "." + baseDomain
		targetURL := "https://" + host + "/" + remainingPath
		return targetURL, true
	}

	targetURL := "https://" + baseHost + "/" + pathAfterSlash
	return targetURL, true
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	if string(ctx.Path()) == "/healthz" {
		ctx.SetStatusCode(200)
		ctx.SetBody([]byte("ok"))
		return
	}

	val, ok := os.LookupEnv("KEY")
	if ok && val != "" && string(ctx.Request.Header.Peek("PROXYKEY")) != val {
		ctx.SetStatusCode(407)
		ctx.SetBody([]byte("Missing or invalid PROXYKEY header."))
		return
	}

	rawURI := string(ctx.Request.Header.RequestURI())

	if rawURI == "/" || rawURI == "" {
		ctx.SetStatusCode(200)
		ctx.SetContentType("text/html; charset=utf-8")
		ctx.SetBody([]byte(`
			<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<title>KoroneProxy</title>
				<style>
					body { font-family: system-ui, -apple-system, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
					h1 { color: #222; }
					.example { background: #f0f0f0; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
					pre { background: #eee; padding: 0.5rem; border-radius: 4px; overflow-x: auto; }
				</style>
			</head>
			<body>
				<h1>KoroneProxy</h1>
				<p>Reverse proxy for pekora.zip APIs.</p>
				<h2>Usage Examples:</h2>
				<div class="example">
					<h3>Main site path:</h3>
					<pre>/apisite/api/alerts/alert-info</pre>
					<p>→ <code>https://www.pekora.zip/apisite/api/alerts/alert-info</code></p>
				</div>
				<div class="example">
					<h3>Subdomain path:</h3>
					<pre>/apis/v1/something</pre>
					<p>→ <code>https://apis.pekora.zip/v1/something</code></p>
				</div>
				<div class="example">
					<h3>Full URL format:</h3>
					<pre>/https://www.pekora.zip/apisite/api/alerts/alert-info</pre>
					<p>→ <code>https://www.pekora.zip/apisite/api/alerts/alert-info</code></p>
				</div>
				<h2>Supported Methods:</h2>
				<p>GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, etc.</p>
			</body>
			</html>
		`))
		return
	}

	targetURL, valid := resolveTargetURL(rawURI)
	if !valid {
		ctx.SetStatusCode(400)
		ctx.SetContentType("text/html; charset=utf-8")
		ctx.SetBody([]byte(`
			<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<title>400 Bad Request - KoroneProxy</title>
				<style>
					body { font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 2rem auto; padding: 0 1rem; text-align: center; }
					h1 { color: #dc2626; }
				</style>
			</head>
			<body>
				<h1>400 Bad Request</h1>
				<p>Invalid URL format. Check your request.</p>
			</body>
			</html>
		`))
		return
	}

	response := makeRequestWithCSRF(ctx, targetURL, string(ctx.Request.Header.Peek("x-csrf-token")), 1)
	defer fasthttp.ReleaseResponse(response)

	if response.StatusCode() == 404 {
		ctx.SetStatusCode(404)
		ctx.SetContentType("text/html; charset=utf-8")
		ctx.SetBody([]byte(`
			<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<title>404 Not Found - KoroneProxy</title>
				<style>
					body { font-family: system-ui, -apple-system, sans-serif; max-width: 600px; margin: 2rem auto; padding: 0 1rem; text-align: center; }
					h1 { color: #dc2626; }
				</style>
			</head>
			<body>
				<h1>404 Not Found</h1>
				<p>The requested URL was not found on this proxy.</p>
				<p>Check your URL format and try again.</p>
			</body>
			</html>
		`))
		return
	}

	ctx.SetStatusCode(response.StatusCode())
	ctx.SetBody(response.Body())

	response.Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		keyLower := strings.ToLower(keyStr)
		switch keyLower {
		case "transfer-encoding", "connection":
			return
		}
		ctx.Response.Header.Set(keyStr, string(value))
	})

	response.Header.VisitAllCookie(func(key, value []byte) {
		ctx.Response.Header.AddBytesKV([]byte("Set-Cookie"), value)
	})
}

func makeRequestWithCSRF(ctx *fasthttp.RequestCtx, targetURL string, csrfToken string, attempt int) *fasthttp.Response {
	if attempt > retries {
		resp := fasthttp.AcquireResponse()
		resp.SetBody([]byte("Proxy failed to connect after maximum retries. Please try again."))
		resp.SetStatusCode(500)
		return resp
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethod(string(ctx.Method()))
	req.SetRequestURI(targetURL)
	req.SetBody(ctx.Request.Body())

	parsed, err := url.Parse(targetURL)
	if err != nil {
		resp := fasthttp.AcquireResponse()
		resp.SetBody([]byte("Invalid target URL."))
		resp.SetStatusCode(400)
		return resp
	}
	targetHost := parsed.Host

	ctx.Request.Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		keyLower := strings.ToLower(keyStr)
		switch keyLower {
		case "proxykey", "host", "connection", "transfer-encoding":
			return
		}
		req.Header.Set(keyStr, string(value))
	})

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Host", targetHost)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", "https://www.pekora.zip/")
	req.Header.Set("Origin", "https://www.pekora.zip")

	if csrfToken != "" {
		req.Header.Set("x-csrf-token", csrfToken)
	}

	req.Header.Del("Roblox-Id")
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Real-Ip")

	resp := fasthttp.AcquireResponse()
	err = client.Do(req, resp)
	if err != nil {
		fasthttp.ReleaseResponse(resp)
		return makeRequestWithCSRF(ctx, targetURL, csrfToken, attempt+1)
	}

	if resp.StatusCode() == 403 {
		newToken := string(resp.Header.Peek("x-csrf-token"))
		if newToken != "" && newToken != csrfToken {
			fasthttp.ReleaseResponse(resp)
			return makeRequestWithCSRF(ctx, targetURL, newToken, attempt+1)
		}
	}

	return resp
}