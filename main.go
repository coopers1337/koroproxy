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
	firstSegment := parts[0]
	remainingPath := ""
	if len(parts) > 1 {
		remainingPath = parts[1]
	}

	if firstSegment == "" {
		return "", false
	}

	subdomain := strings.ToLower(firstSegment)
	host := subdomain + "." + baseDomain
	targetURL := "https://" + host + "/" + remainingPath

	return targetURL, true
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	// Health check endpoint
	if string(ctx.Path()) == "/healthz" {
		ctx.SetStatusCode(200)
		ctx.SetBody([]byte("ok"))
		return
	}

	// Authentication
	val, ok := os.LookupEnv("KEY")
	if ok && val != "" && string(ctx.Request.Header.Peek("PROXYKEY")) != val {
		ctx.SetStatusCode(407)
		ctx.SetBody([]byte("Missing or invalid PROXYKEY header."))
		return
	}

	// Build target URL
	rawURI := string(ctx.Request.Header.RequestURI())

	if rawURI == "/" || rawURI == "" {
		ctx.Redirect(redirectTarget, fasthttp.StatusFound)
		return
	}

	targetURL, valid := resolveTargetURL(rawURI)
	if !valid {
		ctx.Redirect(redirectTarget, fasthttp.StatusFound)
		return
	}

	// Make request with CSRF retry
	csrfToken := string(ctx.Request.Header.Peek("x-csrf-token"))
	response := makeRequestWithCSRF(ctx, targetURL, csrfToken, 1)
	defer fasthttp.ReleaseResponse(response)

	// Handle 404 redirect
	if response.StatusCode() == 404 {
		ctx.Redirect(redirectTarget, fasthttp.StatusFound)
		return
	}

	// Copy response back to client
	ctx.SetStatusCode(response.StatusCode())

	response.Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		switch strings.ToLower(keyStr) {
		case "transfer-encoding", "connection", "content-length":
			return
		}
		ctx.Response.Header.Set(keyStr, string(value))
	})

	response.Header.VisitAllCookie(func(key, value []byte) {
		ctx.Response.Header.AddBytesKV([]byte("Set-Cookie"), value)
	})

	ctx.SetBody(response.Body())
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

	clientCookie := string(ctx.Request.Header.Peek("Cookie"))
	if clientCookie != "" {
		req.Header.Set("Cookie", clientCookie)
	}

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
		log.Printf("Attempt %d failed for %s: %s", attempt, targetURL, err)
		return makeRequestWithCSRF(ctx, targetURL, csrfToken, attempt+1)
	}

	if resp.StatusCode() == 403 {
		newToken := string(resp.Header.Peek("x-csrf-token"))
		if newToken != "" && newToken != csrfToken {
			log.Printf("CSRF token refresh on attempt %d for %s", attempt, targetURL)
			fasthttp.ReleaseResponse(resp)
			return makeRequestWithCSRF(ctx, targetURL, newToken, attempt+1)
		}
	}

	return resp
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}