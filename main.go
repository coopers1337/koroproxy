package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

const (
	userAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	baseTarget = "https://www.pekora.zip"
	allowedDomain = "pekora.zip"
)

var (
	key     string
	timeout time.Duration
	retries int
	client  *fasthttp.Client
	host    string
)

func main() {
	key = os.Getenv("KEY")
	host = os.Getenv("HOST")

	t, _ := strconv.Atoi(os.Getenv("TIMEOUT"))
	if t <= 0 {
		t = 5
	}
	timeout = time.Duration(t) * time.Second

	r, _ := strconv.Atoi(os.Getenv("RETRIES"))
	if r <= 0 {
		r = 3
	}
	retries = r

	client = &fasthttp.Client{
		ReadTimeout:              timeout,
		WriteTimeout:             timeout,
		NoDefaultUserAgentHeader: true,
		DisablePathNormalizing:   true,
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("KoroneProxy listening on :%s\n", port)
	if err := fasthttp.ListenAndServe(":"+port, handler); err != nil {
		fmt.Printf("Fatal: %s\n", err)
		os.Exit(1)
	}
}

// isPekoraHost checks that a hostname is pekora.zip or *.pekora.zip
func isPekoraHost(h string) bool {
	h = strings.ToLower(h)
	return h == allowedDomain || strings.HasSuffix(h, "."+allowedDomain)
}

func resolveTarget(ctx *fasthttp.RequestCtx) (string, bool) {
	path := string(ctx.Path())
	reqHost := string(ctx.Host())
	qs := string(ctx.QueryArgs().QueryString())

	// Format 3: subdomain.koroneproxy.up.railway.app/path
	if host != "" && strings.HasSuffix(reqHost, "."+host) {
		subdomain := strings.TrimSuffix(reqHost, "."+host)
		if subdomain == "" {
			return "", false
		}
		target := fmt.Sprintf("https://%s.%s%s", subdomain, allowedDomain, path)
		if qs != "" {
			target += "?" + qs
		}
		return target, true
	}

	// Format 2: /https://www.pekora.zip/apisite/... or /http://...
	if strings.HasPrefix(path, "/https://") || strings.HasPrefix(path, "/http://") {
		raw := strings.TrimPrefix(path, "/")
		parsed, err := url.Parse(raw)
		if err != nil {
			return "", false
		}

		// MUST be pekora.zip domain only
		if !isPekoraHost(parsed.Host) {
			return "", false
		}

		target := parsed.Scheme + "://" + parsed.Host + parsed.Path
		if qs != "" {
			target += "?" + qs
		} else if parsed.RawQuery != "" {
			target += "?" + parsed.RawQuery
		}
		return target, true
	}

	// Format 1: /apisite/catalog/v1/... → https://www.pekora.zip/apisite/...
	target := baseTarget + path
	if qs != "" {
		target += "?" + qs
	}
	return target, true
}

func handler(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())

	// health check
	if path == "/healthz" {
		ctx.SetStatusCode(200)
		ctx.SetContentType("application/json")
		ctx.SetBodyString(`{"status":"ok"}`)
		return
	}

	// key auth
	if key != "" {
		provided := string(ctx.Request.Header.Peek("x-key"))
		if provided != key {
			jsonError(ctx, 403, "Forbidden")
			return
		}
	}

	// resolve target URL
	targetURL, ok := resolveTarget(ctx)
	if !ok {
		// bad domain or invalid URL
		jsonError(ctx, 403, "Forbidden: only pekora.zip is allowed")
		return
	}

	// double check final target is pekora.zip
	parsed, err := url.Parse(targetURL)
	if err != nil || !isPekoraHost(parsed.Host) {
		jsonError(ctx, 403, "Forbidden: only pekora.zip is allowed")
		return
	}

	fmt.Printf("[PROXY] %s %s → %s\n", string(ctx.Method()), path, targetURL)

	// user cookies from client
	userCookie := string(ctx.Request.Header.Peek("Cookie"))

	// x-csrf-token from client header
	csrfToken := string(ctx.Request.Header.Peek("x-csrf-token"))

	// rbxcsrf4 from client cookie jar
	rbxcsrf4 := extractCookieValue(userCookie, "rbxcsrf4")

	// if we have neither, do a preflight POST to get both
	if csrfToken == "" && rbxcsrf4 == "" {
		csrfToken, rbxcsrf4 = preflight(targetURL, userCookie)
	}

	// proxy with retries
	var lastErr error
	for i := 0; i < retries; i++ {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		req.SetRequestURI(targetURL)
		req.Header.SetMethod(string(ctx.Method()))
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Host", parsed.Host)

		// copy client headers — skip ones we manage manually
		ctx.Request.Header.VisitAll(func(k, v []byte) {
			lo := strings.ToLower(string(k))
			if lo == "host" ||
				lo == "x-key" ||
				lo == "user-agent" ||
				lo == "cookie" ||
				lo == "x-csrf-token" {
				return
			}
			req.Header.SetBytesKV(k, v)
		})

		// set x-csrf-token header
		if csrfToken != "" {
			req.Header.Set("x-csrf-token", csrfToken)
		}

		// build cookie — user cookies + fresh rbxcsrf4 JWT
		finalCookie := mergeCookies(userCookie, "rbxcsrf4", rbxcsrf4)
		if finalCookie != "" {
			req.Header.Set("Cookie", finalCookie)
		}

		// body
		if body := ctx.PostBody(); len(body) > 0 {
			req.SetBody(body)
		}

		err = client.DoTimeout(req, resp, timeout)
		if err != nil {
			lastErr = err
			fmt.Printf("[ERROR] attempt %d: %s → %s\n", i+1, targetURL, err.Error())
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			continue
		}

		status := resp.StatusCode()
		fmt.Printf("[RESP] %d %s\n", status, targetURL)

		// 403 = CSRF rejected
		if status == 403 {
			newCSRF := string(resp.Header.Peek("x-csrf-token"))
			newRbxcsrf4 := findSetCookie(resp, "rbxcsrf4")

			if newCSRF != "" {
				csrfToken = newCSRF
			}
			if newRbxcsrf4 != "" {
				rbxcsrf4 = newRbxcsrf4
			}

			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			continue
		}

		location := string(resp.Header.Peek("Location"))
		contentType := string(resp.Header.Peek("Content-Type"))

		// block redirects to pekora.zip / roblox.com
		if status >= 300 && status < 400 {
			if strings.Contains(location, "pekora.zip") ||
				strings.Contains(location, "roblox.com") {
				fasthttp.ReleaseRequest(req)
				fasthttp.ReleaseResponse(resp)
				jsonError(ctx, 404, "Not Found")
				return
			}
		}

		// block HTML
		if strings.Contains(contentType, "text/html") {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			jsonError(ctx, 404, "Not Found")
			return
		}

		// block upstream 404
		if status == 404 {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
			jsonError(ctx, 404, "Not Found")
			return
		}

		// success
		ctx.SetStatusCode(status)

		// copy response headers
		resp.Header.VisitAll(func(k, v []byte) {
			lo := strings.ToLower(string(k))
			if lo == "transfer-encoding" ||
				lo == "connection" ||
				lo == "set-cookie" {
				return
			}
			ctx.Response.Header.AddBytesKV(k, v)
		})

		// forward x-csrf-token back to client
		if v := string(resp.Header.Peek("x-csrf-token")); v != "" {
			ctx.Response.Header.Set("x-csrf-token", v)
		}

		// forward Set-Cookie headers back to client
		resp.Header.VisitAllCookie(func(k, v []byte) {
			ctx.Response.Header.Add("Set-Cookie", string(k)+"="+string(v))
		})

		ctx.SetBody(resp.Body())

		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
		return
	}

	// all retries failed — hide internal error details
	jsonError(ctx, 502, "Upstream request failed")
}

// preflight does an empty POST to get x-csrf-token + rbxcsrf4 Set-Cookie
func preflight(targetURL string, cookie string) (csrfToken string, rbxcsrf4 string) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(targetURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("User-Agent", userAgent)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	if err := client.DoTimeout(req, resp, timeout); err != nil {
		return "", ""
	}

	csrfToken = string(resp.Header.Peek("x-csrf-token"))
	rbxcsrf4 = findSetCookie(resp, "rbxcsrf4")
	return csrfToken, rbxcsrf4
}

// findSetCookie scans Set-Cookie for a specific cookie name
func findSetCookie(resp *fasthttp.Response, name string) string {
	found := ""
	resp.Header.VisitAllCookie(func(k, v []byte) {
		if string(k) == name {
			found = string(v)
		}
	})
	return found
}

// mergeCookies replaces or appends name=value in existing cookie string
func mergeCookies(existing string, name string, value string) string {
	if value == "" {
		return existing
	}

	var parts []string
	if existing != "" {
		for _, part := range strings.Split(existing, ";") {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, name+"=") {
				continue
			}
			parts = append(parts, trimmed)
		}
	}

	parts = append(parts, name+"="+value)
	return strings.Join(parts, "; ")
}

// extractCookieValue reads a named cookie from Cookie header string
func extractCookieValue(cookieHeader string, name string) string {
	for _, part := range strings.Split(cookieHeader, ";") {
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(trimmed, name+"=") {
			return strings.TrimPrefix(trimmed, name+"=")
		}
	}
	return ""
}

func jsonError(ctx *fasthttp.RequestCtx, status int, message string) {
	ctx.SetStatusCode(status)
	ctx.SetContentType("application/json")
	ctx.SetBodyString(fmt.Sprintf(`{"error":%d,"message":"%s"}`, status, message))
}