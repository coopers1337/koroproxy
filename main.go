package main

import (
	"bytes"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

const (
	baseDomain  = "pekora.zip"
	defaultHost = "www." + baseDomain
	originVal   = "https://" + defaultHost
	refererVal  = originVal + "/"
	uaVal       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	acceptVal   = "application/json, text/plain, */*"
	acceptEnc   = "gzip, deflate, br"
	acceptLang  = "en-US,en;q=0.9"
)

var (
	maxRetries int
	proxyKey   []byte
	client     *fasthttp.Client
)

var (
	bHealthz   = []byte("/healthz")
	bProxykey  = []byte("proxykey")
	bHost      = []byte("host")
	bConn      = []byte("connection")
	bTE        = []byte("transfer-encoding")
	bSetCookie = []byte("Set-Cookie")
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func isSubdomain(s string) bool {
	switch s {
	case "apis", "assetgame", "economy", "auth", "catalog",
		"inventory", "friends", "thumbnails", "games", "users",
		"presence", "chat", "contacts", "groups", "badges",
		"avatar", "develop", "forums", "locale", "metrics",
		"notifications", "points", "premiumfeatures", "publish",
		"trades", "www":
		return true
	}
	return false
}

func resolve(uri string) (target, host string, ok bool) {
	if len(uri) < 2 {
		return
	}
	p := uri[1:]

	full := false
	if strings.HasPrefix(p, "https://") {
		full = true
	} else if strings.HasPrefix(p, "http://") {
		p = "https://" + p[7:]
		full = true
	}

	if full {
		a := p[8:]
		si := strings.IndexByte(a, '/')
		if si < 0 {
			si = len(a)
		}
		host = a[:si]
		h := host
		if ci := strings.LastIndexByte(h, ':'); ci >= 0 {
			h = h[:ci]
		}
		h = strings.ToLower(h)
		if h != baseDomain && !strings.HasSuffix(h, "."+baseDomain) {
			host = defaultHost
			if si < len(a) {
				return "https://" + host + a[si:], host, true
			}
			return "https://" + host + "/", host, true
		}
		return p, host, true
	}

	si := strings.IndexByte(p, '/')
	var seg, rest string
	if si >= 0 {
		seg, rest = strings.ToLower(p[:si]), p[si+1:]
	} else {
		seg = strings.ToLower(p)
	}
	if seg == "" {
		return
	}
	if isSubdomain(seg) {
		host = seg + "." + baseDomain
		return "https://" + host + "/" + rest, host, true
	}
	return "https://" + defaultHost + "/" + p, defaultHost, true
}

func main() {
	t, _ := strconv.Atoi(env("TIMEOUT", "10"))
	if t < 1 {
		t = 10
	}
	d := time.Duration(t) * time.Second

	maxRetries, _ = strconv.Atoi(env("RETRIES", "5"))
	if maxRetries < 1 {
		maxRetries = 1
	}
	if k := os.Getenv("KEY"); k != "" {
		proxyKey = []byte(k)
	}

	client = &fasthttp.Client{
		ReadTimeout:              d,
		WriteTimeout:             d,
		MaxIdleConnDuration:      90 * time.Second,
		MaxConnsPerHost:          1024,
		NoDefaultUserAgentHeader: true,
	}

	addr := ":" + env("PORT", "8080")
	log.Printf("KoroneProxy %s", addr)
	log.Fatal((&fasthttp.Server{
		Handler:               handle,
		NoDefaultServerHeader: true,
		NoDefaultDate:         true,
		NoDefaultContentType:  true,
		ReadTimeout:           d,
		WriteTimeout:          d + d,
	}).ListenAndServe(addr))
}

func handle(ctx *fasthttp.RequestCtx) {
	if bytes.Equal(ctx.Path(), bHealthz) {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("ok")
		return
	}

	if len(proxyKey) > 0 && !bytes.Equal(ctx.Request.Header.Peek("PROXYKEY"), proxyKey) {
		ctx.SetStatusCode(407)
		ctx.SetBodyString("unauthorized")
		return
	}

	uri := string(ctx.Request.Header.RequestURI())
	if uri == "/" || uri == "" {
		ctx.SetStatusCode(200)
		ctx.SetBodyString("KoroneProxy")
		return
	}

	target, host, ok := resolve(uri)
	if !ok {
		ctx.SetStatusCode(400)
		ctx.SetBodyString("bad request")
		return
	}

	fwd(ctx, target, host, string(ctx.Request.Header.Peek("X-Csrf-Token")))
}

func fwd(ctx *fasthttp.RequestCtx, url, host, csrf string) {
	method := ctx.Method()
	body := ctx.Request.Body()

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	for i := 0; i < maxRetries; i++ {
		req.Reset()
		req.Header.SetMethodBytes(method)
		req.SetRequestURI(url)
		if len(body) > 0 {
			req.SetBodyRaw(body)
		}

		ctx.Request.Header.VisitAll(func(k, v []byte) {
			if bytes.EqualFold(k, bProxykey) ||
				bytes.EqualFold(k, bHost) ||
				bytes.EqualFold(k, bConn) ||
				bytes.EqualFold(k, bTE) {
				return
			}
			req.Header.SetBytesKV(k, v)
		})

		req.Header.Set("Host", host)
		req.Header.Set("User-Agent", uaVal)
		req.Header.Set("Accept", acceptVal)
		req.Header.Set("Accept-Encoding", acceptEnc)
		req.Header.Set("Accept-Language", acceptLang)
		req.Header.Set("Referer", refererVal)
		req.Header.Set("Origin", originVal)
		if csrf != "" {
			req.Header.Set("X-Csrf-Token", csrf)
		}
		req.Header.Del("Roblox-Id")
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Real-Ip")

		resp := fasthttp.AcquireResponse()
		if err := client.Do(req, resp); err != nil {
			fasthttp.ReleaseResponse(resp)
			continue
		}

		if resp.StatusCode() == 403 {
			if t := string(resp.Header.Peek("X-Csrf-Token")); t != "" && t != csrf {
				csrf = t
				fasthttp.ReleaseResponse(resp)
				continue
			}
		}

		ctx.SetStatusCode(resp.StatusCode())
		ctx.SetBody(resp.Body())
		resp.Header.VisitAll(func(k, v []byte) {
			if bytes.EqualFold(k, bTE) || bytes.EqualFold(k, bConn) || bytes.EqualFold(k, bSetCookie) {
				return
			}
			ctx.Response.Header.SetBytesKV(k, v)
		})
		resp.Header.VisitAllCookie(func(_, v []byte) {
			ctx.Response.Header.AddBytesKV(bSetCookie, v)
		})

		fasthttp.ReleaseResponse(resp)
		return
	}

	ctx.SetStatusCode(502)
	ctx.SetBodyString("upstream unreachable")
}