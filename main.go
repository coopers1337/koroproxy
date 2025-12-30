package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var timeout, _ = strconv.Atoi(os.Getenv("TIMEOUT"))
var retries, _ = strconv.Atoi(os.Getenv("RETRIES"))
var port = os.Getenv("PORT")
var client *fasthttp.Client

func main() {
	client = &fasthttp.Client{
		ReadTimeout: time.Duration(timeout) * time.Second,
		MaxIdleConnDuration: 60 * time.Second,
	}

	if err := fasthttp.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

func handler(ctx *fasthttp.RequestCtx) {
	if key, ok := os.LookupEnv("KEY"); ok {
		if string(ctx.Request.Header.Peek("PROXYKEY")) != key {
			ctx.SetStatusCode(407)
			ctx.SetBodyString("Missing or invalid PROXYKEY header.")
			return
		}
	}

	resp := forward(ctx, 1)
	defer fasthttp.ReleaseResponse(resp)

	ctx.SetStatusCode(resp.StatusCode())
	ctx.SetBody(resp.Body())
	resp.Header.VisitAll(func(k, v []byte) {
		ctx.Response.Header.SetBytesKV(k, v)
	})
}

func forward(ctx *fasthttp.RequestCtx, attempt int) *fasthttp.Response {
	if attempt > retries {
		r := fasthttp.AcquireResponse()
		r.SetStatusCode(502)
		r.SetBodyString("Proxy failed to connect.")
		return r
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethodBytes(ctx.Method())

	uri := ctx.Request.URI()
	raw := strings.TrimPrefix(string(uri.Path()), "/")

	var target string
	var host string

	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		target = raw
	} else if strings.HasPrefix(raw, "apisite/") {
		target = "https://apisite.pekora.zip/" + strings.TrimPrefix(raw, "apisite/")
	} else {
		parts := strings.SplitN(raw, "/", 2)
		if len(parts) < 2 {
			r := fasthttp.AcquireResponse()
			r.SetStatusCode(400)
			r.SetBodyString("Invalid URL format.")
			return r
		}

		if strings.Contains(parts[0], ".") {
			target = "https://" + raw
		} else {
			target = "https://" + parts[0] + ".pekora.zip/" + parts[1]
		}
	}

	if len(uri.QueryString()) > 0 {
		target += "?" + string(uri.QueryString())
	}

	req.SetRequestURI(target)
	req.SetBody(ctx.Request.Body())

	u := strings.Split(strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://"), "/")
	if len(u) > 0 {
		host = u[0]
	}

	ctx.Request.Header.VisitAll(func(k, v []byte) {
		h := strings.ToLower(string(k))
		if h == "host" || h == "connection" || h == "content-length" || h == "accept-encoding" {
			return
		}
		req.Header.SetBytesKV(k, v)
	})

	req.Header.Set("Host", host)
	req.Header.Set("User-Agent", "KoroProxy")
	req.Header.Set("x-csrf-token", "KoroProxy")

	resp := fasthttp.AcquireResponse()
	if err := client.Do(req, resp); err != nil {
		fasthttp.ReleaseResponse(resp)
		return forward(ctx, attempt+1)
	}

	return resp
}
