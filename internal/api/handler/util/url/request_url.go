package urlutil

import (
	"net/http"
	"net/url"
)

func RequestURL(req *http.Request, xForwardedScheme, xForwardedHost, xForwardedPort string) url.URL {
	reqURL := *req.URL
	if req.URL.Scheme == "" {
		reqURL.Scheme = "http"
	}
	if xForwardedScheme != "" {
		reqURL.Scheme = xForwardedScheme
	}
	if xForwardedHost != "" {
		if /* not omitable port */ xForwardedPort != "" && xForwardedPort != "80" && xForwardedPort != "443" {
			reqURL.Host = xForwardedHost + ":" + xForwardedPort
		} else {
			reqURL.Host = xForwardedHost
		}
	} else {
		reqURL.Host = req.Host
	}
	reqURL.RawPath = req.RequestURI
	return reqURL
}
