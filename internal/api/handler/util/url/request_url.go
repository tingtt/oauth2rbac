package urlutil

import (
	"net/http"
	"net/url"
)

type option struct {
	complementWithRequest           func(*url.URL)
	complementWithXForwardedHeaders func(*url.URL)
}
type optionApplier func(*option)

func WithRequest(req *http.Request) optionApplier {
	return func(o *option) {
		o.complementWithRequest = func(u *url.URL) {
			if u.Scheme == "" {
				if req.TLS == nil {
					u.Scheme = "http"
				} else {
					u.Scheme = "https"
				}
			}
			if u.Host == "" {
				u.Host = req.Host
			}
			if u.RawPath == "" {
				u.RawPath = req.RequestURI
			}
		}
	}
}

func WithXForwardedHeaders(header http.Header) optionApplier {
	xForwardedScheme := header.Get("X-Forwarded-Scheme")
	xForwardedHost := header.Get("X-Forwarded-Host")
	xForwardedPort := header.Get("X-Forwarded-Port")

	return func(o *option) {
		o.complementWithXForwardedHeaders = func(url *url.URL) {
			if xForwardedScheme != "" {
				url.Scheme = xForwardedScheme
			}
			if xForwardedHost != "" {
				if /* not omitable port */ xForwardedPort != "" && xForwardedPort != "80" && xForwardedPort != "443" {
					url.Host = xForwardedHost + ":" + xForwardedPort
				} else {
					url.Host = xForwardedHost
				}
			}
		}
	}
}

func RequestURL(reqURL url.URL, options ...optionApplier) url.URL {
	option := option{}
	for _, apply := range options {
		apply(&option)
	}

	if option.complementWithRequest != nil {
		option.complementWithRequest(&reqURL)
	}
	if option.complementWithXForwardedHeaders != nil {
		option.complementWithXForwardedHeaders(&reqURL)
	}

	return reqURL
}
