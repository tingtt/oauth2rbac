package reverseproxy

import (
	"net/http/httputil"
	"net/url"
	"oauth2rbac/internal/util/slices"
	"strings"
)

func (h *handler) matchProxy(reqURL url.URL) (proxy *httputil.ReverseProxy) {
	key := slices.Find(h.proxyMatchKeys, func(uriPrefix string) bool {
		return strings.HasPrefix(reqURL.String(), uriPrefix)
	})
	if key == nil {
		return nil
	}
	return h.proxies[*key]
}
