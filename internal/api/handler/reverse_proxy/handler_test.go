package reverseproxy

import (
	handleroption "oauth2rbac/internal/api/handler/util/option"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewReverseProxyHandler(t *testing.T) {
	t.Parallel()

	config := Config{Proxies: []Proxy{
		{ExternalURL: "http://example.com/"},
		{ExternalURL: "http://example.com/base/"},
		{ExternalURL: "http://example.com/-/healthz"},
	}}
	handlerOption, _ := handleroption.New(handleroption.WithScope(nil), handleroption.WithSecureCookie(false))

	t.Run("proxyMatchKeys may sorted descending order by number of characters", func(t *testing.T) {
		t.Parallel()
		h := NewReverseProxyHandler(config, handlerOption)

		assert.Equal(t, h.proxyMatchKeys, []string{
			"http://example.com/-/healthz",
			"http://example.com/base/",
			"http://example.com/",
		})

		proxyMatchKeys := make([]string, 0, len(h.proxies))
		for k := range h.proxies {
			proxyMatchKeys = append(proxyMatchKeys, k)
		}
		assert.ElementsMatch(t, h.proxyMatchKeys, proxyMatchKeys)
	})
}
