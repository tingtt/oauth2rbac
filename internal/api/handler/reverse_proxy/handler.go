package reverseproxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"oauth2rbac/internal/acl"
	urlutil "oauth2rbac/internal/api/handler/util/url"
	"oauth2rbac/internal/util/slices"
	"strings"

	"github.com/go-chi/jwtauth/v5"
)

type Config struct {
	Proxies []Proxy
}

type Proxy struct {
	ExternalURL *url.URL
	Target      Host
	SetHeaders  map[string]string
}

type Host struct {
	URL *url.URL
}

type handler struct {
	proxies         map[string]*httputil.ReverseProxy
	jwt             *jwtauth.JWTAuth
	publicEndpoints []acl.Scope
}

func NewReverseProxyHandler(config Config, jwt *jwtauth.JWTAuth, publicEndpoints []acl.Scope) *handler {
	proxies := make(map[string]*httputil.ReverseProxy, len(config.Proxies))
	for _, proxy := range config.Proxies {
		revProxy := httputil.NewSingleHostReverseProxy(proxy.Target.URL)
		revProxy.Director = setHeaderDirector(proxy.SetHeaders)
		proxies[proxy.ExternalURL.Host] = revProxy
	}
	return &handler{proxies, jwt, publicEndpoints}
}

func setHeaderDirector(headers map[string]string) func(req *http.Request) {
	if headers == nil {
		return nil
	}
	return func(req *http.Request) {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}
}

func (h *handler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	reqURL := urlutil.RequestURL(*req.URL, urlutil.WithRequest(req), urlutil.WithXForwardedHeaders(req.Header))

	publicEndpoint := slices.Some(h.publicEndpoints, func(scope acl.Scope) bool {
		return strings.HasPrefix(reqURL.String(), string(scope))
	})
	if publicEndpoint {
		proxy, exists := h.proxies[reqURL.Host]
		if !exists {
			http.Error(res, "Not Found", http.StatusNotFound)
			return
		}
		proxy.ServeHTTP(res, req)
		return
	}

	token, err := h.jwt.Decode(jwtauth.TokenFromCookie(req))
	if err != nil {
		http.Redirect(res, req, loginURLWithRedirectURL(reqURL.String()), http.StatusFound)
		return
	}

	whitelist, err := inspectWhitelistClaim(token.PrivateClaims())
	if err != nil {
		slog.Error(err.Error())
		http.Redirect(res, req, loginURLWithRedirectURL(reqURL.String()), http.StatusFound)
		return
	}

	allowed := slices.Some(whitelist, func(scope string) bool {
		return strings.HasPrefix(reqURL.String(), scope)
	})
	if !allowed {
		http.Error(res, "Forbidden", http.StatusForbidden)
		return
	}

	proxy, exists := h.proxies[req.Host]
	if !exists {
		http.Error(res, "Not Found", http.StatusNotFound)
		return
	}
	proxy.ServeHTTP(res, req)
}

func loginURLWithRedirectURL(redirectURL string) string {
	return fmt.Sprintf(
		"/.auth/login?redirect_url=%s",
		url.QueryEscape(redirectURL),
	)
}

func inspectWhitelistClaim(claims map[string]interface{}) ([]string, error) {
	whitelistClaim, exist := claims["scopes_whitelist"]
	if !exist {
		return nil, errors.New("claim not found: scopes_whitelist")
	}
	whitelist, ok := whitelistClaim.([]interface{})
	if !ok {
		return nil, errors.New("invalid format claims: scopes_whitelist")
	}
	return slices.Map(whitelist, func(item interface{}) string {
		return fmt.Sprint(item)
	}), nil
}
