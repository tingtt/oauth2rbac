package reverseproxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
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
}

type Host struct {
	URL *url.URL
}

type handler struct {
	proxies map[string]*httputil.ReverseProxy
	jwt     *jwtauth.JWTAuth
}

func NewReverseProxyHandler(config Config, jwt *jwtauth.JWTAuth) *handler {
	proxies := make(map[string]*httputil.ReverseProxy, len(config.Proxies))
	for _, host := range config.Proxies {
		proxy := httputil.NewSingleHostReverseProxy(host.Target.URL)
		proxies[host.ExternalURL.Host] = proxy
	}
	return &handler{proxies, jwt}
}

func (h *handler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	requestURL := req.URL.Scheme + "://" + req.Host + req.RequestURI

	token, err := h.jwt.Decode(jwtauth.TokenFromCookie(req))
	if err != nil {
		http.Redirect(res, req, loginURLWithRedirectURL(requestURL), http.StatusFound)
		return
	}

	whitelist, err := inspectWhitelistClaim(token.PrivateClaims())
	if err != nil {
		slog.Error(err.Error())
		http.Redirect(res, req, loginURLWithRedirectURL(requestURL), http.StatusFound)
		return
	}

	allowed := slices.Some(whitelist, func(scope string) bool {
		return strings.HasPrefix(requestURL, scope)
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
