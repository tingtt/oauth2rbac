package reverseproxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
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
	requestURL := req.URL.Scheme + "://" + req.Host + req.URL.Path

	token, err := h.jwt.Decode(jwtauth.TokenFromCookie(req))
	if err != nil {
		fmt.Printf("failed to decode token from Cookie: %v\n", err)
		http.Redirect(res, req, loginURLWithRedirectURL(requestURL), http.StatusFound)
		return
	}
	claims := token.PrivateClaims()

	whitelistClaim, exist := claims["scopes_whitelist"]
	if !exist {
		fmt.Println("claim not found: scopes_whitelist")
		http.Redirect(res, req, loginURLWithRedirectURL(requestURL), http.StatusFound)
		return
	}
	whitelist, ok := whitelistClaim.([]interface{})
	if !ok {
		fmt.Println("invalid format claims: scopes_whitelist")
		http.Redirect(res, req, loginURLWithRedirectURL(requestURL), http.StatusFound)
		return
	}

	allowed := false
	for _, scope := range whitelist {
		if strings.HasPrefix(requestURL, fmt.Sprint(scope)) {
			allowed = true
			break
		}
	}
	if !allowed {
		http.Error(res, "Forbidden", http.StatusForbidden)
		return
	}

	if proxy, exists := h.proxies[req.Host]; exists {
		proxy.ServeHTTP(res, req)
	} else {
		http.Error(res, "Not Found", http.StatusNotFound)
	}
}

func loginURLWithRedirectURL(redirectURL string) string {
	return fmt.Sprintf(
		"/.auth/login?redirect_url=%s",
		url.QueryEscape(redirectURL),
	)
}
