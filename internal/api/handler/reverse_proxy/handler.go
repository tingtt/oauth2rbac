package reverseproxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"oauth2rbac/internal/acl"
	logutil "oauth2rbac/internal/api/handler/util/log"
	urlutil "oauth2rbac/internal/api/handler/util/url"
	"oauth2rbac/internal/util/slices"
	"strings"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
		revProxy.Director = setHeaderDirector(revProxy.Director, proxy.SetHeaders)
		revProxy.ErrorHandler = handleReverceProxyError
		proxies[proxy.ExternalURL.Host] = revProxy
	}
	return &handler{proxies, jwt, publicEndpoints}
}

func setHeaderDirector(defaultDirector func(*http.Request), headers map[string]string) func(req *http.Request) {
	if headers == nil {
		return defaultDirector
	}
	return func(req *http.Request) {
		defaultDirector(req)
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}
}

func handleReverceProxyError(res http.ResponseWriter, inReq *http.Request, err error) {
	inReqURL := urlutil.RequestURL(*inReq.URL, urlutil.WithRequest(inReq), urlutil.WithXForwardedHeaders(inReq.Header))
	slog.Error("http: proxy error", slog.String("host", inReqURL.Host), slog.String("error", err.Error()))
	res.WriteHeader(http.StatusBadGateway)
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqURL := urlutil.RequestURL(*req.URL, urlutil.WithRequest(req), urlutil.WithXForwardedHeaders(req.Header))
	res := &logutil.CustomResponseWriter{ResponseWriter: rw}
	logInfo := logutil.InfoLogger(reqURL, req.Method)

	if publicEndpoint(h.publicEndpoints, reqURL) {
		proxy, exists := h.proxies[reqURL.Host]
		if !exists {
			http.Error(res, "Not Found", http.StatusNotFound)
			logInfo(res, "proxy target not found")
			return
		}
		proxy.ServeHTTP(res, req)
		logInfo(res)
		return
	}

	allowed, err := checkScope(h.jwt.Decode, req, reqURL)
	if err != nil {
		redurectURL := loginURLWithRedirectURL(reqURL.String())
		http.Redirect(res, req, redurectURL, http.StatusFound)
		logInfo(res, redurectURL, "(request login)")
		return
	}
	if !allowed {
		http.Error(res, "Forbidden", http.StatusForbidden)
		logInfo(res, "no access to scope")
		return
	}

	proxy, exists := h.proxies[reqURL.Host]
	if !exists {
		http.Error(res, "Not Found", http.StatusNotFound)
		logInfo(res, "proxy target not found")
		return
	}
	proxy.ServeHTTP(res, req)
	logInfo(res)
}

func publicEndpoint(publicEndpoints []acl.Scope, reqURL url.URL) bool {
	return slices.Some(publicEndpoints, func(scope acl.Scope) bool {
		return strings.HasPrefix(reqURL.String(), string(scope))
	})
}

func checkScope(jwtDecode func(string) (jwt.Token, error), req *http.Request, reqURL url.URL) (allowed bool, _ error) {
	token, err := jwtDecode(jwtauth.TokenFromCookie(req))
	if err != nil {
		return false, err
	}
	whitelist, err := inspectWhitelistClaim(token.PrivateClaims())
	if err != nil {
		return false, err
	}
	allowed = slices.Some(whitelist, func(scope string) bool {
		return strings.HasPrefix(reqURL.String(), scope)
	})
	return allowed, nil
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
