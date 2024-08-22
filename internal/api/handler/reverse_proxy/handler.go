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
	"oauth2rbac/internal/util/tree"
	"strings"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Config struct {
	Proxies []Proxy
}

type Proxy struct {
	ExternalURL string
	Target      Target
	SetHeaders  map[string][]string
}

type Target struct {
	URL string
}

type handler struct {
	proxyMatchKeys  []string // need sorted in descending order by number of characters
	proxies         map[string]*httputil.ReverseProxy
	jwt             *jwtauth.JWTAuth
	publicEndpoints []acl.Scope
}

func NewReverseProxyHandler(config Config, jwt *jwtauth.JWTAuth, publicEndpoints []acl.Scope) *handler {
	proxies := make(map[string]*httputil.ReverseProxy, len(config.Proxies))
	var rootProxyMatchKeys *tree.Node[string]
	numberOfCharactersDescendinig := func(new, curr string) (isLeft bool) {
		return len(new) > len(curr)
	}
	for _, proxy := range config.Proxies {
		targetURL, _ := url.Parse(proxy.Target.URL)    // format already checked in loading manifest
		externalURL, _ := url.Parse(proxy.ExternalURL) // format already checked in loading manifest

		proxies[proxy.ExternalURL] = newSingleHostReverseProxy(targetURL, externalURL.Path, proxy.SetHeaders)
		rootProxyMatchKeys = tree.Insert(rootProxyMatchKeys, proxy.ExternalURL, numberOfCharactersDescendinig)
	}
	proxyMatchKeys := []string{}
	tree.InOrderTraversal(rootProxyMatchKeys, &proxyMatchKeys)
	return &handler{proxyMatchKeys, proxies, jwt, publicEndpoints}
}

func newSingleHostReverseProxy(targetURL *url.URL, matchPath string, headers map[string][]string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	rewriteRequestURL := proxy.Director
	proxy.Director = func(req *http.Request) {
		trimBaseURLWithTrailingSlashTarget(req, targetURL.Path, matchPath)
		rewriteRequestURL(req)
		setHeaders(req, headers)
	}
	proxy.ErrorHandler = handleReverceProxyError
	return proxy
}

func trimBaseURLWithTrailingSlashTarget(req *http.Request, targetPath, matchPath string) {
	if /* proxy target path has a trainig slash */ strings.HasSuffix(targetPath, "/") {
		baseURL := strings.TrimSuffix(matchPath, "/")
		req.URL.Path = strings.TrimPrefix(req.URL.Path, baseURL)
	}
}

func setHeaders(req *http.Request, headers map[string][]string) {
	for key, value := range headers {
		for _, vv := range value {
			req.Header.Set(key, vv)
		}
	}
}

func handleReverceProxyError(res http.ResponseWriter, inReq *http.Request, err error) {
	inReqURL := urlutil.RequestURL(*inReq.URL, urlutil.WithRequest(inReq), urlutil.WithXForwardedHeaders(inReq.Header))
	slog.Error("http: proxy error", slog.String("host", inReqURL.Host), slog.String("error", err.Error()))
	res.WriteHeader(http.StatusBadGateway)
}

func (h *handler) matchProxy(reqURL url.URL) (proxy *httputil.ReverseProxy) {
	key := slices.Find(h.proxyMatchKeys, func(uriPrefix string) bool {
		return strings.HasPrefix(reqURL.String(), uriPrefix)
	})
	if key == nil {
		return nil
	}
	return h.proxies[*key]
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqURL := urlutil.RequestURL(*req.URL, urlutil.WithRequest(req), urlutil.WithXForwardedHeaders(req.Header))
	res := &logutil.CustomResponseWriter{ResponseWriter: rw}
	logInfo := logutil.InfoLogger(reqURL, req.Method)

	if publicEndpoint(h.publicEndpoints, reqURL) {
		proxy := h.matchProxy(reqURL)
		if proxy == nil {
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

	proxy := h.matchProxy(reqURL)
	if proxy == nil {
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
