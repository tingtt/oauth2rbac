package reverseproxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"oauth2rbac/internal/acl"
	cookieutil "oauth2rbac/internal/api/handler/util/cookie"
	handleroption "oauth2rbac/internal/api/handler/util/option"
	urlutil "oauth2rbac/internal/api/handler/util/url"
	"oauth2rbac/internal/util/options"
	"oauth2rbac/internal/util/tree"
	"strings"

	"github.com/go-chi/jwtauth/v5"
)

type handler struct {
	proxyMatchKeys   []string // need sorted in descending order by number of characters
	proxies          map[string]*httputil.ReverseProxy
	jwt              *jwtauth.JWTAuth
	publicEndpoints  []acl.Scope
	cookieController cookieutil.Controller
}

func NewReverseProxyHandler(config Config, jwtAuth *jwtauth.JWTAuth, publicEndpoints []acl.Scope, _options ...handleroption.Applier) *handler {
	option := options.Create(_options...)

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
	return &handler{
		proxyMatchKeys,
		proxies,
		jwtAuth,
		publicEndpoints,
		cookieutil.NewController(option.UsingTLS),
	}
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
