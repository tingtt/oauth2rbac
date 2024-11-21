package reverseproxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"oauth2rbac/internal/acl"
	logutil "oauth2rbac/internal/api/handler/util/log"
	urlutil "oauth2rbac/internal/api/handler/util/url"
	"oauth2rbac/internal/util/slices"
	"strings"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqURL := urlutil.RequestURL(*req.URL, urlutil.WithRequest(req), urlutil.WithXForwardedHeaders(req.Header))
	res, logInfo := logutil.InfoLogger(reqURL, req.Method, rw, req)

	if publicEndpoint(h.publicEndpoints, reqURL) {
		proxy := h.matchProxy(reqURL)
		if proxy == nil {
			http.Error(res, "Not Found", http.StatusNotFound)
			logInfo("proxy target not found")
			return
		}
		proxy.ServeHTTP(res, req)
		logInfo("proxy successful (public)")
		return
	}

	allowed, err := checkScope(h.jwt.Decode, req, reqURL)
	if /* unauthorized */ err != nil {
		redirectURL := loginURLWithRedirectURL(reqURL.String())
		h.cookieController.SetRedirectURLForAfterLogin(res, reqURL.String())
		http.Redirect(res, req, redirectURL, http.StatusFound)
		logInfo("request login")
		return
	}
	if !allowed {
		http.Error(res, "Forbidden", http.StatusForbidden)
		logInfo("no access to the scope")
		return
	}

	proxy := h.matchProxy(reqURL)
	if proxy == nil {
		http.Error(res, "Not Found", http.StatusNotFound)
		logInfo("proxy target not found")
		return
	}
	proxy.ServeHTTP(res, req)
	logInfo("proxy successful (authorized)")
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
	allowlist, err := inspectallowlistClaim(token.PrivateClaims())
	if err != nil {
		return false, err
	}
	allowed = slices.Some(allowlist, func(scope string) bool {
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

func inspectallowlistClaim(claims map[string]interface{}) ([]string, error) {
	allowlistClaim, exist := claims["scopes_allowlist"]
	if !exist {
		return nil, errors.New("claim not found: scopes_allowlist")
	}
	allowlist, ok := allowlistClaim.([]interface{})
	if !ok {
		return nil, errors.New("invalid format claims: scopes_allowlist")
	}
	return slices.Map(allowlist, func(item interface{}) string {
		return fmt.Sprint(item)
	}), nil
}
