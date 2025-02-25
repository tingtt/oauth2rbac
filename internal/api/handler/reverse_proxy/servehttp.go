package reverseproxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"oauth2rbac/internal/acl"
	logutil "oauth2rbac/internal/api/handler/util/log"
	urlutil "oauth2rbac/internal/api/handler/util/url"
	"oauth2rbac/internal/util/slices"
	"sort"
	"strings"
	"time"

	jwtmiddleware "oauth2rbac/internal/api/middleware/jwt"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqURL := urlutil.RequestURL(*req.URL, urlutil.WithRequest(req), urlutil.WithXForwardedHeaders(req.Header))
	res, logInfo := logutil.InfoLogger(reqURL, req.Method, rw, req)

	if publicEndpoint(h.publicEndpoints, reqURL, req.Method) {
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

	token, err := h.jwt.Decode(jwtauth.TokenFromCookie(req))
	if /* unauthorized */ err != nil {
		redirectURL := loginURLWithRedirectURL(reqURL.String())
		h.cookie.SetRedirectURLForAfterLogin(res, reqURL.String())
		http.Redirect(res, req, redirectURL, http.StatusFound)
		logInfo("request login", slog.String("err", err.Error()))
		return
	}

	scope, err := checkScope(token, reqURL, req.Method)
	if err != nil {
		http.Error(res, "System Error. Please contact administrator.", http.StatusInternalServerError)
		logInfo("internal error", slog.String("err", err.Error()))
		return
	}
	if scope == nil {
		http.Error(res, "Forbidden", http.StatusForbidden)
		logInfo("no access to the scope")
		return
	}

	tokenExpiryIn := jwtmiddleware.DefaultExpiry
	if scope.JWTExpiryIn != nil {
		tokenExpiryIn = *scope.JWTExpiryIn
	}
	_, newTokenStr, err := renewJWT(token.PrivateClaims(), h.jwt.Encode, tokenExpiryIn)
	if err != nil {
		slog.Error(fmt.Errorf("failed to renew jwt token: %w", err).Error())
		res.WriteHeader(http.StatusInternalServerError)
		// TODO: error view
		logInfo("failed to renew jwt token")
		return
	}
	h.cookie.SetJWT(res, newTokenStr)

	proxy := h.matchProxy(reqURL)
	if proxy == nil {
		http.Error(res, "Not Found", http.StatusNotFound)
		logInfo("proxy target not found")
		return
	}
	proxy.ServeHTTP(res, req)
	logInfo("proxy successful (authorized)")
}

func publicEndpoint(publicEndpoints []acl.Scope, reqURL url.URL, reqMethod string) bool {
	return slices.Some(publicEndpoints, func(scope acl.Scope) bool {
		return strings.HasPrefix(reqURL.String(), scope.ExternalURL) &&
			slices.Some(scope.Methods, func(method string) bool {
				return method == reqMethod || method == "*"
			})
	})
}

func checkScope(token jwt.Token, reqURL url.URL, reqMethod string) (*acl.Scope, error) {
	allowlist, err := inspectallowlistClaim(token.PrivateClaims())
	if err != nil {
		return nil, err
	}
	return slices.Find(allowlist, func(scope acl.Scope) bool {
		return strings.HasPrefix(reqURL.String(), scope.ExternalURL) &&
			slices.Some(scope.Methods, func(method string) bool {
				return method == reqMethod || method == "*"
			})
	}), nil
}

func loginURLWithRedirectURL(redirectURL string) string {
	return fmt.Sprintf(
		"/.auth/login?redirect_url=%s",
		url.QueryEscape(redirectURL),
	)
}

func inspectallowlistClaim(claims map[string]interface{}) ([]acl.Scope, error) {
	allowlistClaim, exist := claims["allowed_scopes"]
	if !exist {
		return nil, errors.New("claim not found: allowed_scopes")
	}
	allowlist, ok := allowlistClaim.([]interface{})
	if !ok {
		return nil, errors.New("invalid format claims: allowed_scopes")
	}
	allowedScopes, err := slices.MapE(allowlist, func(item interface{}) (acl.Scope, error) {
		scopeMap, ok := item.(map[string]interface{})
		if !ok {
			return acl.Scope{}, errors.New("invalid format claims: scopes_allowlist[i]")
		}
		externalURL, ok := scopeMap["ExternalURL"].(string)
		if !ok {
			return acl.Scope{}, errors.New("invalid format claims: scopes_allowlist[i].ExternalURL")
		}
		methodsI, ok := scopeMap["Methods"].([]interface{})
		if !ok {
			return acl.Scope{}, errors.New("invalid format claims: scopes_allowlist[i].Methods")
		}
		methods, err := slices.MapE(methodsI, func(methodI interface{}) (string, error) {
			method, ok := methodI.(string)
			if !ok {
				return "", errors.New("invalid format claims: scopes_allowlist[i].Methods[i]")
			}
			return method, nil
		})
		if err != nil {
			return acl.Scope{}, err
		}
		return acl.Scope{ExternalURL: externalURL, Methods: methods}, nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(allowedScopes, func(i, j int) bool {
		return len(allowedScopes[i].ExternalURL) > len(allowedScopes[j].ExternalURL)
	})
	return allowedScopes, nil
}

func renewJWT(
	claim map[string]interface{},
	encodeFunc func(claims map[string]interface{}) (t jwt.Token, tokenString string, err error),
	expiryIn time.Duration,
) (t jwt.Token, tokenString string, err error) {
	jwtauth.SetIssuedNow(claim)
	jwtauth.SetExpiryIn(claim, expiryIn)
	t, str, err := encodeFunc(claim)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode jwt token: %w", err)
	}
	return t, str, nil
}
