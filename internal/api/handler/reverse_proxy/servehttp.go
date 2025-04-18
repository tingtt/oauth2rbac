package reverseproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	oauth2handler "github.com/tingtt/oauth2rbac/internal/api/handler/oauth2"
	logutil "github.com/tingtt/oauth2rbac/internal/api/handler/util/log"
	urlutil "github.com/tingtt/oauth2rbac/internal/api/handler/util/url"
	"github.com/tingtt/oauth2rbac/pkg/jwtclaims"

	jwtmiddleware "github.com/tingtt/oauth2rbac/internal/api/middleware/jwt"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqURL := urlutil.RequestURL(
		*req.URL,
		urlutil.WithRequest(req),
		urlutil.WithHostHeader(req.Header),
		urlutil.WithXForwardedHeaders(req.Header),
	)
	res, logInfo := logutil.InfoLogger(reqURL, req.Method, rw, req)

	if !h.acl.LoginRequired(&reqURL, req.Method) {
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

	token, err := h.jwt.Decode(tokenStrFromRequest(req))
	if /* unauthorized or token expired */ err != nil {
		redirectURL := loginURLWithRedirectURL(reqURL.String())
		h.cookie.SetRedirectURLForAfterLogin(res, reqURL.String())
		http.Redirect(res, req, redirectURL, http.StatusFound)
		logInfo("request login", slog.String("reason", err.Error()))
		if !errors.Is(err, jwt.ErrTokenExpired()) {
			slog.Error("failed to decode JWT", slog.String("err", err.Error()))
			slog.Debug("failed to decode JWT", slog.String("jwt", tokenStrFromRequest(req)), slog.String("err", err.Error()))
		}
		return
	}

	claimsJSON, _ := json.Marshal(token.PrivateClaims())
	jwtPrivateClaims, err := jwtclaims.Unmarshal(claimsJSON)
	if err != nil {
		http.Error(res, "System Error. Please contact administrator.", http.StatusInternalServerError)
		logInfo("internal error", slog.String("err", err.Error()))
		slog.Error("failed to unmarshal token claims", slog.String("err", err.Error()))
		slog.Debug("failed to unmarshal token claims", slog.String("jwt", tokenStrFromRequest(req)), slog.String("err", err.Error()))
		return
	}

	allowedScopes := jwtPrivateClaims.AllowedScopes
	roles := jwtPrivateClaims.Roles
	if /* acl config reloaded */ token.IssuedAt().Before(*h.issuedJWTAvailableSince) {
		// load acl config
		allowedScopes = h.acl.AllowedScopes(&reqURL, jwtPrivateClaims.Email)
		roles = h.acl.Roles(&reqURL, jwtPrivateClaims.Email)
	}

	if /* forbidden */ !allowedScopes.Match(reqURL.Path, req.Method) {
		http.Error(res, "Forbidden", http.StatusForbidden)
		logInfo("no access to the scope")
		return
	}

	newPrivateClaims := oauth2handler.JWTClaims(jwtPrivateClaims)
	newPrivateClaims.AllowedScopes = allowedScopes
	newPrivateClaims.Roles = roles
	tokenExpiryIn := jwtmiddleware.DefaultExpiry
	originConfig := h.acl.OriginConfig(&reqURL)
	if originConfig != nil {
		if originConfig.JWTExpiryIn != nil {
			tokenExpiryIn = time.Duration(*originConfig.JWTExpiryIn)
		}
	}
	_, newTokenStr, err := renewJWT(newPrivateClaims.MapCollect(), h.jwt.Encode, tokenExpiryIn)
	if err != nil {
		slog.Error("failed to renew jwt token", slog.String("err", err.Error()))
		slog.Debug("failed to renew jwt token", slog.String("jwt", tokenStrFromRequest(req)), slog.String("err", err.Error()))
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

func tokenStrFromRequest(req *http.Request) string {
	authorizationToken, _ := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if authorizationToken != "" {
		return authorizationToken
	}
	return jwtauth.TokenFromCookie(req)
}

func loginURLWithRedirectURL(redirectURL string) string {
	return fmt.Sprintf(
		"/.auth/login?redirect_url=%s",
		url.QueryEscape(redirectURL),
	)
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
