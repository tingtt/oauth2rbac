package oauth2handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/tingtt/oauth2rbac/internal/acl"
	"github.com/tingtt/oauth2rbac/internal/api/handler/oauth2/ui"
	cookieutil "github.com/tingtt/oauth2rbac/internal/api/handler/util/cookie"
	logutil "github.com/tingtt/oauth2rbac/internal/api/handler/util/log"
	urlutil "github.com/tingtt/oauth2rbac/internal/api/handler/util/url"
	"github.com/tingtt/oauth2rbac/pkg/jwtclaims"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
)

func (h *handler) Callback(rw http.ResponseWriter, req *http.Request) {
	providerName := chi.URLParam(req, "oauthProvider")

	reqURL := urlutil.RequestURL(*req.URL, urlutil.WithRequest(req), urlutil.WithXForwardedHeaders(req.Header))
	res, logInfo := logutil.InfoLogger(reqURL, req.Method, rw, req)

	oauth2, supported := h.oauth2[providerName]
	if !supported {
		http.Redirect(res, req, fmt.Sprintf("/.auth/login/%s", req.URL.RawQuery), http.StatusTemporaryRedirect)
		logInfo("unsupported oauth2 provider")
		return
	}

	redirectURL := reqURL.Scheme + "://" + reqURL.Host + "/.auth/" + providerName + "/callback"

	ctx := context.Background()
	oauth2Token, err := oauth2.Exchange(ctx, req.FormValue("code"), redirectURL)
	if err != nil {
		slog.Error("failed to exchange code to token", slog.String("provider", providerName), slog.String("error", err.Error()))
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(clientSideRedirectConfirmErrorHTML(
			/* request redirect to */ fmt.Sprintf("/.auth/login/%s", req.URL.RawQuery),
			/* cause */ "failed to exchange code to token",
		)))
		logInfo("failed to exchange code to token", slog.String("provider", providerName), slog.String("error", err.Error()))
		return
	}
	oauth2ProviderUsername, emails, err := oauth2.GetUserInfo(ctx, oauth2Token)
	if err != nil {
		slog.Error("failed to get userinfo", slog.String("provider", providerName), slog.String("error", err.Error()))
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(clientSideRedirectConfirmErrorHTML(
			/* request redirect to */ fmt.Sprintf("/.auth/login/%s", req.URL.RawQuery),
			/* cause */ "failed to get userinfo",
		)))
		logInfo("failed to get userinfo", slog.String("provider", providerName), slog.String("error", err.Error()))
		return
	}

	allowedScopes := []acl.Scope{}
	for _, scope := range h.scope.Get(emails) {
		externalURL, err := url.Parse(scope.ExternalURL)
		if err != nil {
			slog.Error(fmt.Errorf("failed to parse external url: %w", err).Error())
			res.WriteHeader(http.StatusInternalServerError)
			res.Write([]byte(clientSideRedirectConfirmErrorHTML(
				/* request redirect to */ fmt.Sprintf("/.auth/login/%s", req.URL.RawQuery),
				/* cause */ "failed to parse external url",
			)))
			logInfo("failed to parse external url")
			return
		}
		if /* same origin */ reqURL.Scheme == externalURL.Scheme && reqURL.Host == externalURL.Host {
			exists := false
			for i, allowedScope := range allowedScopes {
				if /* same scope */ allowedScope.ExternalURL == scope.ExternalURL {
					allowedScopes[i].Methods = append(allowedScopes[i].Methods, scope.Methods...)
					allowedScopes[i].Methods = slices.Compact(allowedScopes[i].Methods)
					exists = true
					break
				}
			}
			if !exists {
				allowedScopes = append(allowedScopes, scope)
			}
		}
	}

	c := JWTClaims{
		AllowedScopes: allowedScopes,
		Emails:        emails,
	}
	switch providerName {
	case "github":
		c.GitHub = &jwtclaims.ClaimsGitHub{ID: oauth2ProviderUsername}
	case "google":
		c.Google = &jwtclaims.ClaimsGoogle{Username: oauth2ProviderUsername}
	}
	claim := c.MapCollect()
	jwtauth.SetIssuedNow(claim)
	jwtauth.SetExpiryIn(claim, time.Hour)
	_, tokenStr, err := h.jwt.Encode(claim)
	if err != nil {
		slog.Error(fmt.Errorf("failed to encode jwt token: %w", err).Error())
		res.WriteHeader(http.StatusInternalServerError)
		res.Write([]byte(clientSideRedirectConfirmErrorHTML(
			/* request redirect to */ fmt.Sprintf("/.auth/login/%s", req.URL.RawQuery),
			/* cause */ "failed to encode jwt token",
		)))
		logInfo("failed to encode jwt token")
		return
	}

	h.cookie.SetJWT(res, tokenStr)
	cookieRedirectPath, err := req.Cookie(cookieutil.COOKIE_KEY_REDIRECT_URL_FOR_AFTER_LOGIN)
	if /* cookie redirect url not received */ err != nil {
		html := ui.ClientSideRedirect("/")
		err = html.Render(rw)
		if err != nil {
			slog.Error(fmt.Errorf("failed render html: %w", err).Error())
			http.Error(res, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		logInfo("signed-in", slog.Bool("cookie_redirect_url_found", false))
		return
	}
	html := ui.ClientSideRedirect(cookieRedirectPath.Value)
	err = html.Render(rw)
	if err != nil {
		slog.Error(fmt.Errorf("failed render html: %w", err).Error())
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	logInfo("signed-in", slog.Bool("cookie_redirect_url_found", true))
}

func clientSideRedirectConfirmErrorHTML(url string, cause string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Error occured</title>
</head>
<body>
		<font color="red">%s</font>
		<br />
    <p><a href="%s">login</a>.</p>
</body>
</html>
`, cause, url)
}
