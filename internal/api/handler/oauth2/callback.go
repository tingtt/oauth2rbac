package oauth2handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	cookieutil "oauth2rbac/internal/api/handler/util/cookie"
	urlutil "oauth2rbac/internal/api/handler/util/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
)

func (h *handler) Callback(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	providerName := chi.URLParam(req, "oauthProvider")

	oauth2, supported := h.oAuth2[providerName]
	if !supported {
		http.Redirect(w, req, fmt.Sprintf("/.auth/login/%s", req.URL.RawQuery), http.StatusTemporaryRedirect)
		return
	}

	reqURL := urlutil.RequestURL(*req.URL, urlutil.WithRequest(req), urlutil.WithXForwardedHeaders(req.Header))
	redirectURL := reqURL.Scheme + "://" + reqURL.Host + "/.auth/" + providerName + "/callback"

	oauth2Token, err := oauth2.Exchange(ctx, req.FormValue("code"), redirectURL)
	if err != nil {
		fmt.Printf("failed to exchange code to token (provider: %s): %v\n", providerName, err)
		http.Redirect(w, req, fmt.Sprintf("/.auth/login/%s", req.URL.RawQuery), http.StatusTemporaryRedirect)
		return
	}
	emails, err := oauth2.GetEmail(ctx, oauth2Token)
	if err != nil {
		fmt.Printf("failed to get email (%s): %v\n", providerName, err)
		http.Redirect(w, req, fmt.Sprintf("/.auth/login/%s", req.URL.RawQuery), http.StatusTemporaryRedirect)
		return
	}
	scopes := h.scope.Get(emails)
	if len(scopes) == 0 {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Forbidden"))
		return
	}

	claim := map[string]interface{}{
		"scopes_whitelist": scopes,
	}
	jwtauth.SetIssuedNow(claim)
	jwtauth.SetExpiryIn(claim, time.Hour)
	_, tokenStr, err := h.JWTAuth.Encode(claim)
	if err != nil {
		slog.Error(fmt.Errorf("failed to encode jwt token: %w", err).Error())
		return
	}

	h.cookieController.SetJWT(w, tokenStr)
	fmt.Printf("received cookie: %v\n", len(req.Cookies()))
	for _, cookie := range req.Cookies() {
		fmt.Printf("received cookie: %v\t%v\n", cookie.Name, cookie.Value)
	}
	cookieRedirectPath, err := req.Cookie(cookieutil.COOKIE_KEY_REDIRECT_URL_FOR_AFTER_LOGIN)
	if /* cookie redirect url not received */ err != nil {
		slog.Error(err.Error())
		w.Write([]byte(clientSideRedirectHTML("/")))
		return
	}
	slog.Info(cookieRedirectPath.Value)
	w.Write([]byte(clientSideRedirectHTML(cookieRedirectPath.Value)))
}

func clientSideRedirectHTML(url string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0; url=%s">
    <script type="text/javascript">
        window.location.href = "%s";
    </script>
    <title>Redirecting...</title>
</head>
<body>
    <p>If you are not redirected automatically, follow this <a href="%s">link</a>.</p>
</body>
</html>
`, url, url, url)
}
