package oauth2

import (
	"context"
	"fmt"
	"net/http"
	urlutil "oauth2rbac/internal/api/handler/util/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
)

func (h *Handler) Callback(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	providerName := chi.URLParam(req, "oauthProvider")

	oauth2, supported := h.OAuth2[providerName]
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
	scopes := h.Scope.Get(emails)
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
	_, tokenStr, err := h.JWT.Encode(claim)
	if err != nil {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    tokenStr,
		Path:     "/",
		Domain:   "",
		MaxAge:   int(time.Hour / time.Second),
		Secure:   false,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	w.Write([]byte(clientSideRedirectHTML("/")))
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
