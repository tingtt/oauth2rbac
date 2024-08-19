package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"oauth2rbac/internal/acl"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
)

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	providerName := chi.URLParam(r, "oauthProvider")

	oauth2, supported := h.OAuth2[providerName]
	if !supported {
		http.Redirect(w, r, fmt.Sprintf("/.auth/login/%s", r.URL.RawQuery), http.StatusTemporaryRedirect)
		return
	}

	oauth2Token, err := oauth2.Exchange(ctx, r.FormValue("code"), "http://"+r.Host+r.URL.Path)
	if err != nil {
		fmt.Printf("failed to exchange code to token (provider: %s): %v\n", providerName, err)
		http.Redirect(w, r, fmt.Sprintf("/.auth/login/%s", r.URL.RawQuery), http.StatusTemporaryRedirect)
		return
	}
	emails, err := oauth2.GetEmail(ctx, oauth2Token)
	if err != nil {
		fmt.Printf("failed to get email (%s): %v\n", providerName, err)
		http.Redirect(w, r, fmt.Sprintf("/.auth/login/%s", r.URL.RawQuery), http.StatusTemporaryRedirect)
		return
	}
	scopes := scopesFromEmails(emails, h.Whiltelist)
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

func scopesFromEmails(emails []string, whiltelist acl.Pool) []acl.Scope {
	scopeMap := make(map[acl.Scope]bool, 0)
	for _, email := range emails {
		if scopes, allowed := whiltelist[acl.Email(email)]; allowed {
			for _, scope := range scopes {
				scopeMap[scope] = true
			}
		}
	}
	keys := make([]acl.Scope, 0, len(scopeMap))
	for s := range scopeMap {
		keys = append(keys, s)
	}
	return keys
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
