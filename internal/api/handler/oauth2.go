package handler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"oauth2rbac/internal/oauth2"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-xmlfmt/xmlfmt"
)

func (h *handler) SelectOAuthProvider(w http.ResponseWriter, r *http.Request) {
	htmlFormat := `<!DOCTYPE html><html><body>%s</body></html>`
	body := ""
	for providerName := range oauth2.Providers {
		body += fmt.Sprintf(`<div><a href="/.auth/%s/login?%s">%s</a></div>`, providerName, r.URL.RawQuery, providerName)
	}
	w.Write([]byte(xmlfmt.FormatXML(fmt.Sprintf(htmlFormat, body), "\t", "  ")))
}

func (h *handler) OAuthLogin(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "oauthProvider")
	oauth2, supported := h.oauth2[providerName]
	if !supported {
		http.Redirect(w, r, "/.auth/login", http.StatusTemporaryRedirect)
	}
	redirectURL := oauth2.AuthCodeURL(r.URL.Query().Get("redirect_url"))
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func (h *handler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "oauthProvider")
	oauth2, supported := h.oauth2[providerName]
	if !supported {
		http.Redirect(w, r, "/.auth/login", http.StatusTemporaryRedirect)
	}

	ctx := context.Background()

	email, err := emailFromCode(ctx, oauth2, r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// TODO: verify email and roles and generate token for Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		Domain:   "",
		Expires:  time.Now().Add(time.Hour),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	// TODO: redirect to redirect_url
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func emailFromCode(ctx context.Context, oauth2 oauth2.Service, code string) ([]string, error) {
	token, err := oauth2.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	return oauth2.GetEmail(ctx, token)
}
