package oauth2

import (
	"fmt"
	"net/http"
	"path"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "oauthProvider")
	oauth2, supported := h.OAuth2[providerName]
	if !supported {
		http.Redirect(w, r, "/.auth/login", http.StatusTemporaryRedirect)
	}

	callbackURL := fmt.Sprintf("http://%s%s/callback", r.Host, path.Dir(r.URL.String()))
	http.Redirect(w, r, oauth2.AuthCodeURL(callbackURL), http.StatusTemporaryRedirect)
}
