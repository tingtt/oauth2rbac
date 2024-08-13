package oauth2

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) Login(w http.ResponseWriter, req *http.Request) {
	providerName := chi.URLParam(req, "oauthProvider")
	oauth2, supported := h.OAuth2[providerName]
	if !supported {
		http.Redirect(w, req, "/.auth/login", http.StatusTemporaryRedirect)
	}

	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	callbackURL := req.URL.Scheme + "://" + req.Host + "/.auth/" + providerName + "/callback"
	http.Redirect(w, req, oauth2.AuthCodeURL(callbackURL), http.StatusTemporaryRedirect)
}
