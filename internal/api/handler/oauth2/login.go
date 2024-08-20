package oauth2

import (
	"net/http"
	urlutil "oauth2rbac/internal/api/handler/util/url"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) Login(w http.ResponseWriter, req *http.Request) {
	providerName := chi.URLParam(req, "oauthProvider")
	oauth2, supported := h.OAuth2[providerName]
	if !supported {
		http.Redirect(w, req, "/.auth/login", http.StatusTemporaryRedirect)
		return
	}

	reqURL := urlutil.RequestURL(req,
		req.Header.Get("X-Forwarded-Protocol"),
		req.Header.Get("X-Forwarded-Host"),
		req.Header.Get("X-Forwarded-Port"),
	)
	callbackURL := reqURL.Scheme + "://" + reqURL.Host + "/.auth/" + providerName + "/callback"
	http.Redirect(w, req, oauth2.AuthCodeURL(callbackURL), http.StatusTemporaryRedirect)
}
