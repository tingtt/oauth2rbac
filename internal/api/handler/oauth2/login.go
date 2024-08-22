package oauth2handler

import (
	"net/http"
	urlutil "oauth2rbac/internal/api/handler/util/url"

	"github.com/go-chi/chi/v5"
)

func (h *handler) Login(w http.ResponseWriter, req *http.Request) {
	providerName := chi.URLParam(req, "oauthProvider")
	oauth2, supported := h.oAuth2[providerName]
	if !supported {
		http.Redirect(w, req, "/.auth/login", http.StatusTemporaryRedirect)
		return
	}

	reqURL := urlutil.RequestURL(*req.URL, urlutil.WithRequest(req), urlutil.WithXForwardedHeaders(req.Header))
	callbackURL := reqURL.Scheme + "://" + reqURL.Host + "/.auth/" + providerName + "/callback"
	http.Redirect(w, req, oauth2.AuthCodeURL(callbackURL), http.StatusTemporaryRedirect)
}
