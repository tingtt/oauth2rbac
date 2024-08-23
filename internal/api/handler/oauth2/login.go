package oauth2handler

import (
	"net/http"
	logutil "oauth2rbac/internal/api/handler/util/log"
	urlutil "oauth2rbac/internal/api/handler/util/url"

	"github.com/go-chi/chi/v5"
)

func (h *handler) Login(rw http.ResponseWriter, req *http.Request) {
	providerName := chi.URLParam(req, "oauthProvider")

	reqURL := urlutil.RequestURL(*req.URL, urlutil.WithRequest(req), urlutil.WithXForwardedHeaders(req.Header))
	res, logInfo := logutil.InfoLogger(reqURL, req.Method, rw, req)

	oauth2, supported := h.oauth2[providerName]
	if !supported {
		http.Redirect(res, req, "/.auth/login", http.StatusTemporaryRedirect)
		logInfo("unsupported oauth2 provider")
		return
	}

	callbackURL := reqURL.Scheme + "://" + reqURL.Host + "/.auth/" + providerName + "/callback"
	http.Redirect(res, req, oauth2.AuthCodeURL(callbackURL), http.StatusTemporaryRedirect)
	logInfo("")
}
