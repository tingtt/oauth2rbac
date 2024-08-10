package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func New(oauth2 Oauth2Config) http.Handler {
	r := chi.NewRouter()

	handler := handler{oauth2Config, nil}

	r.Route("/.auth", func(r chi.Router) {
		r.Get("/login", handler.SelectOAuthProvider)
		r.Get("/{oauthProvider}/login", handler.OAuthLogin)
		r.Get("/{oauthProvider}/callback", handler.OAuthCallback)
	})
	return r
}
