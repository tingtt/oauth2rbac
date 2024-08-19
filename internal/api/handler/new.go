package handler

import (
	"net/http"
	"oauth2rbac/internal/acl"
	oauth2h "oauth2rbac/internal/api/handler/oauth2"
	reverseproxy "oauth2rbac/internal/api/handler/reverse_proxy"
	"oauth2rbac/internal/api/middleware/jwt"
	"oauth2rbac/internal/oauth2"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
)

func New(oauth2Config map[string]oauth2.Service, jwtSignKey string, revProxyConfig reverseproxy.Config, acl acl.Pool) http.Handler {
	r := chi.NewRouter()

	oauth2Handler := oauth2h.Handler{
		JWT:        jwt.NewAuth(jwtSignKey),
		OAuth2:     oauth2Config,
		Whiltelist: acl,
	}

	r.Use(jwtauth.Verifier(oauth2Handler.JWT))

	r.Route("/.auth", func(r chi.Router) {
		r.Get("/login", oauth2Handler.SelectProvider)
		r.Get("/{oauthProvider}/login", oauth2Handler.Login)
		r.Get("/{oauthProvider}/callback", oauth2Handler.Callback)
	})

	rpFunc := reverseproxy.NewReverseProxyHandler(revProxyConfig, oauth2Handler.JWT, acl["-"]).ServeHTTP
	r.HandleFunc("/*", rpFunc)
	return r
}
