package handler

import (
	"net/http"
	"oauth2rbac/internal/acl"
	oauth2handler "oauth2rbac/internal/api/handler/oauth2"
	reverseproxy "oauth2rbac/internal/api/handler/reverse_proxy"
	cookieutil "oauth2rbac/internal/api/handler/util/cookie"
	handleroption "oauth2rbac/internal/api/handler/util/option"
	"oauth2rbac/internal/api/middleware/jwt"
	"oauth2rbac/internal/oauth2"
	"oauth2rbac/internal/util/options"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
)

func New(
	oauth2Config map[string]oauth2.Service,
	jwtSignKey string,
	revProxyConfig reverseproxy.Config,
	_acl acl.Pool,
	handlerOptions ...handleroption.Applier,
) http.Handler {
	r := chi.NewRouter()

	oauth2Handler := oauth2handler.New(
		jwt.NewAuth(jwtSignKey),
		oauth2Config,
		acl.NewScopeProvider(_acl),
		cookieutil.NewController(options.Create(handlerOptions...).UsingTLS),
	)

	r.Use(jwtauth.Verifier(oauth2Handler.JWTAuth))

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("healthy"))
	})

	r.Route("/.auth", func(r chi.Router) {
		r.Get("/login", oauth2Handler.SelectProvider)
		r.Get("/{oauthProvider}/login", oauth2Handler.Login)
		r.Get("/{oauthProvider}/callback", oauth2Handler.Callback)
	})

	revProxy := reverseproxy.NewReverseProxyHandler(
		revProxyConfig,
		oauth2Handler.JWTAuth,
		_acl["-"], // public endpoints
		handlerOptions...,
	)
	r.HandleFunc("/*", revProxy.ServeHTTP)
	return r
}
