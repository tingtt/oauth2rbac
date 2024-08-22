package handler

import (
	"net/http"
	oauth2handler "oauth2rbac/internal/api/handler/oauth2"
	reverseproxy "oauth2rbac/internal/api/handler/reverse_proxy"
	handleroption "oauth2rbac/internal/api/handler/util/option"
	"oauth2rbac/internal/oauth2"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
)

func New(
	oauth2Config map[string]oauth2.Service,
	revProxyConfig reverseproxy.Config,
	handlerOptions ...handleroption.Applier,
) (http.Handler, error) {
	option, err := handleroption.New(handlerOptions...)
	if err != nil {
		return nil, err
	}

	oauth2Handler := oauth2handler.New(oauth2Config, option)

	r := chi.NewRouter()
	r.Use(jwtauth.Verifier(option.JWTAuth))
	r.Get("/healthz", healthCheck)
	r.Route("/.auth", func(r chi.Router) {
		r.Get("/login", oauth2Handler.SelectProvider)
		r.Get("/{oauthProvider}/login", oauth2Handler.Login)
		r.Get("/{oauthProvider}/callback", oauth2Handler.Callback)
	})

	revProxy := reverseproxy.NewReverseProxyHandler(revProxyConfig, option)
	r.HandleFunc("/*", revProxy.ServeHTTP)
	return r, nil
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("healthy"))
}
