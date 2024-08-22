package oauth2handler

import (
	"oauth2rbac/internal/acl"
	cookieutil "oauth2rbac/internal/api/handler/util/cookie"
	handleroption "oauth2rbac/internal/api/handler/util/option"
	"oauth2rbac/internal/oauth2"

	"github.com/go-chi/jwtauth/v5"
)

type handler struct {
	oauth2           map[string]oauth2.Service
	JWTAuth          *jwtauth.JWTAuth
	scope            acl.ScopeProvider
	cookieController cookieutil.Controller
}

func New(oauth2 map[string]oauth2.Service, option *handleroption.Option) handler {
	return handler{oauth2, option.JWTAuth, option.ScopeProvider, option.CookieController}
}
