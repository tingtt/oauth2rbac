package oauth2handler

import (
	"oauth2rbac/internal/acl"
	cookieutil "oauth2rbac/internal/api/handler/util/cookie"
	"oauth2rbac/internal/oauth2"

	"github.com/go-chi/jwtauth/v5"
)

type handler struct {
	JWTAuth          *jwtauth.JWTAuth
	oAuth2           map[string]oauth2.Service
	scope            acl.ScopeProvider
	cookieController cookieutil.Controller
}

func New(jwtAuth *jwtauth.JWTAuth, oauth2 map[string]oauth2.Service, scope acl.ScopeProvider, cookieController cookieutil.Controller) handler {
	return handler{
		JWTAuth:          jwtAuth,
		oAuth2:           oauth2,
		scope:            scope,
		cookieController: cookieController,
	}
}
