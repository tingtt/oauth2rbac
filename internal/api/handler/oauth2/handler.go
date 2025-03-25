package oauth2handler

import (
	"github.com/tingtt/oauth2rbac/internal/acl"
	cookieutil "github.com/tingtt/oauth2rbac/internal/api/handler/util/cookie"
	handleroption "github.com/tingtt/oauth2rbac/internal/api/handler/util/option"
	"github.com/tingtt/oauth2rbac/internal/oauth2"

	"github.com/go-chi/jwtauth/v5"
)

type handler struct {
	oauth2 map[string]oauth2.Service
	jwt    *jwtauth.JWTAuth
	acl    acl.Provider
	cookie cookieutil.Controller
}

func New(oauth2 map[string]oauth2.Service, option *handleroption.Option) handler {
	return handler{oauth2, option.JWTAuth, option.ACLProvider, option.CookieController}
}
