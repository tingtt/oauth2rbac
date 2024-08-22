package oauth2

import (
	"oauth2rbac/internal/acl"
	"oauth2rbac/internal/oauth2"

	"github.com/go-chi/jwtauth/v5"
)

type Handler struct {
	JWT    *jwtauth.JWTAuth
	OAuth2 map[string]oauth2.Service
	Scope  acl.ScopeProvider
}
