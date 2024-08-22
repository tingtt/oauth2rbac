package handleroption

import (
	"errors"
	"oauth2rbac/internal/acl"
	cookieutil "oauth2rbac/internal/api/handler/util/cookie"
	"oauth2rbac/internal/api/middleware/jwt"
	"oauth2rbac/internal/util/options"

	"github.com/go-chi/jwtauth/v5"
)

func New(_options ...Applier) (*Option, error) {
	option := options.Create(_options...)
	return option, validate(option)
}

func validate(option *Option) error {
	if option.ScopeProvider == nil {
		return errors.New("scope provider not provided")
	}
	if option.CookieController == nil {
		return errors.New("cookie controller not provided")
	}
	return nil
}

type Option struct {
	JWTAuth          *jwtauth.JWTAuth
	ScopeProvider    acl.ScopeProvider
	CookieController cookieutil.Controller
}

type Applier = options.Applier[Option]

func WithJWTAuth(jwtSecret string) Applier {
	return func(o *Option) { o.JWTAuth = jwt.NewAuth(jwtSecret) }
}
func WithScope(whitelist acl.Pool) Applier {
	return func(o *Option) { o.ScopeProvider = acl.NewScopeProvider(whitelist) }
}
func WithSecureCookie(useSecure bool) Applier {
	return func(o *Option) { o.CookieController = cookieutil.NewController(useSecure) }
}
