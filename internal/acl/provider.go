package acl

import (
	"net/url"
)

// Provider is an interface that provides the allowed scopes for a given email and URL.
// Is also caches the allowed scopes for a given URL and email.
type Provider interface {
	LoginRequired(url *url.URL, method string) bool
	AllowedScopes(url *url.URL, email string) AllowedScopes
	Roles(url *url.URL, email string) []string
	OriginConfig(url *url.URL) *OriginConfig

	originFromURL(url *url.URL) string
}

func NewProvider(pool Pool) Provider {
	pool = pool.sanitized()
	cache := cache{}
	cache.initialize(pool)
	return &provider{pool, cache}
}

type provider struct {
	pool  Pool
	cache cache
}

func (p *provider) originFromURL(url *url.URL) string {
	return url.Scheme + "://" + url.Host
}

// AllowedScopes implements Provider.
func (p *provider) AllowedScopes(url *url.URL, email string) AllowedScopes {
	origin := p.originFromURL(url)

	if allowedScopes, hit := p.cache.matchAllowedScopes(origin, email); hit {
		return allowedScopes
	}

	scope := p.pool.MatchOrigin(origin)
	if scope == nil {
		return nil
	}
	allowedScopes := scope.AllowedScopes(email)

	p.cache.cacheAllowedScopes(origin, email, allowedScopes)
	return allowedScopes
}

// LoginRequired implements Provider.
func (p *provider) LoginRequired(url *url.URL, method string) bool {
	origin := p.originFromURL(url)

	if loginRequired, hit := p.cache.matchLoginRequired(origin, url.Path, method); hit {
		return loginRequired
	}

	scope := p.pool.MatchOrigin(origin)
	if scope == nil {
		return true
	}
	return scope.LoginRequired(url.Path, method)
}

// Roles implements Provider.
func (p *provider) Roles(url *url.URL, email string) []string {
	origin := p.originFromURL(url)

	if roles, hit := p.cache.matchRoles(origin, email); hit {
		return roles
	}

	scope := p.pool.MatchOrigin(origin)
	if scope == nil {
		return nil
	}
	roles := scope.AllowedRoles(email)

	p.cache.cacheRoles(origin, email, roles)
	return roles
}

// OriginConfig implements Provider.
func (p *provider) OriginConfig(url *url.URL) *OriginConfig {
	origin := p.originFromURL(url)
	scope := p.pool.MatchOrigin(origin)
	if scope == nil {
		return nil
	}
	return &scope.OriginConfig
}
