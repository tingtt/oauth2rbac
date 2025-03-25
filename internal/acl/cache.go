package acl

import (
	"slices"
	"strings"
)

type cache struct {
	originScopes        map[ /* origin */ string]cacheAllowedScopes
	originLoginRequired map[ /* origin */ string]cacheLoginRequired
	originRoles         map[ /* origin */ string]map[ /* email */ string][]string
}

type cacheAllowedScopes struct {
	emailAllowedScopes map[ /* email */ string]AllowedScopes
}

type cacheLoginRequired struct {
	pathMethods map[Path]map[Method]bool
}

func (cache *cache) initialize(pool Pool) {
	cache.originScopes = make(map[string]cacheAllowedScopes)
	for origin, paths := range pool {
		cache.originScopes[origin] = cacheAllowedScopes{
			emailAllowedScopes: make(map[string]AllowedScopes),
		}

		emails := []string{}
		for _, scopes := range paths.PathScopes {
			for _, scope := range scopes {
				for _, emailRegex := range scope.EmailRegexes {
					if /* not regex */ !strings.Contains(string(emailRegex), "*") {
						emails = append(emails, string(emailRegex))
					}
				}
			}
		}

		scope := pool.MatchOrigin(origin)
		if scope == nil {
			continue
		}
		slices.Sort(emails)
		for _, email := range slices.Compact(emails) {
			cache.originScopes[origin].emailAllowedScopes[email] = scope.AllowedScopes(email)
		}
	}

	cache.originLoginRequired = make(map[string]cacheLoginRequired)
	for origin, paths := range pool {
		cache.originLoginRequired[origin] = cacheLoginRequired{
			pathMethods: make(map[Path]map[Method]bool),
		}

		scope := pool.MatchOrigin(origin)
		if scope == nil {
			continue
		}
		for path, scopes := range paths.PathScopes {
			cache.originLoginRequired[origin].pathMethods[path] = make(map[Method]bool)
			for _, pathScope := range scopes {
				for _, method := range pathScope.Methods {
					cache.originLoginRequired[origin].pathMethods[path][method] = scope.LoginRequired(path, method)
				}
			}
		}
	}

	cache.originRoles = make(map[string]map[string][]string)
	for origin, scope := range pool {
		roles := map[ /* email */ string][]string{}

		emails := []string{}
		for _, emailRegexes := range scope.Roles {
			for _, emailRegex := range emailRegexes {
				if /* not regex */ !strings.Contains(string(emailRegex), "*") {
					emails = append(emails, string(emailRegex))
				}
			}
		}
		slices.Sort(emails)

		for _, email := range slices.Compact(emails) {
			roles[email] = append(roles[email], scope.AllowedRoles(email)...)
			slices.Sort(roles[email])
			roles[email] = slices.Compact(roles[email])
		}

		cache.originRoles[origin] = roles
	}
}

func (cache *cache) matchAllowedScopes(origin, email string) (AllowedScopes, bool) {
	if cache.originScopes == nil {
		return nil, false
	}
	originScope, ok := cache.originScopes[origin]
	if !ok {
		return nil, false
	}
	if originScope.emailAllowedScopes == nil {
		return nil, false
	}
	allowedScopes, ok := originScope.emailAllowedScopes[email]
	return allowedScopes, ok
}

func (cache *cache) cacheAllowedScopes(origin, email string, scopes AllowedScopes) {
	if cache.originScopes == nil {
		cache.originScopes = make(map[string]cacheAllowedScopes)
	}
	if _, hit := cache.originScopes[origin]; !hit {
		cache.originScopes[origin] = cacheAllowedScopes{
			emailAllowedScopes: map[string]AllowedScopes{},
		}
	}
	cache.originScopes[origin].emailAllowedScopes[email] = scopes
}

func (cache *cache) matchLoginRequired(origin, path, method string) (loginRequired bool, ok bool) {
	if cache.originLoginRequired == nil {
		return false, false
	}
	originPathMethods, ok := cache.originLoginRequired[origin]
	if !ok {
		return false, false
	}
	if originPathMethods.pathMethods == nil {
		return false, false
	}
	methods := matchPath(path, originPathMethods.pathMethods)
	if methods == nil {
		return false, false
	}
	loginRequired, ok = (*methods)[method]
	if ok {
		return loginRequired, true
	}
	loginRequired, ok = (*methods)["*"]
	return loginRequired, ok
}

func (cache *cache) cacheRoles(origin, email string, roles []string) {
	if cache.originRoles == nil {
		cache.originRoles = make(map[string]map[string][]string)
	}
	if _, hit := cache.originRoles[origin]; !hit {
		cache.originRoles[origin] = map[string][]string{}
	}
	cache.originRoles[origin][email] = roles
}

func (cache *cache) matchRoles(origin, email string) ([]string, bool) {
	if cache.originRoles == nil {
		return nil, false
	}
	for emailRegex, roles := range cache.originRoles[origin] {
		if string(emailRegex) == "-" || string(emailRegex) == email {
			return roles, true
		}
	}
	return nil, true
}
