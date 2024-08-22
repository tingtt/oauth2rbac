package acl

import (
	"fmt"
	"log/slog"
	"oauth2rbac/internal/util/slices"
	"regexp"
	"strings"
)

type ScopeProvider interface {
	PublicEndpoints() []Scope
	Get(emails []Email) []Scope
}
type matcher interface {
	match(email Email, whitelist Pool) []Scope
}

func NewScopeProvider(whitelist Pool) ScopeProvider {
	p := &scopeProvider{scopeMatcher{}, make(map[string][]Scope), whitelist}
	go p.initializeCache()
	return p
}

type scopeProvider struct {
	matcher   matcher
	cache     map[string][]Scope
	whitelist Pool
}

func (p *scopeProvider) PublicEndpoints() []Scope {
	return p.whitelist["-"]
}

func (p scopeProvider) initializeCache() {
	for email, scopes := range p.whitelist {
		if strings.Contains(string(email), "*") {
			continue
		}
		p.cache[string(email)] = scopes
	}
	slog.Info("acl: scope loaded")
}

func (p scopeProvider) get(email Email) []Scope {
	if scopes, hit := p.cache[string(email)]; hit {
		slog.Debug(fmt.Sprintf("acl: scope cache hit (%s)", email))
		return scopes
	}
	slog.Debug(fmt.Sprintf("acl: scope cache not exists (%s)", email))

	scopes := p.matcher.match(email, p.whitelist)
	p.cache[string(email)] = scopes
	return scopes
}

func (p scopeProvider) Get(emails []Email) []Scope {
	cacheKey := strings.Join(slices.Map(emails, func(e Email) string { return string(e) }), ";")
	if scopes, hit := p.cache[cacheKey]; hit {
		slog.Debug(fmt.Sprintf("acl: scope cache hit (%s)", cacheKey))
		return scopes
	}
	slog.Debug(fmt.Sprintf("acl: scope cache not exists (%s)", cacheKey))

	scopes := []Scope{}
	for _, email := range emails {
		scopes = append(scopes, p.get(email)...)
	}
	scopes = slices.Compact(scopes)
	p.cache[cacheKey] = scopes
	return scopes
}

type scopeMatcher struct{}

func (p scopeMatcher) match(email Email, whitelist Pool) []Scope {
	scopes := []Scope{}
	for allowedEmail, _scopes := range whitelist {
		// Convert the email pattern to a regex pattern
		regexPattern := fmt.Sprintf("^%s$", allowedEmail)
		regexPattern = regexp.MustCompile(`\.`).ReplaceAllString(regexPattern, `\.`)
		regex := regexp.MustCompile(regexPattern)

		// Check if the email matches the regex pattern
		if regex.MatchString(string(email)) {
			scopes = append(scopes, _scopes...)
		}
	}
	return scopes
}
