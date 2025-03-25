package acl

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

type Pool map[ /* origin */ string]ScopeOrigin

func (p Pool) sanitized() Pool {
	sanitized := Pool{}
	for origin, scope := range p {
		sanitizedOrigin, _ := strings.CutSuffix(origin, "/")
		scope.PathScopes = func() map[Path][]ScopePath {
			sanitizedPathScopes := map[Path][]ScopePath{}
			for path, scopes := range scope.PathScopes {
				sanitizedScopes := make([]ScopePath, 0, len(scopes))
				for _, scope := range scopes {
					sanitizedMethods := make([]Method, 0, len(scope.Methods))
					for _, method := range scope.Methods {
						sanitizedMethods = append(sanitizedMethods, strings.ToUpper(method))
					}
					slices.Sort(sanitizedMethods)
					sanitizedScopes = append(sanitizedScopes, ScopePath{
						EmailRegexes: scope.EmailRegexes,
						Methods:      slices.Compact(sanitizedMethods),
					})
				}
				sanitizedPathScopes[path] = sanitizedScopes
			}
			return sanitizedPathScopes
		}()
		sanitized[sanitizedOrigin] = scope
	}
	return sanitized
}

func (p Pool) MatchOrigin(origin string) *ScopeOrigin {
	if scope, ok := p[origin]; ok {
		return &scope
	}
	return nil
}

type Path = string
type Method = string

// EmailRegex is a regex pattern for email addresses without the ^ and $ anchors.
type EmailRegex string

func (eg EmailRegex) Match(email string) bool {
	// Convert the email pattern to a regex pattern
	regexPattern := fmt.Sprintf("^%s$", eg)
	regexPattern = regexp.MustCompile(`\.`).ReplaceAllString(regexPattern, `\.`)
	regex := regexp.MustCompile(regexPattern)

	// Check if the email matches the regex pattern
	return regex.MatchString(email)
}

type ScopeOrigin struct {
	PathScopes   map[Path][]ScopePath    `yaml:"paths"`
	Roles        map[string][]EmailRegex `yaml:"roles"`
	OriginConfig `yaml:",inline"`
}

type OriginConfig struct {
	JWTExpiryIn *JWTExpiryIn `yaml:"jwt_expiry_in"`
}

type JWTExpiryIn time.Duration

func (d *JWTExpiryIn) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v any
	if err := unmarshal(&v); err != nil {
		return err
	}
	switch value := v.(type) {
	case int:
		*d = JWTExpiryIn(time.Duration(value) * time.Second)
		return nil
	case int64:
		*d = JWTExpiryIn(time.Duration(value) * time.Second)
		return nil
	case float32:
		*d = JWTExpiryIn(time.Duration(value * float32(time.Second)))
		return nil
	case float64:
		*d = JWTExpiryIn(time.Duration(value * float64(time.Second)))
		return nil
	case string:
		var err error
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = JWTExpiryIn(parsed)
		return nil
	default:
		return errors.New("invalid duration")
	}
}

type ScopePath struct {
	EmailRegexes []EmailRegex `yaml:"emails"`
	Methods      []Method     `yaml:"methods"`
}

type AllowedScopes map[Path][]Method

func (as AllowedScopes) Match(path, method string) bool {
	methods := matchPath(path, as)
	if methods == nil {
		return false
	}
	return slices.Contains(*methods, "*") || slices.Contains(*methods, method)
}

func sortPathsByLengthDesc[S any](m map[Path]S) []Path {
	keys := make([]Path, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})
	return keys
}

func matchPath[S any](path string, m map[Path]S) *S {
	for _, p := range sortPathsByLengthDesc(m) {
		if strings.HasPrefix(path, string(p)) {
			v := m[p]
			return &v
		}
	}
	return nil
}

func (scope ScopeOrigin) LoginRequired(path, method string) bool {
	matchedScopes := matchPath(path, scope.PathScopes)
	if matchedScopes == nil {
		return true
	}

	anonymousAllowed := false
	for _, matchedScope := range *matchedScopes {
		if slices.Contains(matchedScope.Methods, method) {
			if slices.Contains(matchedScope.EmailRegexes, "-") {
				anonymousAllowed = true
			} else {
				return true
			}
		}
	}
	return !anonymousAllowed
}

func (scope ScopeOrigin) AllowedScopes(email string) AllowedScopes {
	allowedScopes := AllowedScopes{}
	for path, scopes := range scope.PathScopes {
		allowedScopes[path] = []Method{}
		for _, s := range scopes {
			for _, emailRegex := range s.EmailRegexes {
				if string(emailRegex) == "-" || string(emailRegex) == email || emailRegex.Match(email) {
					allowedScopes[path] = slices.Compact(append(allowedScopes[path], s.Methods...))
				}
			}
		}
	}
	return allowedScopes
}

func (scope ScopeOrigin) AllowedRoles(email string) []string {
	roles := []string{}
	for role, emailRegexes := range scope.Roles {
		for _, emailRegex := range emailRegexes {
			if string(role) == "-" || string(role) == email || emailRegex.Match(email) {
				roles = append(roles, role)
			}
		}
	}
	slices.Sort(roles)
	return slices.Compact(roles)
}
