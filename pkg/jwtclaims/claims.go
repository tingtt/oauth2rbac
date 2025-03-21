package jwtclaims

import (
	"encoding/json"

	"github.com/tingtt/oauth2rbac/internal/acl"
)

type Claims struct {
	AllowedScopes []acl.Scope `json:"allowed_scopes"`
	Emails        []acl.Email `json:"emails"`

	GitHub *ClaimsGitHub `json:"github,omitempty"`
	Google *ClaimsGoogle `json:"google,omitempty"`
}

type ClaimsGitHub struct {
	ID string `json:"id"`
}

type ClaimsGoogle struct {
	Username string `json:"username"`
}

func Unmarshal(dataJSON []byte) (Claims, error) {
	claims := Claims{}
	err := json.Unmarshal(dataJSON, &claims)
	return claims, err
}
