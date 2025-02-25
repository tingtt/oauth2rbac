package jwtclaims

import (
	"encoding/json"
	"oauth2rbac/internal/acl"
)

type Claims struct {
	AllowedScopes []acl.Scope `json:"allowed_scopes"`
	Emails        []acl.Email `json:"emails"`
}

func Unmarshal(dataJSON []byte) (Claims, error) {
	claims := Claims{}
	err := json.Unmarshal(dataJSON, &claims)
	return claims, err
}
