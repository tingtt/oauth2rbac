package oauth2handler

import (
	"encoding/json"

	"github.com/tingtt/oauth2rbac/pkg/jwtclaims"
)

type JWTClaims jwtclaims.Claims

func (c JWTClaims) MapCollect() map[string]any {
	bytes, err := json.Marshal(c)
	if err != nil {
		panic("failed to marshal claim to json: " + err.Error())
	}
	mapped := map[string]any{}
	err = json.Unmarshal(bytes, &mapped)
	if err != nil {
		panic("failed to unmarhsal json to map[string]any: " + err.Error())
	}
	return mapped
}
