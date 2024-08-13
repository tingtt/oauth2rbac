package jwt

import "github.com/go-chi/jwtauth/v5"

func NewAuth(signKey string) *jwtauth.JWTAuth {
	return jwtauth.New("HS256", []byte(signKey), nil)
}
