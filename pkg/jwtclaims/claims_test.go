package jwtclaims_test

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tingtt/oauth2rbac/pkg/jwtclaims"

	"github.com/golang-jwt/jwt/v5"
)

func ExampleUnmarshal() {
	// Takes http.Request
	_ = new(http.Request)

	// Get JWT, e.g. from cookie, header, etc.
	cookie := &http.Cookie{Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGxvd2VkX3Njb3BlcyI6eyIvIjpbIioiXSwiL2FkbWluIjpbIioiXX0sImVtYWlsIjoiYWRtaW5AZXhhbXBsZS50ZXN0IiwiZ29vZ2xlIjp7InVzZXJuYW1lIjoiYWRtaW4gZXhhbXBsZSJ9LCJnaXRodWIiOnsiaWQiOiJleGFtcGxlIn19.XlfvenXTSP15as6_8j4Z3DAHej2MgBggRx8Qj4JlKMI"}

	// Parse JWT with parser you are using, e.g. golang-jwt/jwt
	token, _ := jwt.Parse(cookie.Value, func(t *jwt.Token) (any, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte("a-string-secret-at-least-256-bits-long"), nil
	})
	if mapClaims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		jsonClaims, _ := json.Marshal(mapClaims)

		// Unmarshal JWT claims to struct oauth2rbac supports
		claims, _ := jwtclaims.Unmarshal(jsonClaims)

		fmt.Printf("%+v\n", claims.AllowedScopes)
		fmt.Printf("%+v\n", claims.Email)
		fmt.Printf("%+v\n", claims.Google)
		fmt.Printf("%+v\n", claims.GitHub)
		// Output:
		// map[/:[*] /admin:[*]]
		// admin@example.test
		// &{Username:admin example}
		// &{ID:example}
	}
}
