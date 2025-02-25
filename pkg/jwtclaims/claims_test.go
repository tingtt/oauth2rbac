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
	cookie := &http.Cookie{Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGxvd2VkX3Njb3BlcyI6W3siZXh0ZXJuYWxfdXJsIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgwLyIsIm1ldGhvZHMiOlsiKiJdLCJqd3RfZXhwaXJ5X2luIjoxMDgwMDAwMDAwMDAwMCwicm9sZXMiOlsiYWRtaW4iXX1dLCJlbWFpbHMiOlsiYWRtaW5AZXhhbXBsZS50ZXN0Il0sImV4cCI6MTc0MDQ4MzM0OCwiaWF0IjoxNzQwNDc5NzQ4fQ.ZXolVi-yGohljqKm6hUa4JeddEhpHMZeWVL2SeA1CeU"}

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
		fmt.Printf("%+v\n", claims.Emails)
		// Output:
		// [{ExternalURL:http://127.0.0.1:8080/ Methods:[*] JWTExpiryIn:3h0m0s Roles:[admin]}]
		// [admin@example.test]
	}
}
