package clioption

import "errors"

func checkJWTSignKey(jwtSignKey string) error {
	if jwtSignKey == "" {
		return errors.New("CLI option `--jwt-secret` cannot be empty")
	}
	return nil
}
