package clioption

import (
	"crypto/tls"
	"errors"
	"strings"

	"github.com/tingtt/oauth2rbac/internal/util/slices"
)

func tlsCerts(pairs []string) ([]tls.Certificate, error) {
	return slices.MapE(pairs, func(x509KeyPairStr string) (tls.Certificate, error) {
		x509KeyPair := strings.Split(x509KeyPairStr, ";")
		if len(x509KeyPair) != 2 {
			return tls.Certificate{}, errors.New("invalid format CLI option `--tls-cert` given")
		}
		certFilePath, keyFilePath := x509KeyPair[0], x509KeyPair[1]
		return tls.LoadX509KeyPair(certFilePath, keyFilePath)
	})
}
