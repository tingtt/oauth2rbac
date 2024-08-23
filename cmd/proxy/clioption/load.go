package clioption

import (
	"crypto/tls"
	"log/slog"
	"oauth2rbac/internal/acl"
	reverseproxy "oauth2rbac/internal/api/handler/reverse_proxy"
	"oauth2rbac/internal/oauth2"

	"github.com/spf13/pflag"
)

type CLIOption struct {
	Port            uint16
	OAuth2          map[string]oauth2.Service
	JWTSignKey      string
	RevProxyConfig  reverseproxy.Config
	ACL             acl.Pool
	X509KeyPairs    []tls.Certificate
	UseSecureCookie bool

	LogLevel slog.Level
}

func Load() (CLIOption, error) {
	// Options for key features
	port := pflag.Uint16("port", 8080, "Port to listen")
	jwtSignKey := pflag.String("jwt-secret", "", "JWT sign secret")
	oauth2Clients := pflag.StringArray("oauth2-client", nil, "OAuth2 (format: `<ProviderName>;<ClientID>;<ClientSecret>`)")
	manifestFilePath := pflag.StringP("/etc/oauth2rbac/config.file", "f", "", "Manifest file path")
	x509KeyPairs := pflag.StringArray("tls-cert", nil, "x509 key pair (format: `<CertFilePath>;<KeyFilePath>`)")
	useSecureCookie := pflag.Bool("secure-cookie", false, "Use cookies with Secure attribute. If TLS certificate is set, it is always true.")

	// Options for developer
	debugLogEnable := pflag.Bool("debug", false, "Enable debug logs")

	pflag.Parse()

	if err := checkJWTSignKey(*jwtSignKey); err != nil {
		return CLIOption{}, err
	}

	oauth2Config, err := oauth2Config(oauth2Clients)
	if err != nil {
		return CLIOption{}, err
	}

	revProxyConfig, acl, err := loadAndValidateManifest(*manifestFilePath)
	if err != nil {
		return CLIOption{}, err
	}

	certs, err := tlsCerts(*x509KeyPairs)
	if err != nil {
		return CLIOption{}, err
	}

	if len(certs) != 0 && !*useSecureCookie {
		*useSecureCookie = true
	}

	if *debugLogEnable {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	return CLIOption{
		Port:            *port,
		OAuth2:          oauth2Config,
		JWTSignKey:      *jwtSignKey,
		RevProxyConfig:  revProxyConfig,
		ACL:             acl,
		X509KeyPairs:    certs,
		UseSecureCookie: *useSecureCookie,
	}, nil
}
