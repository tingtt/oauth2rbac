package clioption

import (
	"oauth2rbac/internal/acl"
	reverseproxy "oauth2rbac/internal/api/handler/reverse_proxy"
	"oauth2rbac/internal/oauth2"

	"github.com/spf13/pflag"
)

type CLIOption struct {
	Port           uint16
	OAuth2         map[string]oauth2.Service
	JWTSignKey     string
	RevProxyConfig reverseproxy.Config
	ACL            acl.Pool
}

func Load() (CLIOption, error) {
	port := pflag.Uint16("port", 8080, "Port to listen")
	jwtSignKey := pflag.String("jwt-secret", "", "JWT sign secret")
	oauth2Clients := pflag.StringArray("oauth2-client", nil, "OAuth2 (format: `<ProviderName>;<ClientID>;<ClientSecret>`)")
	manifestFilePath := pflag.StringP("/etc/oauth2rbac/config.file", "f", "", "Manifest file path")
	pflag.Parse()

	if err := checkJWTSignKey(*jwtSignKey); err != nil {
		return CLIOption{}, err
	}

	oauth2Config, err := oauth2Config(oauth2Clients)
	if err != nil {
		return CLIOption{}, err
	}

	revProxyConfig, acl, err := RevProxyACL(*manifestFilePath)
	if err != nil {
		return CLIOption{}, err
	}

	return CLIOption{
		Port:           *port,
		OAuth2:         oauth2Config,
		JWTSignKey:     *jwtSignKey,
		RevProxyConfig: revProxyConfig,
		ACL:            acl,
	}, nil
}
