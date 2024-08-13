package clioption

import (
	"errors"
	"fmt"
	"oauth2rbac/internal/oauth2"
	"strings"
)

func oauth2Config(clients *[]string) (map[string]oauth2.Service, error) {
	oauth2Config := map[string]oauth2.Service{}
	for _, c := range *clients {
		client := strings.Split(c, ";")
		if len(client) != 3 {
			return nil, errors.New("invalid format CLI option `--oauth2-client` given")
		}
		providerName, clientId, clientSecret := client[0], client[1], client[2]

		provider, supported := oauth2.Providers[providerName]
		if !supported {
			return nil, fmt.Errorf("oauth2 provider `%s` is not supported", providerName)
		}

		oauth2Config[providerName] = oauth2.New(&oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Scopes:       provider.Scopes,
			Endpoint:     provider.Endpoint,
		}, provider.GetEmailFunc)
	}
	if len(oauth2Config) == 0 {
		return nil, errors.New("CLI option `--oauth2-client` is required")
	}
	return oauth2Config, nil
}
