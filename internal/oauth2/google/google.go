package google

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	apiv2google "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

var Endpoint = google.Endpoint

func GetUserInfoFunc(ctx context.Context, config oauth2.Config, token *oauth2.Token) (username, email string, err error) {
	client := config.Client(ctx, token)

	service, err := apiv2google.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return "", "", fmt.Errorf("failed to instanciate OAuth2 service: %w", err)
	}

	userInfo, err := service.Userinfo.Get().Do()
	if err != nil {
		return "", "", fmt.Errorf("failed to get email: %w", err)
	}

	return userInfo.Name, userInfo.Email, nil
}
