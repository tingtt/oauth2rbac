package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var Endpoint = github.Endpoint

func GetEmailFunc(ctx context.Context, config oauth2.Config, token *oauth2.Token) (emails []string, err error) {
	client := config.Client(ctx, token)

	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return nil, fmt.Errorf("failed to get user emails: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user emails: status code %d", resp.StatusCode)
	}

	var bodyEmails []struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bodyEmails); err != nil {
		return nil, fmt.Errorf("failed to parse emails: %w", err)
	}

	for _, email := range bodyEmails {
		emails = append(emails, email.Email)
	}

	if len(emails) == 0 {
		return nil, fmt.Errorf("failed to get email by github OAuth2: email not found")
	}
	return emails, nil
}
