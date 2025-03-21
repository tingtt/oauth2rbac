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

func GetUserInfoFunc(ctx context.Context, config oauth2.Config, token *oauth2.Token) (string /* id */, []string /* emails */, error) {
	client := config.Client(ctx, token)

	emails, err := getEmails(client)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get emails from github: %w", err)
	}

	id, err := getID(client)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get id from github: %w", err)
	}

	return id, emails, nil
}

func getEmails(client *http.Client) ([]string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received status code %d", resp.StatusCode)
	}

	var bodyEmails []struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bodyEmails); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	var emails []string
	for _, email := range bodyEmails {
		emails = append(emails, email.Email)
	}
	if len(emails) == 0 {
		return nil, fmt.Errorf("not found")
	}
	return emails, nil
}

func getID(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received status code %d", resp.StatusCode)
	}

	var responseBody struct {
		ID string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
		return "", fmt.Errorf("parse error: %w", err)
	}
	return responseBody.ID, nil
}
