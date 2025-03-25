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

func GetUserInfoFunc(ctx context.Context, config oauth2.Config, token *oauth2.Token) (string /* id */, string /* email */, error) {
	client := config.Client(ctx, token)

	email, err := getPrimaryEmail(client)
	if err != nil {
		return "", "", fmt.Errorf("failed to get emails from github: %w", err)
	}

	id, err := getID(client)
	if err != nil {
		return "", "", fmt.Errorf("failed to get id from github: %w", err)
	}

	return id, email, nil
}

func getPrimaryEmail(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received status code %d", resp.StatusCode)
	}

	var bodyEmails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bodyEmails); err != nil {
		return "", fmt.Errorf("parse error: %w", err)
	}

	for _, email := range bodyEmails {
		if email.Primary {
			return email.Email, nil
		}
	}
	return "", fmt.Errorf("primary email not found")
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
