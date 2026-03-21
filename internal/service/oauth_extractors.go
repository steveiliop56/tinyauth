package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"
)

type GithubEmailResponse []struct {
	Email   string `json:"email"`
	Primary bool   `json:"primary"`
}

type GithubUserInfoResponse struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	ID    int    `json:"id"`
}

func defaultExtractor(client *http.Client, url string) (config.Claims, error) {
	var claims config.Claims

	res, err := client.Get(url)
	if err != nil {
		return config.Claims{}, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return config.Claims{}, fmt.Errorf("request failed with status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return config.Claims{}, err
	}

	tlog.App.Trace().Str("body", string(body)).Msg("Userinfo response body")

	err = json.Unmarshal(body, &claims)
	if err != nil {
		return config.Claims{}, err
	}

	return claims, nil
}

func githubExtractor(client *http.Client, url string) (config.Claims, error) {
	var user config.Claims

	userInfo, err := githubRequest[GithubUserInfoResponse](client, "https://api.github.com/user")
	if err != nil {
		return config.Claims{}, err
	}

	userEmails, err := githubRequest[GithubEmailResponse](client, "https://api.github.com/user/emails")
	if err != nil {
		return config.Claims{}, err
	}

	if len(userEmails) == 0 {
		return user, errors.New("no emails found")
	}

	for _, email := range userEmails {
		if email.Primary {
			user.Email = email.Email
			break
		}
	}

	// Use first available email if no primary email was found
	if user.Email == "" {
		user.Email = userEmails[0].Email
	}

	user.PreferredUsername = userInfo.Login
	user.Name = userInfo.Name
	user.Sub = strconv.Itoa(userInfo.ID)

	return user, nil
}

func githubRequest[T any](client *http.Client, url string) (T, error) {
	var githubRes T

	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return githubRes, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")

	res, err := client.Do(req)
	if err != nil {
		return githubRes, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return githubRes, fmt.Errorf("request failed with status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return githubRes, err
	}

	err = json.Unmarshal(body, &githubRes)
	if err != nil {
		return githubRes, err
	}

	return githubRes, nil
}
