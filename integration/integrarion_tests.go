package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func testUnauthorized(client *http.Client) error {
	req, err := http.NewRequest("GET", WhoamiURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// nginx and envoy will throw us at the frontend
	if resp.StatusCode != http.StatusUnauthorized && !strings.Contains(string(body), "<div id=\"root\"></div>") {
		return fmt.Errorf("expected status code %d or to to contain '<div id=\"root\"></div>', got %d", http.StatusUnauthorized, resp.StatusCode)
	}
	return nil
}

func testLoggedIn(client *http.Client) error {
	req, err := http.NewRequest("GET", WhoamiURL, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(DefaultUsername, DefaultPassword)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
	return nil
}

func testACLAllowed(client *http.Client) error {
	req, err := http.NewRequest("GET", WhoamiURL+"/allow", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
	return nil
}
