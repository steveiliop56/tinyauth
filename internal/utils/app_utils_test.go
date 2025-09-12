package utils_test

import (
	"os"
	"testing"
	"tinyauth/internal/config"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"gotest.tools/v3/assert"
)

func TestGetRootDomain(t *testing.T) {
	// Normal case
	domain := "http://sub.tinyauth.app"
	expected := "tinyauth.app"
	result, err := utils.GetCookieDomain(domain)
	assert.NilError(t, err)
	assert.Equal(t, expected, result)

	// Domain with multiple subdomains
	domain = "http://b.c.tinyauth.app"
	expected = "c.tinyauth.app"
	result, err = utils.GetCookieDomain(domain)
	assert.NilError(t, err)
	assert.Equal(t, expected, result)

	// Domain with no subdomain
	domain = "http://tinyauth.app"
	expected = "tinyauth.app"
	_, err = utils.GetCookieDomain(domain)
	assert.Error(t, err, "invalid app url, must be at least second level domain")

	// Invalid domain (only TLD)
	domain = "com"
	_, err = utils.GetCookieDomain(domain)
	assert.ErrorContains(t, err, "invalid app url, must be at least second level domain")

	// IP address
	domain = "http://10.10.10.10"
	_, err = utils.GetCookieDomain(domain)
	assert.ErrorContains(t, err, "IP addresses not allowed")

	// Invalid URL
	domain = "http://[::1]:namedport"
	_, err = utils.GetCookieDomain(domain)
	assert.ErrorContains(t, err, "parse \"http://[::1]:namedport\": invalid port \":namedport\" after host")

	// URL with scheme and path
	domain = "https://sub.tinyauth.app/path"
	expected = "tinyauth.app"
	result, err = utils.GetCookieDomain(domain)
	assert.NilError(t, err)
	assert.Equal(t, expected, result)

	// URL with port
	domain = "http://sub.tinyauth.app:8080"
	expected = "tinyauth.app"
	result, err = utils.GetCookieDomain(domain)
	assert.NilError(t, err)
	assert.Equal(t, expected, result)

	// Domain managed by ICANN
	domain = "http://example.co.uk"
	_, err = utils.GetCookieDomain(domain)
	assert.Error(t, err, "domain in public suffix list, cannot set cookies")
}

func TestParseFileToLine(t *testing.T) {
	// Normal case
	content := "user1\nuser2\nuser3"
	expected := "user1,user2,user3"
	result := utils.ParseFileToLine(content)
	assert.Equal(t, expected, result)

	// Case with empty lines and spaces
	content = " user1 \n\n user2 \n user3 \n"
	expected = "user1,user2,user3"
	result = utils.ParseFileToLine(content)
	assert.Equal(t, expected, result)

	// Case with only empty lines
	content = "\n\n\n"
	expected = ""
	result = utils.ParseFileToLine(content)
	assert.Equal(t, expected, result)

	// Case with single user
	content = "singleuser"
	expected = "singleuser"
	result = utils.ParseFileToLine(content)
	assert.Equal(t, expected, result)

	// Case with trailing newline
	content = "user1\nuser2\n"
	expected = "user1,user2"
	result = utils.ParseFileToLine(content)
	assert.Equal(t, expected, result)
}

func TestFilter(t *testing.T) {
	// Normal case
	slice := []int{1, 2, 3, 4, 5}
	testFunc := func(n int) bool { return n%2 == 0 }
	expected := []int{2, 4}
	result := utils.Filter(slice, testFunc)
	assert.DeepEqual(t, expected, result)

	// Case with no matches
	slice = []int{1, 3, 5}
	testFunc = func(n int) bool { return n%2 == 0 }
	expected = []int{}
	result = utils.Filter(slice, testFunc)
	assert.DeepEqual(t, expected, result)

	// Case with all matches
	slice = []int{2, 4, 6}
	testFunc = func(n int) bool { return n%2 == 0 }
	expected = []int{2, 4, 6}
	result = utils.Filter(slice, testFunc)
	assert.DeepEqual(t, expected, result)

	// Case with empty slice
	slice = []int{}
	testFunc = func(n int) bool { return n%2 == 0 }
	expected = []int{}
	result = utils.Filter(slice, testFunc)
	assert.DeepEqual(t, expected, result)

	// Case with different type (string)
	sliceStr := []string{"apple", "banana", "cherry"}
	testFuncStr := func(s string) bool { return len(s) > 5 }
	expectedStr := []string{"banana", "cherry"}
	resultStr := utils.Filter(sliceStr, testFuncStr)
	assert.DeepEqual(t, expectedStr, resultStr)
}

func TestGetContext(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)

	// Normal case
	c.Set("context", &config.UserContext{Username: "testuser"})
	result, err := utils.GetContext(c)
	assert.NilError(t, err)
	assert.Equal(t, "testuser", result.Username)

	// Case with no context
	c.Set("context", nil)
	_, err = utils.GetContext(c)
	assert.Error(t, err, "invalid user context in request")

	// Case with invalid context type
	c.Set("context", "invalid type")
	_, err = utils.GetContext(c)
	assert.Error(t, err, "invalid user context in request")
}

func TestIsRedirectSafe(t *testing.T) {
	// Setup
	domain := "example.com"

	// Case with no subdomain
	redirectURL := "http://example.com/welcome"
	result := utils.IsRedirectSafe(redirectURL, domain)
	assert.Equal(t, false, result)

	// Case with different domain
	redirectURL = "http://malicious.com/phishing"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.Equal(t, false, result)

	// Case with subdomain
	redirectURL = "http://sub.example.com/page"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.Equal(t, true, result)

	// Case with empty redirect URL
	redirectURL = ""
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.Equal(t, false, result)

	// Case with invalid URL
	redirectURL = "http://[::1]:namedport"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.Equal(t, false, result)

	// Case with URL having port
	redirectURL = "http://sub.example.com:8080/page"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.Equal(t, true, result)

	// Case with URL having different subdomain
	redirectURL = "http://another.example.com/page"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.Equal(t, true, result)

	// Case with URL having different TLD
	redirectURL = "http://example.org/page"
	result = utils.IsRedirectSafe(redirectURL, domain)
	assert.Equal(t, false, result)
}

func TestGetOAuthProvidersConfig(t *testing.T) {
	env := []string{"PROVIDERS_CLIENT1_CLIENT_ID=client1-id", "PROVIDERS_CLIENT1_CLIENT_SECRET=client1-secret"}
	args := []string{"/tinyauth/tinyauth", "--providers-client2-client-id=client2-id", "--providers-client2-client-secret=client2-secret"}

	expected := map[string]config.OAuthServiceConfig{
		"client1": {
			ClientID:     "client1-id",
			ClientSecret: "client1-secret",
		},
		"client2": {
			ClientID:     "client2-id",
			ClientSecret: "client2-secret",
		},
	}

	result, err := utils.GetOAuthProvidersConfig(env, args, "")
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, result)

	// Case with no providers
	env = []string{}
	args = []string{"/tinyauth/tinyauth"}
	expected = map[string]config.OAuthServiceConfig{}

	result, err = utils.GetOAuthProvidersConfig(env, args, "")
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, result)

	// Case with secret from file
	file, err := os.Create("/tmp/tinyauth_test_file")
	assert.NilError(t, err)

	_, err = file.WriteString("file content\n")
	assert.NilError(t, err)

	err = file.Close()
	assert.NilError(t, err)
	defer os.Remove("/tmp/tinyauth_test_file")

	env = []string{"PROVIDERS_CLIENT1_CLIENT_ID=client1-id", "PROVIDERS_CLIENT1_CLIENT_SECRET_FILE=/tmp/tinyauth_test_file"}
	args = []string{"/tinyauth/tinyauth"}
	expected = map[string]config.OAuthServiceConfig{
		"client1": {
			ClientID:     "client1-id",
			ClientSecret: "file content",
		},
	}

	result, err = utils.GetOAuthProvidersConfig(env, args, "")
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, result)

	// Case with google provider and no redirect URL
	env = []string{"PROVIDERS_GOOGLE_CLIENT_ID=google-id", "PROVIDERS_GOOGLE_CLIENT_SECRET=google-secret"}
	args = []string{"/tinyauth/tinyauth"}
	expected = map[string]config.OAuthServiceConfig{
		"google": {
			ClientID:     "google-id",
			ClientSecret: "google-secret",
			RedirectURL:  "http://app.url/api/oauth/callback/google",
		},
	}

	result, err = utils.GetOAuthProvidersConfig(env, args, "http://app.url")
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, result)
}
