package auth_test

import (
	"testing"
	"time"
	"tinyauth/internal/auth"
	"tinyauth/internal/docker"
	"tinyauth/internal/types"
)

var config = types.AuthConfig{
	Users:          types.Users{},
	OauthWhitelist: "",
	SessionExpiry:  3600,
}

func TestLoginRateLimiting(t *testing.T) {
	// Initialize a new auth service with 3 max retries and 5 seconds timeout
	config.LoginMaxRetries = 3
	config.LoginTimeout = 5
	authService := auth.NewAuth(config, &docker.Docker{})

	// Test identifier
	identifier := "test_user"

	// Test successful login - should not lock account
	t.Log("Testing successful login")

	authService.RecordLoginAttempt(identifier, true)
	locked, _ := authService.IsAccountLocked(identifier)

	if locked {
		t.Fatalf("Account should not be locked after successful login")
	}

	// Test 2 failed attempts - should not lock account yet
	t.Log("Testing 2 failed login attempts")

	authService.RecordLoginAttempt(identifier, false)
	authService.RecordLoginAttempt(identifier, false)
	locked, _ = authService.IsAccountLocked(identifier)

	if locked {
		t.Fatalf("Account should not be locked after only 2 failed attempts")
	}

	// Add one more failed attempt (total 3) - should lock account with maxRetries=3
	t.Log("Testing 3 failed login attempts")
	authService.RecordLoginAttempt(identifier, false)
	locked, remainingTime := authService.IsAccountLocked(identifier)

	if !locked {
		t.Fatalf("Account should be locked after reaching max retries")
	}
	if remainingTime <= 0 || remainingTime > 5 {
		t.Fatalf("Expected remaining time between 1-5 seconds, got %d", remainingTime)
	}

	// Test reset after waiting for timeout - use 1 second timeout for fast testing
	t.Log("Testing unlocking after timeout")

	// Reinitialize auth service with a shorter timeout for testing
	config.LoginTimeout = 1
	config.LoginMaxRetries = 3
	authService = auth.NewAuth(config, &docker.Docker{})

	// Add enough failed attempts to lock the account
	for i := 0; i < 3; i++ {
		authService.RecordLoginAttempt(identifier, false)
	}

	// Verify it's locked
	locked, _ = authService.IsAccountLocked(identifier)
	if !locked {
		t.Fatalf("Account should be locked initially")
	}

	// Wait a bit and verify it gets unlocked after timeout
	time.Sleep(1500 * time.Millisecond) // Wait longer than the timeout
	locked, _ = authService.IsAccountLocked(identifier)

	if locked {
		t.Fatalf("Account should be unlocked after timeout period")
	}

	// Test disabled rate limiting
	t.Log("Testing disabled rate limiting")
	config.LoginMaxRetries = 0
	config.LoginTimeout = 0
	authService = auth.NewAuth(config, &docker.Docker{})

	for i := 0; i < 10; i++ {
		authService.RecordLoginAttempt(identifier, false)
	}

	locked, _ = authService.IsAccountLocked(identifier)
	if locked {
		t.Fatalf("Account should not be locked when rate limiting is disabled")
	}
}

func TestConcurrentLoginAttempts(t *testing.T) {
	// Initialize a new auth service with 2 max retries and 5 seconds timeout
	config.LoginMaxRetries = 2
	config.LoginTimeout = 5
	authService := auth.NewAuth(config, &docker.Docker{})

	// Test multiple identifiers
	identifiers := []string{"user1", "user2", "user3"}

	// Test that locking one identifier doesn't affect others
	t.Log("Testing multiple identifiers")

	// Add enough failed attempts to lock first user (2 attempts with maxRetries=2)
	authService.RecordLoginAttempt(identifiers[0], false)
	authService.RecordLoginAttempt(identifiers[0], false)

	// Check if first user is locked
	locked, _ := authService.IsAccountLocked(identifiers[0])
	if !locked {
		t.Fatalf("User1 should be locked after reaching max retries")
	}

	// Check that other users are not affected
	for i := 1; i < len(identifiers); i++ {
		locked, _ := authService.IsAccountLocked(identifiers[i])
		if locked {
			t.Fatalf("User%d should not be locked", i+1)
		}
	}

	// Test successful login after failed attempts (but before lock)
	t.Log("Testing successful login after failed attempts but before lock")

	// One failed attempt for user2
	authService.RecordLoginAttempt(identifiers[1], false)

	// Successful login should reset the counter
	authService.RecordLoginAttempt(identifiers[1], true)

	// Now try a failed login again - should not be locked as counter was reset
	authService.RecordLoginAttempt(identifiers[1], false)
	locked, _ = authService.IsAccountLocked(identifiers[1])
	if locked {
		t.Fatalf("User2 should not be locked after successful login reset")
	}
}
