package utils_test

import (
	"os"
	"testing"

	"github.com/steveiliop56/tinyauth/internal/utils"

	"gotest.tools/v3/assert"
)

func TestGetUsers(t *testing.T) {
	// Setup
	file, err := os.Create("/tmp/tinyauth_users_test.txt")
	assert.NilError(t, err)

	_, err = file.WriteString("      user1:$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G        \n         user2:$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G                    ") // Spacing is on purpose
	assert.NilError(t, err)

	err = file.Close()
	assert.NilError(t, err)
	defer os.Remove("/tmp/tinyauth_users_test.txt")

	// Test file
	users, err := utils.GetUsers([]string{}, "/tmp/tinyauth_users_test.txt")

	assert.NilError(t, err)

	assert.Equal(t, 2, len(users))

	assert.Equal(t, "user1", users[0].Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", users[0].Password)
	assert.Equal(t, "user2", users[1].Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", users[1].Password)

	// Test config
	users, err = utils.GetUsers([]string{"user3:$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", "user4:$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G"}, "")

	assert.NilError(t, err)

	assert.Equal(t, 2, len(users))

	assert.Equal(t, "user3", users[0].Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", users[0].Password)
	assert.Equal(t, "user4", users[1].Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", users[1].Password)

	// Test both
	users, err = utils.GetUsers([]string{"user5:$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G"}, "/tmp/tinyauth_users_test.txt")

	assert.NilError(t, err)

	assert.Equal(t, 3, len(users))

	assert.Equal(t, "user5", users[0].Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", users[0].Password)
	assert.Equal(t, "user1", users[1].Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", users[1].Password)
	assert.Equal(t, "user2", users[2].Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", users[2].Password)

	// Test empty
	users, err = utils.GetUsers([]string{}, "")

	assert.NilError(t, err)

	assert.Equal(t, 0, len(users))

	// Test non-existent file
	users, err = utils.GetUsers([]string{}, "/tmp/non_existent_file.txt")

	assert.ErrorContains(t, err, "no such file or directory")

	assert.Equal(t, 0, len(users))
}

func TestParseUsers(t *testing.T) {
	// Valid users
	users, err := utils.ParseUsers([]string{"user1:$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", "user2:$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G:ABCDEF"}) // user2 has TOTP

	assert.NilError(t, err)

	assert.Equal(t, 2, len(users))

	assert.Equal(t, "user1", users[0].Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", users[0].Password)
	assert.Equal(t, "", users[0].TotpSecret)
	assert.Equal(t, "user2", users[1].Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", users[1].Password)
	assert.Equal(t, "ABCDEF", users[1].TotpSecret)

	// Valid weirdly spaced users
	users, err = utils.ParseUsers([]string{"      user1:$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G        ", "         user2:$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G:ABCDEF                    "}) // Spacing is on purpose
	assert.NilError(t, err)

	assert.Equal(t, 2, len(users))

	assert.Equal(t, "user1", users[0].Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", users[0].Password)
	assert.Equal(t, "", users[0].TotpSecret)
	assert.Equal(t, "user2", users[1].Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", users[1].Password)
	assert.Equal(t, "ABCDEF", users[1].TotpSecret)
}

func TestParseUser(t *testing.T) {
	// Valid user without TOTP
	user, err := utils.ParseUser("user1:$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G")

	assert.NilError(t, err)

	assert.Equal(t, "user1", user.Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", user.Password)
	assert.Equal(t, "", user.TotpSecret)

	// Valid user with TOTP
	user, err = utils.ParseUser("user2:$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G:ABCDEF")

	assert.NilError(t, err)

	assert.Equal(t, "user2", user.Username)
	assert.Equal(t, "$2a$10$Mz5xhkfSJUtPWkzCd/TdaePh9CaXc5QcGII5wIMPLSR46eTwma30G", user.Password)
	assert.Equal(t, "ABCDEF", user.TotpSecret)

	// Valid user with $$ in password
	user, err = utils.ParseUser("user3:pa$$word123")

	assert.NilError(t, err)

	assert.Equal(t, "user3", user.Username)
	assert.Equal(t, "pa$word123", user.Password)
	assert.Equal(t, "", user.TotpSecret)

	// User with spaces
	user, err = utils.ParseUser("   user4   :   password123   :   TOTPSECRET   ")

	assert.NilError(t, err)

	assert.Equal(t, "user4", user.Username)
	assert.Equal(t, "password123", user.Password)
	assert.Equal(t, "TOTPSECRET", user.TotpSecret)

	// Invalid users
	_, err = utils.ParseUser("user1") // Missing password
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser("user1:")
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser(":password123")
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser("user1:password123:ABC:EXTRA") // Too many parts
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser("user1::ABC")
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser(":password123:ABC")
	assert.ErrorContains(t, err, "invalid user format")

	_, err = utils.ParseUser("   :   :   ")
	assert.ErrorContains(t, err, "invalid user format")
}
