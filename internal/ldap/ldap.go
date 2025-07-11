package ldap

import (
	"crypto/tls"
	"fmt"
	"time"
	"tinyauth/internal/types"

	ldapgo "github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
)

type LDAP struct {
	Config types.LdapConfig
	Conn   *ldapgo.Conn
}

func NewLDAP(config types.LdapConfig) (*LDAP, error) {
	// Create a new LDAP instance with the provided configuration
	ldap := &LDAP{
		Config: config,
	}

	// Connect to the LDAP server
	if err := ldap.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	// Start heartbeat goroutine
	go func() {
		for range time.Tick(time.Duration(5) * time.Minute) {
			err := ldap.heartbeat()
			if err != nil {
				log.Error().Err(err).Msg("LDAP connection heartbeat failed")
			}
		}
	}()

	return ldap, nil
}

func (l *LDAP) Connect() error {
	// Connect to the LDAP server
	conn, err := ldapgo.DialURL(l.Config.Address, ldapgo.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: l.Config.Insecure,
		MinVersion:         tls.VersionTLS12,
	}))
	if err != nil {
		return err
	}

	// Bind to the LDAP server with the provided credentials
	err = conn.Bind(l.Config.BindDN, l.Config.BindPassword)
	if err != nil {
		return err
	}

	// Store the connection in the LDAP struct
	l.Conn = conn
	return nil
}

func (l *LDAP) Search(username string) (string, error) {
	// Escape the username to prevent LDAP injection
	escapedUsername := ldapgo.EscapeFilter(username)
	filter := fmt.Sprintf(l.Config.SearchFilter, escapedUsername)

	// Create a search request to find the user by username
	searchRequest := ldapgo.NewSearchRequest(
		l.Config.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	// Perform the search
	searchResult, err := l.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(searchResult.Entries) != 1 {
		return "", fmt.Errorf("err multiple or no entries found for user %s", username)
	}

	// User found, return the distinguished name (DN)
	userDN := searchResult.Entries[0].DN

	return userDN, nil
}

func (l *LDAP) Bind(userDN string, password string) error {
	// Bind to the LDAP server with the user's DN and password
	err := l.Conn.Bind(userDN, password)
	if err != nil {
		return err
	}
	return nil
}

func (l *LDAP) heartbeat() error {
	// Perform a simple search to check if the connection is alive
	log.Info().Msg("Performing LDAP connection heartbeat")

	// Create a search request to find the user by username
	searchRequest := ldapgo.NewSearchRequest(
		l.Config.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		"(uid=*)",
		[]string{},
		nil,
	)

	// Perform the search
	_, err := l.Conn.Search(searchRequest)
	if err != nil {
		return err
	}

	// No error means the connection is alive
	return nil
}
