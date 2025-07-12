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
	ldap := &LDAP{
		Config: config,
	}

	_, err := ldap.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

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

func (l *LDAP) connect() (*ldapgo.Conn, error) {
	conn, err := ldapgo.DialURL(l.Config.Address, ldapgo.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: l.Config.Insecure,
		MinVersion:         tls.VersionTLS12,
	}))
	if err != nil {
		return nil, err
	}

	err = conn.Bind(l.Config.BindDN, l.Config.BindPassword)
	if err != nil {
		return nil, err
	}

	// Set and return the connection
	l.Conn = conn
	return conn, nil
}

func (l *LDAP) Search(username string) (string, error) {
	// Escape the username to prevent LDAP injection
	escapedUsername := ldapgo.EscapeFilter(username)
	filter := fmt.Sprintf(l.Config.SearchFilter, escapedUsername)

	searchRequest := ldapgo.NewSearchRequest(
		l.Config.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	searchResult, err := l.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(searchResult.Entries) != 1 {
		return "", fmt.Errorf("err multiple or no entries found for user %s", username)
	}

	userDN := searchResult.Entries[0].DN
	return userDN, nil
}

func (l *LDAP) Bind(userDN string, password string) error {
	err := l.Conn.Bind(userDN, password)
	if err != nil {
		return err
	}
	return nil
}

func (l *LDAP) heartbeat() error {
	log.Debug().Msg("Performing LDAP connection heartbeat")

	searchRequest := ldapgo.NewSearchRequest(
		"",
		ldapgo.ScopeBaseObject, ldapgo.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{},
		nil,
	)

	_, err := l.Conn.Search(searchRequest)
	if err != nil {
		return err
	}

	// No error means the connection is alive
	return nil
}
