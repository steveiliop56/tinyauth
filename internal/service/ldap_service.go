package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	ldapgo "github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
)

type LdapServiceConfig struct {
	Address      string
	BindDN       string
	BindPassword string
	BaseDN       string
	Insecure     bool
	SearchFilter string
}

type LdapService struct {
	Config LdapServiceConfig
	Conn   *ldapgo.Conn
}

func NewLdapService(config LdapServiceConfig) *LdapService {
	return &LdapService{
		Config: config,
	}
}

func (ldap *LdapService) Init() error {
	_, err := ldap.connect()
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	go func() {
		for range time.Tick(time.Duration(5) * time.Minute) {
			err := ldap.heartbeat()
			if err != nil {
				log.Error().Err(err).Msg("LDAP connection heartbeat failed")
				if reconnectErr := ldap.reconnect(); reconnectErr != nil {
					log.Error().Err(reconnectErr).Msg("Failed to reconnect to LDAP server")
					continue
				}
				log.Info().Msg("Successfully reconnected to LDAP server")
			}
		}
	}()

	return nil
}

func (ldap *LdapService) connect() (*ldapgo.Conn, error) {
	log.Debug().Msg("Connecting to LDAP server")
	conn, err := ldapgo.DialURL(ldap.Config.Address, ldapgo.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: ldap.Config.Insecure,
		MinVersion:         tls.VersionTLS12,
	}))
	if err != nil {
		return nil, err
	}

	log.Debug().Msg("Binding to LDAP server")
	err = conn.Bind(ldap.Config.BindDN, ldap.Config.BindPassword)
	if err != nil {
		return nil, err
	}

	// Set and return the connection
	ldap.Conn = conn
	return conn, nil
}

func (ldap *LdapService) Search(username string) (string, error) {
	// Escape the username to prevent LDAP injection
	escapedUsername := ldapgo.EscapeFilter(username)
	filter := fmt.Sprintf(ldap.Config.SearchFilter, escapedUsername)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.Config.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	searchResult, err := ldap.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(searchResult.Entries) != 1 {
		return "", fmt.Errorf("err multiple or no entries found for user %s", username)
	}

	userDN := searchResult.Entries[0].DN
	return userDN, nil
}

func (ldap *LdapService) Bind(userDN string, password string) error {
	err := ldap.Conn.Bind(userDN, password)
	if err != nil {
		return err
	}
	return nil
}

func (ldap *LdapService) heartbeat() error {
	log.Debug().Msg("Performing LDAP connection heartbeat")

	searchRequest := ldapgo.NewSearchRequest(
		"",
		ldapgo.ScopeBaseObject, ldapgo.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{},
		nil,
	)

	_, err := ldap.Conn.Search(searchRequest)
	if err != nil {
		return err
	}

	// No error means the connection is alive
	return nil
}

func (ldap *LdapService) reconnect() error {
	log.Info().Msg("Reconnecting to LDAP server")

	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = 500 * time.Millisecond
	exp.RandomizationFactor = 0.1
	exp.Multiplier = 1.5
	exp.Reset()

	operation := func() (*ldapgo.Conn, error) {
		ldap.Conn.Close()
		conn, err := ldap.connect()
		if err != nil {
			return nil, nil
		}
		return conn, nil
	}

	_, err := backoff.Retry(context.TODO(), operation, backoff.WithBackOff(exp), backoff.WithMaxTries(3))

	if err != nil {
		return err
	}

	return nil
}
