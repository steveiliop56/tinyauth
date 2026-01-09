package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"slices"
	"strings"
	"sync"
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
	AuthCert     string
	AuthKey      string
}

type LdapService struct {
	config LdapServiceConfig
	conn   *ldapgo.Conn
	mutex  sync.RWMutex
	cert   *tls.Certificate
}

func NewLdapService(config LdapServiceConfig) *LdapService {
	return &LdapService{
		config: config,
	}
}

func (ldap *LdapService) Init() error {
	// Check whether authentication with client certificate is possible
	if ldap.config.AuthCert != "" && ldap.config.AuthKey != "" {
		cert, err := tls.LoadX509KeyPair(ldap.config.AuthCert, ldap.config.AuthKey)
		if err != nil {
			return fmt.Errorf("failed to initialize LDAP with mTLS authentication: %w", err)
		}
		ldap.cert = &cert
		log.Info().Msg("Using LDAP with mTLS authentication")

		// TODO: Add optional extra CA certificates, instead of `InsecureSkipVerify`
		/*
			caCert, _ := ioutil.ReadFile(*caFile)
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig := &tls.Config{
						...
			RootCAs:      caCertPool,
			}
		*/
	}
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
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	var conn *ldapgo.Conn
	var err error

	// TODO: There's also STARTTLS (or SASL)-based mTLS authentication
	// scenario, where we first connect to plain text port (389) and
	// continue with a STARTTLS negotiation:
	// 1. conn = ldap.DialURL("ldap://ldap.example.com:389")
	// 2. conn.StartTLS(tlsConfig)
	// 3. conn.externalBind()
	if ldap.cert != nil {
		conn, err = ldapgo.DialURL(ldap.config.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*ldap.cert},
		}))
	} else {
		conn, err = ldapgo.DialURL(ldap.config.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: ldap.config.Insecure,
			MinVersion:         tls.VersionTLS12,
		}))
	}
	if err != nil {
		return nil, err
	}

	ldap.conn = conn

	err = ldap.BindService(false)
	if err != nil {
		return nil, err
	}
	return ldap.conn, nil
}

func (ldap *LdapService) GetUserDN(username string) (string, error) {
	// Escape the username to prevent LDAP injection
	escapedUsername := ldapgo.EscapeFilter(username)
	filter := fmt.Sprintf(ldap.config.SearchFilter, escapedUsername)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	searchResult, err := ldap.conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(searchResult.Entries) != 1 {
		return "", fmt.Errorf("multiple or no entries found for user %s", username)
	}

	userDN := searchResult.Entries[0].DN
	return userDN, nil
}

func (ldap *LdapService) GetUserGroups(userDN string) ([]string, error) {
	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		"(objectclass=groupOfUniqueNames)",
		[]string{"uniquemember"},
		nil,
	)

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	searchResult, err := ldap.conn.Search(searchRequest)
	if err != nil {
		return []string{}, err
	}

	groupDNs := []string{}

	for _, entry := range searchResult.Entries {
		memberAttributes := entry.GetAttributeValues("uniquemember")
		// no need to escape username here, if it's malicious it won't match anything
		if slices.Contains(memberAttributes, userDN) {
			groupDNs = append(groupDNs, entry.DN)
		}
	}

	// Should work for most ldap providers?
	groups := []string{}

	for _, groupDN := range groupDNs {
		groupDN = strings.TrimPrefix(groupDN, "cn=")
		parts := strings.SplitN(groupDN, ",", 2)
		if len(parts) > 0 {
			groups = append(groups, parts[0])
		}
	}

	return groups, nil
}

func (ldap *LdapService) BindService(rebind bool) error {
	// Locks must not be used for initial binding attempt
	if rebind {
		ldap.mutex.Lock()
		defer ldap.mutex.Unlock()
	}

	if ldap.cert != nil {
		return ldap.conn.ExternalBind()
	}
	return ldap.conn.Bind(ldap.config.BindDN, ldap.config.BindPassword)
}

func (ldap *LdapService) Bind(userDN string, password string) error {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()
	err := ldap.conn.Bind(userDN, password)
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

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()
	_, err := ldap.conn.Search(searchRequest)
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
		ldap.conn.Close()
		conn, err := ldap.connect()
		if err != nil {
			return nil, err
		}
		return conn, nil
	}

	_, err := backoff.Retry(context.TODO(), operation, backoff.WithBackOff(exp), backoff.WithMaxTries(3))

	if err != nil {
		return err
	}

	return nil
}
