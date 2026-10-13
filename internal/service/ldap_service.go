package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	ldapgo "github.com/go-ldap/ldap/v3"
	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"go.uber.org/dig"
)

var (
	ErrLDAPNoUsers       = errors.New("no users found")
	ErrLDAPMultipleUsers = errors.New("multiple users found")
)

type UserInfoResult struct {
	DN    string
	CN    string
	Email string
}

type LdapService struct {
	log    *logger.Logger
	ctx    context.Context
	config *model.Config

	conn   *ldapgo.Conn
	mutex  sync.RWMutex
	cert   *tls.Certificate
	bindPw string
}

type LdapServiceInput struct {
	dig.In

	Log    *logger.Logger
	Config *model.Config
	Ding   *ding.Ding
	Ctx    context.Context
}

func NewLdapService(i LdapServiceInput) (*LdapService, error) {
	if i.Config.LDAP.Address == "" {
		return nil, nil
	}

	ldap := &LdapService{
		log:    i.Log,
		config: i.Config,
		ctx:    i.Ctx,
	}

	ldap.bindPw = utils.GetSecret(i.Config.LDAP.BindPassword, i.Config.LDAP.BindPasswordFile)

	// Check whether authentication with client certificate is possible
	if i.Config.LDAP.AuthCert != "" && i.Config.LDAP.AuthKey != "" {
		cert, err := tls.LoadX509KeyPair(i.Config.LDAP.AuthCert, i.Config.LDAP.AuthKey)

		if err != nil {
			return nil, fmt.Errorf("failed to initialize LDAP with mTLS authentication: %w", err)
		}

		i.Log.App.Info().Msg("LDAP mTLS authentication configured successfully")

		ldap.cert = &cert

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
		// 3s + 4.5s (3x1.5) = ~6.75-8.25s total wait time before giving up
		err = ldap.reconnect(3 * time.Second)
		return nil, fmt.Errorf("failed to connect to ldap server: %w", err)
	}

	i.Ding.Go(func(ctx context.Context) {
		ldap.log.App.Debug().Msg("Starting LDAP connection heartbeat routine")

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				err := ldap.heartbeat()
				if err != nil {
					ldap.log.App.Warn().Err(err).Msg("LDAP connection heartbeat failed, attempting to reconnect")
					if reconnectErr := ldap.reconnect(1 * time.Second); reconnectErr != nil {
						ldap.log.App.Error().Err(reconnectErr).Msg("Failed to reconnect to LDAP server")
						continue
					}
					ldap.log.App.Info().Msg("Successfully reconnected to LDAP server")
				}
			case <-ctx.Done():
				ldap.log.App.Debug().Msg("LDAP service context cancelled, stopping heartbeat")
				return
			}
		}
	}, ding.RingMajor)

	return ldap, nil
}

// connect establishes a new connection, binds it to the service account and
// makes it the shared connection.
func (ldap *LdapService) connect() (*ldapgo.Conn, error) {
	conn, err := ldap.dial()
	if err != nil {
		return nil, err
	}

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	if err := ldap.bindConn(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Swap the connection while holding the lock so concurrent readers never
	// observe an unbound or closed connection.
	old := ldap.conn
	ldap.conn = conn
	if old != nil {
		old.Close()
	}

	return ldap.conn, nil
}

// dial opens a new connection to the LDAP server without touching any shared
// state, so it is safe to call while the service lock is held.
func (ldap *LdapService) dial() (*ldapgo.Conn, error) {
	// TODO: There's also STARTTLS (or SASL)-based mTLS authentication
	// scenario, where we first connect to plain text port (389) and
	// continue with a STARTTLS negotiation:
	// 1. conn = ldap.DialURL("ldap://ldap.example.com:389")
	// 2. conn.StartTLS(tlsConfig)
	// 3. conn.externalBind()
	if ldap.cert != nil {
		return ldapgo.DialURL(ldap.config.LDAP.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*ldap.cert},
		}))
	}

	return ldapgo.DialURL(ldap.config.LDAP.Address, ldapgo.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: ldap.config.LDAP.Insecure,
		MinVersion:         tls.VersionTLS12,
	}))
}

// bindConn binds an already established connection as the LDAP service
// account (or externally/anonymous when configured). Callers must hold the
// service lock.
func (ldap *LdapService) bindConn(conn *ldapgo.Conn) error {
	if ldap.cert != nil {
		return conn.ExternalBind()
	}

	// attempt unauthenticated/anonymous bind if both BindDN and bindpw are unset
	if ldap.config.LDAP.BindDN == "" && ldap.bindPw == "" {
		return conn.UnauthenticatedBind("")
	}

	return conn.Bind(ldap.config.LDAP.BindDN, ldap.bindPw)
}

func (ldap *LdapService) GetUserInfo(username string) (*UserInfoResult, error) {
	escapedUsername := ldapgo.EscapeFilter(username)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.LDAP.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		strings.Replace(ldap.config.LDAP.SearchFilter, "%s", escapedUsername, 1),
		[]string{"dn", "mail", "cn"},
		nil,
	)

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	searchResult, err := ldap.conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(searchResult.Entries) != 1 {
		if len(searchResult.Entries) == 0 {
			return nil, ErrLDAPNoUsers
		}
		return nil, ErrLDAPMultipleUsers
	}

	entry := searchResult.Entries[0]
	return &UserInfoResult{
		DN:    entry.DN,
		CN:    entry.GetAttributeValue("cn"),
		Email: entry.GetAttributeValue("mail"),
	}, nil
}

func (ldap *LdapService) GetUserCount() (int, error) {
	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.LDAP.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		"(objectClass=person)",
		[]string{"dn"},
		nil,
	)

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	searchResult, err := ldap.conn.Search(searchRequest)
	if err != nil {
		return 0, err
	}

	return len(searchResult.Entries), nil
}

func (ldap *LdapService) GetUserGroups(userDN string) ([]string, error) {
	escapedUserDN := ldapgo.EscapeFilter(userDN)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.LDAP.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		strings.Replace(ldap.config.LDAP.GroupSearchFilter, "%s", escapedUserDN, 1),
		[]string{"dn"},
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
		groupDNs = append(groupDNs, entry.DN)
	}

	groups := []string{}

	// I guess it should work for most ldap providers
	for _, dn := range groupDNs {
		rdnParts, err := ldapgo.ParseDN(dn)
		if err != nil {
			return []string{}, err
		}
		if len(rdnParts.RDNs) == 0 || len(rdnParts.RDNs[0].Attributes) == 0 {
			return []string{}, fmt.Errorf("invalid DN format: %s", dn)
		}
		groups = append(groups, rdnParts.RDNs[0].Attributes[0].Value)
	}

	return groups, nil
}

// heartbeat probes the shared connection with a root search. The lock is
// released before returning so a reconnect triggered by a failure can
// immediately acquire it.
func (ldap *LdapService) heartbeat() error {
	ldap.log.App.Debug().Msg("Performing LDAP connection heartbeat")

	searchRequest := ldapgo.NewSearchRequest(
		"",
		ldapgo.ScopeBaseObject, ldapgo.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{},
		nil,
	)

	ldap.mutex.Lock()
	_, err := ldap.conn.Search(searchRequest)
	ldap.mutex.Unlock()
	if err != nil {
		return err
	}

	// No error means the connection is alive
	return nil
}

// Authenticate binds the connection as userDN and then restores the
// service-account bind, all while holding the lock. This keeps the shared
// connection from ever being left bound as an unprivileged user and stops the
// heartbeat from dropping it in the middle of an authentication (issue #1191).
func (ldap *LdapService) Authenticate(userDN string, password string) error {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	// Always restore the service-account bind, even when the user bind fails,
	// so the shared connection is never left bound as an unprivileged user.
	bindErr := ldap.conn.Bind(userDN, password)
	rebindErr := ldap.bindConn(ldap.conn)

	if rebindErr != nil {
		if bindErr != nil {
			return fmt.Errorf("failed to rebind to ldap service account: %w, original error: %w", rebindErr, bindErr)
		}
		return fmt.Errorf("failed to rebind to ldap service account: %w", rebindErr)
	}

	if bindErr != nil {
		return fmt.Errorf("failed to bind to ldap user: %w", bindErr)
	}

	return nil
}

func (ldap *LdapService) reconnect(interval time.Duration) error {
	ldap.log.App.Info().Msg("Attempting to reconnect to LDAP server")

	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = interval
	exp.RandomizationFactor = 0.1
	exp.Multiplier = 1.5
	exp.Reset()

	operation := func() (*ldapgo.Conn, error) {
		// Dial the replacement before touching any shared state, then swap
		// under the lock. In-flight authentications therefore always run
		// against a bound connection and never see a closed one.
		conn, err := ldap.dial()
		if err != nil {
			return nil, err
		}

		ldap.mutex.Lock()
		defer ldap.mutex.Unlock()

		if err := ldap.bindConn(conn); err != nil {
			conn.Close()
			return nil, err
		}

		old := ldap.conn
		ldap.conn = conn
		if old != nil {
			old.Close()
		}

		return conn, nil
	}

	_, err := backoff.Retry(ldap.ctx, operation, backoff.WithBackOff(exp), backoff.WithMaxTries(3))

	if err != nil {
		return err
	}

	return nil
}
