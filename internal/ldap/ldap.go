package ldap

import (
	"fmt"
	"tinyauth/internal/types"

	ldapgo "github.com/go-ldap/ldap/v3"
)

type LDAP struct {
	Config types.LdapConfig
	Conn   *ldapgo.Conn
	BaseDN string
}

func NewLDAP(config types.LdapConfig) (*LDAP, error) {
	// Connect to the LDAP server
	conn, err := ldapgo.DialURL(config.Address)
	if err != nil {
		return nil, err
	}

	// Try to connect using TLS
	// conn.StartTLS(&tls.Config{
	// 	InsecureSkipVerify: true,
	// })

	// Bind to the LDAP server with the provided credentials
	err = conn.Bind(config.BindUser, config.BindPassword)
	if err != nil {
		return nil, err
	}

	return &LDAP{
		Config: config,
		Conn:   conn,
		BaseDN: config.BaseDN,
	}, nil
}

func (l *LDAP) Search(username string) (string, error) {
	// Create a search request to find the user by username
	searchRequest := ldapgo.NewSearchRequest(
		l.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", username),
		[]string{"dn"},
		nil,
	)

	// Perform the search
	searchResult, err := l.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(searchResult.Entries) != 1 {
		return "", fmt.Errorf("user not found or multiple entries found for username: %s", username)
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
