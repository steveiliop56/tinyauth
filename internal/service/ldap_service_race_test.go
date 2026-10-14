package service

import (
	"strings"
	"sync"
	"testing"
	"time"

	ldapgo "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
)

// ldapClosedConnErr is the error the go-ldap client returns when a request is
// in flight while the underlying connection is closed by another goroutine.
// It is the exact failure described in issue #1191: the rebind/heartbeat drops
// the connection mid-authentication.
const ldapClosedConnErr = "response channel closed"

// TestReconnectWaitsForInFlightAuthentication is the core regression test for
// #1191.
//
// It holds a user bind (the authentication step) open on the shared
// connection, then races a reconnect against it. With the mutex in place the
// reconnect blocks until the authentication has released the lock, so the
// in-flight bind completes against a live connection.
//
// Before the fix the rebind/heartbeat closed the shared connection while the
// authentication was still running, and the bind failed with
// `ldap: response channel closed` — exactly the failure in the issue.
func TestReconnectWaitsForInFlightAuthentication(t *testing.T) {
	s := newFakeLDAPServer(t)

	// Construct the service first (this performs the initial service bind).
	svc := newTestLdapService(t, s.addr())

	// Now hold subsequent binds open until released, and signal when a bind
	// has started.
	bindStarted := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	s.setBlockBind(func() {
		once.Do(func() { close(bindStarted) })
		<-release
	})

	authErr := make(chan error, 1)
	go func() {
		authErr <- svc.Authenticate("uid=alice,dc=example,dc=com", "secret")
	}()

	// Wait until the user bind is actually in flight on the server side.
	select {
	case <-bindStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("bind never reached the server")
	}

	// Trigger the rebind path while the bind is in flight. With the mutex in
	// place this must block on the lock and therefore cannot close the live
	// connection.
	reconnectDone := make(chan error, 1)
	go func() {
		reconnectDone <- svc.reconnect(10 * time.Millisecond)
	}()

	// The reconnect must NOT have completed while the bind is still running:
	// completing means it swapped and closed the connection mid-request.
	select {
	case err := <-reconnectDone:
		t.Fatalf("reconnect returned while an authentication was in flight (err=%v); "+
			"the service lock is not protecting the connection", err)
	case <-time.After(200 * time.Millisecond):
		// Expected: reconnect is blocked on the lock.
	}

	close(release) // let the in-flight bind complete

	require.NoError(t, <-authErr,
		"in-flight authentication must not be broken by a concurrent rebind")
	require.NoError(t, <-reconnectDone, "reconnect should succeed after the bind finishes")
}

// TestUnsynchronizedReconnectReproducesRace demonstrates the pre-fix failure
// mode directly: closing the live connection while a request is in flight
// breaks that request. It guards against the test above silently passing for
// the wrong reason (e.g. the fake server behaviour changing).
func TestUnsynchronizedReconnectReproducesRace(t *testing.T) {
	s := newFakeLDAPServer(t)

	searchStarted := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { select { case <-release: default: close(release) } })
	var once sync.Once
	s.setBlockSearch(func() {
		once.Do(func() { close(searchStarted) })
		<-release
	})

	conn, err := ldapgo.DialURL(s.addr())
	require.NoError(t, err)
	require.NoError(t, conn.Bind("cn=admin,dc=example,dc=com", "pw"))

	errCh := make(chan error, 1)
	go func() {
		req := ldapgo.NewSearchRequest(
			"", ldapgo.ScopeBaseObject, ldapgo.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)", []string{}, nil)
		_, err := conn.Search(req)
		errCh <- err
	}()

	select {
	case <-searchStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("search never reached the server")
	}

	// This is what the buggy code did: drop the connection without waiting.
	conn.Close()
	close(release)

	select {
	case err := <-errCh:
		require.Error(t, err, "closing a connection mid-request must break the request")
		require.Contains(t, err.Error(), ldapClosedConnErr,
			"expected the documented closed-connection failure, got: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight search never returned after the connection was closed")
	}
}

// TestAuthenticateRestoresServiceBindOnFailure verifies that a failed user
// bind still leaves the shared connection bound as the service account, so a
// later LDAP search does not run as an unprivileged (or unbound) identity.
func TestAuthenticateRestoresServiceBindOnFailure(t *testing.T) {
	s := newFakeLDAPServer(t)
	svc := newTestLdapService(t, s.addr())

	// The fake server accepts binds; authenticate a "user" and confirm the
	// service rebind ran (two bind round-trips: user + service).
	require.NoError(t, svc.Authenticate("uid=alice,dc=example,dc=com", "secret"))

	binds, _, _ := s.counts()
	require.Equal(t, 3, binds, "expected initial service bind + user bind + service rebind")
}

// TestConcurrentAuthAndReconnectNoClosedConn is the stress test: many
// authentication/search operations run concurrently with repeated reconnects.
// Under `go test -race` it asserts both that there is no data race and that no
// request ever observes a closed connection.
func TestConcurrentAuthAndReconnectNoClosedConn(t *testing.T) {
	s := newFakeLDAPServer(t)
	svc := newTestLdapService(t, s.addr())

	const workers = 8
	const iterations = 25

	var wg sync.WaitGroup
	errCh := make(chan error, workers*iterations+iterations)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if err := svc.Authenticate("uid=alice,dc=example,dc=com", "secret"); err != nil {
					errCh <- err
					return
				}
				// GetUserInfo returns ErrLDAPNoUsers on the empty fake result,
				// which is fine; only closed-connection errors are failures.
				if _, err := svc.GetUserInfo("alice"); err != nil &&
					strings.Contains(err.Error(), ldapClosedConnErr) {
					errCh <- err
					return
				}
			}
		}()
	}

	// Reconnect concurrently with the workers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < iterations; j++ {
			if err := svc.reconnect(5 * time.Millisecond); err != nil {
				errCh <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}
}

// TestHeartbeatUsesSharedConnection ensures the heartbeat probe runs against
// the shared connection and observes a live socket.
func TestHeartbeatUsesSharedConnection(t *testing.T) {
	s := newFakeLDAPServer(t)
	svc := newTestLdapService(t, s.addr())

	require.NoError(t, svc.heartbeat())
	_, searches, _ := s.counts()
	require.GreaterOrEqual(t, searches, 1)
}
