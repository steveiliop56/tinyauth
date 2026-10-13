package service

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	ldapgo "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

// fakeLDAPServer is a tiny in-process LDAPv3 server that answers BindRequest
// and SearchRequest with fixed, valid BER responses. It exists so tests can
// exercise the real go-ldap client (real *ldapgo.Conn values, real Close()
// semantics) against loopback TCP without an external directory.
type fakeLDAPServer struct {
	ln net.Listener

	mu        sync.Mutex
	binds     int
	searches  int
	openConns int
	// blockSearch, when non-nil, is called at the start of every search. Tests
	// use it to hold a search open while another goroutine races a reconnect.
	blockSearch func()

	// blockBind, when non-nil, is called at the start of every bind. Tests use
	// it to hold a user bind open while another goroutine races a reconnect.
	blockBind func()
}

func newFakeLDAPServer(t *testing.T) *fakeLDAPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &fakeLDAPServer{ln: ln}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeLDAPServer) addr() string { return "ldap://" + s.ln.Addr().String() }

func (s *fakeLDAPServer) setBlockBind(f func()) {
	s.mu.Lock()
	s.blockBind = f
	s.mu.Unlock()
}

func (s *fakeLDAPServer) setBlockSearch(f func()) {
	s.mu.Lock()
	s.blockSearch = f
	s.mu.Unlock()
}

func (s *fakeLDAPServer) counts() (binds, searches, open int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.binds, s.searches, s.openConns
}

func (s *fakeLDAPServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.openConns++
		s.mu.Unlock()
		go s.handle(c)
	}
}

func (s *fakeLDAPServer) handle(c net.Conn) {
	defer func() {
		s.mu.Lock()
		s.openConns--
		s.mu.Unlock()
		c.Close()
	}()

	r := bufio.NewReader(c)
	for {
		frame, err := readFrame(r)
		if err != nil {
			return
		}
		op := classify(frame)
		switch op {
		case opBind:
			s.mu.Lock()
			hook := s.blockBind
			s.binds++
			s.mu.Unlock()
			if hook != nil {
				hook()
			}
			if _, err := c.Write(bindResponse(frame)); err != nil {
				return
			}
		case opSearch:
			s.mu.Lock()
			hook := s.blockSearch
			s.searches++
			s.mu.Unlock()
			if hook != nil {
				hook()
			}
			if _, err := c.Write(searchResponse(frame)); err != nil {
				return
			}
		case opUnbind:
			return
		default:
			return
		}
	}
}

// readFrame reads a single LDAPMessage (one BER SEQUENCE) framed by the ASN.1
// length. LDAP has no length prefix other than the BER encoding itself.
func readFrame(r *bufio.Reader) ([]byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if tag != 0x30 {
		return nil, io.ErrUnexpectedEOF
	}
	lb, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	var length int
	buf := []byte{tag, lb}
	if lb&0x80 == 0 {
		length = int(lb)
	} else {
		n := int(lb & 0x7f)
		lenBytes := make([]byte, n)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, err
		}
		buf = append(buf, lenBytes...)
		switch n {
		case 2:
			length = int(binary.BigEndian.Uint16(lenBytes))
		default:
			for _, b := range lenBytes {
				length = length<<8 | int(b)
			}
		}
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(buf, body...), nil
}

type ldapOp int

const (
	opUnknown ldapOp = iota
	opBind
	opSearch
	opUnbind
)

// parseTLV decodes one BER tag-length-value triple with support for the
// multi-byte definite length form.
func parseTLV(b []byte) (tag byte, length int, value []byte, ok bool) {
	if len(b) < 2 {
		return 0, 0, nil, false
	}
	tag = b[0]
	lb := b[1]
	off := 2
	if lb&0x80 == 0 {
		length = int(lb)
	} else {
		n := int(lb & 0x7f)
		if len(b) < 2+n {
			return 0, 0, nil, false
		}
		for _, x := range b[2 : 2+n] {
			length = length<<8 | int(x)
		}
		off = 2 + n
	}
	if len(b) < off+length {
		return 0, 0, nil, false
	}
	return tag, length, b[off : off+length], true
}

// readMessage returns the outer SEQUENCE body and the messageID. It fully
// decodes the BER length (including multi-byte forms) rather than assuming a
// single length byte, which is what real LDAP clients emit for long filters.
func readMessage(frame []byte) (msgID int, opBytes []byte, ok bool) {
	_, _, body, ok := parseTLV(frame)
	if !ok {
		return 0, nil, false
	}
	id, rest, ok := parseIntTLV(body)
	if !ok {
		return 0, nil, false
	}
	return id, rest, true
}

// parseIntTLV parses a leading BER INTEGER and returns its value plus the
// remaining bytes.
func parseIntTLV(b []byte) (int, []byte, bool) {
	if len(b) < 2 || b[0] != 0x02 {
		return 0, nil, false
	}
	lb := b[1]
	off := 2
	var length int
	if lb&0x80 == 0 {
		length = int(lb)
	} else {
		n := int(lb & 0x7f)
		if len(b) < 2+n {
			return 0, nil, false
		}
		for _, x := range b[2 : 2+n] {
			length = length<<8 | int(x)
		}
		off = 2 + n
	}
	if length <= 0 || len(b) < off+length {
		return 0, nil, false
	}
	id := 0
	for _, x := range b[off : off+length] {
		id = id<<8 | int(x)
	}
	return id, b[off+length:], true
}

// classify returns the LDAP protocol operation encoded in a frame.
func classify(frame []byte) ldapOp {
	_, op, ok := readMessage(frame)
	if !ok || len(op) == 0 {
		return opUnknown
	}
	switch op[0] & 0x1f {
	case 0: // BindRequest
		return opBind
	case 3: // SearchRequest
		return opSearch
	case 2: // UnbindRequest
		return opUnbind
	}
	return opUnknown
}

// ldapMessage wraps an ASN.1 SEQUENCE with a correctly encoded length so
// responses are always well-formed regardless of messageID magnitude.
func ldapMessage(msgID int, protocolOp []byte) []byte {
	id := encodeInteger(msgID)
	body := append(id, protocolOp...)
	return append(encodeSequenceHeader(len(body)), body...)
}

func encodeInteger(v int) []byte {
	if v == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	var b []byte
	for x := v; x > 0; x >>= 8 {
		b = append([]byte{byte(x & 0xff)}, b...)
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	return append([]byte{0x02, byte(len(b))}, b...)
}

func encodeSequenceHeader(length int) []byte {
	if length < 0x80 {
		return []byte{0x30, byte(length)}
	}
	var lenBytes []byte
	for x := length; x > 0; x >>= 8 {
		lenBytes = append([]byte{byte(x & 0xff)}, lenBytes...)
	}
	return append([]byte{0x30, byte(0x80 | len(lenBytes))}, lenBytes...)
}

// bindResponse echoes the request messageID with a success resultCode (0).
func bindResponse(req []byte) []byte {
	id, _, _ := readMessage(req)
	op := []byte{
		0x61, 0x07, // [APPLICATION 1] BindResponse
		0x0a, 0x01, 0x00, // resultCode: success
		0x04, 0x00, // matchedDN
		0x04, 0x00, // diagnosticMessage
	}
	return ldapMessage(id, op)
}

// searchResponse returns a SearchResultDone (success) with zero entries. Tests
// only need a well-formed, successful round-trip; entry parsing is not the
// subject under test.
func searchResponse(req []byte) []byte {
	id, _, _ := readMessage(req)
	op := []byte{
		0x65, 0x07, // [APPLICATION 5] SearchResultDone
		0x0a, 0x01, 0x00, // resultCode: success
		0x04, 0x00,
		0x04, 0x00,
	}
	return ldapMessage(id, op)
}

// newTestLdapService builds a real LdapService bound to the fake server.
func newTestLdapService(t *testing.T, addr string) *LdapService {
	t.Helper()
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	svc := &LdapService{
		log: log,
		ctx: context.Background(),
		config: &model.Config{
			LDAP: model.LDAPConfig{
				Address:           addr,
				BaseDN:            "dc=example,dc=com",
				SearchFilter:      "(&(objectClass=person)(uid=%s))",
				GroupSearchFilter: "(&(objectClass=group)(member=%s))",
				Insecure:          true,
			},
		},
	}
	require.NoError(t, svc.dialAndBind())
	return svc
}

// dialAndBind is a test convenience mirroring connect() without the swap.
// It reads svc.conn under the lock to stay race-free with reconnect.
func (svc *LdapService) dialAndBind() error {
	conn, err := svc.dial()
	if err != nil {
		return err
	}
	if err := svc.bindConn(conn); err != nil {
		conn.Close()
		return err
	}
	svc.mutex.Lock()
	svc.conn = conn
	svc.mutex.Unlock()
	return nil
}

var _ = ldapgo.NewSearchRequest
var _ = time.Second
