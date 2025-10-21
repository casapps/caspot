package postgresql

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/casapps/caspot/internal/database"
)

type Honeypot struct {
	db       *database.DB
	config   *Config
	listener net.Listener
	mu       sync.RWMutex
	running  bool
}

type Config struct {
	Port          int
	Version       string
	FakeDatabases []string
	FakeSchemas   map[string][]string
	AuthMethods   []string
}

type pgSession struct {
	conn     net.Conn
	db       *database.DB
	config   *Config
	sourceIP string
	username string
	database string
	salt     []byte
}

func New(db *database.DB, config *Config) (*Honeypot, error) {
	return &Honeypot{
		db:     db,
		config: config,
	}, nil
}

func (h *Honeypot) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("PostgreSQL honeypot already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.config.Port, err)
	}

	h.listener = listener
	h.running = true

	go h.acceptConnections()

	fmt.Printf("PostgreSQL honeypot started on port %d\n", h.config.Port)
	return nil
}

func (h *Honeypot) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.running = false
	if h.listener != nil {
		h.listener.Close()
	}

	return nil
}

func (h *Honeypot) acceptConnections() {
	for h.running {
		conn, err := h.listener.Accept()
		if err != nil {
			if h.running {
				fmt.Printf("Failed to accept connection: %v\n", err)
			}
			continue
		}

		go h.handleConnection(conn)
	}
}

func (h *Honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()

	sourceIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

	event := &database.Event{
		EventType:   "connection",
		SourceIP:    sourceIP,
		DestPort:    h.config.Port,
		ServiceName: "postgresql",
		Protocol:    "tcp",
		Severity:    "low",
	}
	h.db.LogEvent(event)

	session := &pgSession{
		conn:     conn,
		db:       h.db,
		config:   h.config,
		sourceIP: sourceIP,
		salt:     []byte{0x12, 0x34, 0x56, 0x78},
	}

	// Read startup message
	startupMsg, err := session.readMessage()
	if err != nil {
		return
	}

	// Parse startup message
	session.parseStartup(startupMsg)

	// Send authentication request (MD5)
	session.sendAuthMD5()

	// Read authentication response
	authMsg, err := session.readMessage()
	if err != nil {
		return
	}

	// Parse authentication
	password := session.parseAuth(authMsg)

	event = &database.Event{
		EventType:   "authentication",
		SourceIP:    sourceIP,
		DestPort:    h.config.Port,
		ServiceName: "postgresql",
		Protocol:    "tcp",
		Username:    session.username,
		Password:    password,
		Command:     fmt.Sprintf("Database: %s", session.database),
		Severity:    "high",
	}
	h.db.LogEvent(event)

	// Always reject
	session.sendError("28P01", "password authentication failed for user \"" + session.username + "\"")
}

func (s *pgSession) readMessage() ([]byte, error) {
	// Read message length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(s.conn, lenBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lenBuf)
	if length < 4 {
		return nil, fmt.Errorf("invalid message length")
	}

	// Read message data
	data := make([]byte, length-4)
	if _, err := io.ReadFull(s.conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

func (s *pgSession) parseStartup(data []byte) {
	if len(data) < 4 {
		return
	}

	// Skip protocol version
	pos := 4

	// Parse parameters (null-terminated key-value pairs)
	for pos < len(data) {
		// Find key
		keyEnd := bytes.IndexByte(data[pos:], 0)
		if keyEnd < 0 {
			break
		}
		key := string(data[pos : pos+keyEnd])
		pos = pos + keyEnd + 1

		// Find value
		valueEnd := bytes.IndexByte(data[pos:], 0)
		if valueEnd < 0 {
			break
		}
		value := string(data[pos : pos+valueEnd])
		pos = pos + valueEnd + 1

		switch key {
		case "user":
			s.username = value
		case "database":
			s.database = value
		}

		if data[pos] == 0 {
			break
		}
	}
}

func (s *pgSession) parseAuth(data []byte) string {
	if len(data) < 1 {
		return ""
	}

	msgType := data[0]
	if msgType == 'p' && len(data) > 5 {
		// Password message
		passLen := binary.BigEndian.Uint32(data[1:5])
		if int(passLen) <= len(data)-5 {
			return fmt.Sprintf("[MD5:%s]", hex.EncodeToString(data[5:passLen+1]))
		}
	}

	return "[encrypted]"
}

func (s *pgSession) sendAuthMD5() {
	msg := &bytes.Buffer{}

	// Message type: AuthenticationMD5Password
	msg.WriteByte('R')

	// Length placeholder
	lengthPos := msg.Len()
	msg.Write([]byte{0, 0, 0, 0})

	// Authentication type (5 = MD5)
	binary.Write(msg, binary.BigEndian, int32(5))

	// Salt
	msg.Write(s.salt)

	// Update length
	data := msg.Bytes()
	binary.BigEndian.PutUint32(data[lengthPos:], uint32(msg.Len()-1))

	s.conn.Write(data)
}

func (s *pgSession) sendError(code, message string) {
	msg := &bytes.Buffer{}

	// Message type: ErrorResponse
	msg.WriteByte('E')

	// Length placeholder
	lengthPos := msg.Len()
	msg.Write([]byte{0, 0, 0, 0})

	// Severity
	msg.WriteByte('S')
	msg.WriteString("FATAL")
	msg.WriteByte(0)

	// Code
	msg.WriteByte('C')
	msg.WriteString(code)
	msg.WriteByte(0)

	// Message
	msg.WriteByte('M')
	msg.WriteString(message)
	msg.WriteByte(0)

	// End of message
	msg.WriteByte(0)

	// Update length
	data := msg.Bytes()
	binary.BigEndian.PutUint32(data[lengthPos:], uint32(msg.Len()-1))

	s.conn.Write(data)
}

func generateMD5Hash(username, password string, salt []byte) string {
	// PostgreSQL MD5 authentication:
	// md5(md5(password + username) + salt)
	h1 := md5.Sum([]byte(password + username))
	h1Hex := hex.EncodeToString(h1[:])

	h2 := md5.Sum(append([]byte(h1Hex), salt...))
	return "md5" + hex.EncodeToString(h2[:])
}