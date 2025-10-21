package mysql

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
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
	FakeTables    map[string][]string
	AuthEnabled   bool
}

type mysqlSession struct {
	conn        net.Conn
	db          *database.DB
	config      *Config
	sourceIP    string
	username    string
	connID      uint32
	scramble    []byte
	sequenceID  byte
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
		return fmt.Errorf("MySQL honeypot already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.config.Port, err)
	}

	h.listener = listener
	h.running = true

	go h.acceptConnections()

	fmt.Printf("MySQL honeypot started on port %d\n", h.config.Port)
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
		ServiceName: "mysql",
		Protocol:    "tcp",
		Severity:    "low",
	}
	h.db.LogEvent(event)

	session := &mysqlSession{
		conn:       conn,
		db:         h.db,
		config:     h.config,
		sourceIP:   sourceIP,
		connID:     rand.Uint32(),
		scramble:   generateScramble(),
		sequenceID: 0,
	}

	// Send initial handshake
	session.sendHandshake()

	// Read auth response
	authData, err := session.readPacket()
	if err != nil {
		return
	}

	username, password := session.parseAuth(authData)
	session.username = username

	event = &database.Event{
		EventType:   "authentication",
		SourceIP:    sourceIP,
		DestPort:    h.config.Port,
		ServiceName: "mysql",
		Protocol:    "tcp",
		Username:    username,
		Password:    password,
		Severity:    "high",
	}
	h.db.LogEvent(event)

	// Always reject authentication
	session.sendError(1045, "28000", "Access denied for user '%s'@'%s' (using password: YES)", username, sourceIP)
}

func (s *mysqlSession) sendHandshake() {
	packet := &bytes.Buffer{}

	// Protocol version
	packet.WriteByte(10)

	// Server version
	packet.WriteString(s.config.Version)
	packet.WriteByte(0)

	// Connection ID
	binary.Write(packet, binary.LittleEndian, s.connID)

	// Auth plugin data part 1 (8 bytes)
	packet.Write(s.scramble[:8])

	// Filler
	packet.WriteByte(0)

	// Capabilities (lower 2 bytes)
	packet.Write([]byte{0xff, 0xf7})

	// Character set
	packet.WriteByte(33) // utf8_general_ci

	// Status flags
	packet.Write([]byte{0x02, 0x00})

	// Capabilities (upper 2 bytes)
	packet.Write([]byte{0xff, 0x81})

	// Length of auth plugin data
	packet.WriteByte(21)

	// Reserved
	packet.Write(make([]byte, 10))

	// Auth plugin data part 2 (12 bytes)
	packet.Write(s.scramble[8:20])
	packet.WriteByte(0)

	// Auth plugin name
	packet.WriteString("mysql_native_password")
	packet.WriteByte(0)

	s.sendPacket(packet.Bytes())
}

func (s *mysqlSession) sendPacket(data []byte) error {
	length := len(data)
	header := make([]byte, 4)

	// Packet length (3 bytes)
	header[0] = byte(length)
	header[1] = byte(length >> 8)
	header[2] = byte(length >> 16)

	// Sequence ID
	header[3] = s.sequenceID
	s.sequenceID++

	_, err := s.conn.Write(header)
	if err != nil {
		return err
	}

	_, err = s.conn.Write(data)
	return err
}

func (s *mysqlSession) readPacket() ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(s.conn, header); err != nil {
		return nil, err
	}

	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	s.sequenceID = header[3] + 1

	data := make([]byte, length)
	if _, err := io.ReadFull(s.conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

func (s *mysqlSession) parseAuth(data []byte) (string, string) {
	pos := 0

	// Skip client capabilities (4 bytes)
	pos += 4

	// Skip max packet size (4 bytes)
	pos += 4

	// Skip character set (1 byte)
	pos++

	// Skip reserved (23 bytes)
	pos += 23

	// Username (null-terminated)
	usernameEnd := bytes.IndexByte(data[pos:], 0)
	username := ""
	if usernameEnd >= 0 {
		username = string(data[pos : pos+usernameEnd])
		pos = pos + usernameEnd + 1
	}

	// Password (length-encoded)
	password := ""
	if pos < len(data) {
		passLen := int(data[pos])
		pos++
		if pos+passLen <= len(data) {
			password = fmt.Sprintf("[encrypted:%d bytes]", passLen)
		}
	}

	return username, password
}

func (s *mysqlSession) sendError(errno uint16, sqlState, format string, args ...interface{}) {
	packet := &bytes.Buffer{}

	// Error indicator
	packet.WriteByte(0xff)

	// Error number
	binary.Write(packet, binary.LittleEndian, errno)

	// SQL state marker
	packet.WriteByte('#')

	// SQL state
	packet.WriteString(sqlState)

	// Error message
	packet.WriteString(fmt.Sprintf(format, args...))

	s.sendPacket(packet.Bytes())
}

func generateScramble() []byte {
	scramble := make([]byte, 20)
	for i := range scramble {
		scramble[i] = byte(rand.Intn(256))
	}
	return scramble
}