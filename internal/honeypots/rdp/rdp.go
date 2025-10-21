package rdp

import (
	"bytes"
	"fmt"
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
	Port         int
	ComputerName string
	Domain       string
	OSVersion    string
	FakeUsers    []string
	NLAEnabled   bool
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
		return fmt.Errorf("RDP honeypot already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.config.Port, err)
	}

	h.listener = listener
	h.running = true

	go h.acceptConnections()

	fmt.Printf("RDP honeypot started on port %d\n", h.config.Port)
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
		ServiceName: "rdp",
		Protocol:    "tcp",
		Severity:    "low",
	}
	h.db.LogEvent(event)

	// Read initial connection request
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	// Parse X.224 Connection Request
	if n > 11 && buffer[0] == 0x03 { // TPKT
		// Send X.224 Connection Confirm
		h.sendConnectionConfirm(conn)

		// Continue reading for authentication attempts
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				break
			}

			if n > 0 {
				// Log any authentication attempts
				event := &database.Event{
					EventType:   "rdp_handshake",
					SourceIP:    sourceIP,
					DestPort:    h.config.Port,
					ServiceName: "rdp",
					Protocol:    "tcp",
					Command:     fmt.Sprintf("RDP data: %d bytes", n),
					Severity:    "medium",
				}

				// Look for CredSSP/NLA authentication
				if bytes.Contains(buffer[:n], []byte("NTLMSSP")) {
					event.EventType = "authentication"
					event.Severity = "high"

					// Try to extract username from NTLM
					if idx := bytes.Index(buffer[:n], []byte("NTLMSSP")); idx >= 0 {
						// Simple extraction attempt
						event.Username = "[NTLM Authentication Attempt]"
					}
				}

				h.db.LogEvent(event)

				// Send generic error response
				h.sendError(conn)
				break
			}
		}
	}
}

func (h *Honeypot) sendConnectionConfirm(conn net.Conn) {
	response := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT Header
		0x0e,                   // Length
		0xd0,                   // X.224 Type (Connection Confirm)
		0x00, 0x00,             // Destination reference
		0x12, 0x34,             // Source reference
		0x00,                   // Class and options
		0x02,                   // RDP Negotiation Response
		0x00,                   // Flags
		0x08,                   // Length
		0x00, 0x00, 0x00, 0x00, // Selected protocol (RDP)
	}

	conn.Write(response)
}

func (h *Honeypot) sendError(conn net.Conn) {
	// Send a generic disconnect/error
	response := []byte{
		0x03, 0x00, 0x00, 0x0b, // TPKT Header
		0x06,       // Length
		0x80,       // X.224 Type (Disconnect Request)
		0x00, 0x00, // Destination reference
		0x00, 0x00, // Source reference
	}

	conn.Write(response)
}