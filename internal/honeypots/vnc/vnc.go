package vnc

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
	Port              int
	ProtocolVersion   string
	AuthTypes         []byte
	DesktopName       string
	ScreenWidth       uint16
	ScreenHeight      uint16
	PixelFormat       string
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
		return fmt.Errorf("VNC honeypot already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.config.Port, err)
	}

	h.listener = listener
	h.running = true

	go h.acceptConnections()

	fmt.Printf("VNC honeypot started on port %d\n", h.config.Port)
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
		ServiceName: "vnc",
		Protocol:    "tcp",
		Severity:    "low",
	}
	h.db.LogEvent(event)

	// Send RFB protocol version
	conn.Write([]byte(h.config.ProtocolVersion + "\n"))

	// Read client protocol version
	clientVersion := make([]byte, 12)
	n, err := conn.Read(clientVersion)
	if err != nil || n < 12 {
		return
	}

	// Send security types
	conn.Write([]byte{byte(len(h.config.AuthTypes))})
	conn.Write(h.config.AuthTypes)

	// Read selected security type
	secType := make([]byte, 1)
	if _, err := conn.Read(secType); err != nil {
		return
	}

	// Handle authentication based on type
	switch secType[0] {
	case 1: // None
		// Send OK
		conn.Write([]byte{0, 0, 0, 0})

	case 2: // VNC Authentication
		// Send challenge
		challenge := make([]byte, 16)
		for i := range challenge {
			challenge[i] = byte(i)
		}
		conn.Write(challenge)

		// Read response
		response := make([]byte, 16)
		if _, err := conn.Read(response); err == nil {
			event := &database.Event{
				EventType:   "authentication",
				SourceIP:    sourceIP,
				DestPort:    h.config.Port,
				ServiceName: "vnc",
				Protocol:    "tcp",
				Password:    "[VNC Challenge-Response]",
				Severity:    "high",
			}
			h.db.LogEvent(event)
		}

		// Send authentication failed
		conn.Write([]byte{0, 0, 0, 1})
		conn.Write([]byte{0, 0, 0, 22}) // Reason length
		conn.Write([]byte("Authentication failed"))
		return

	default:
		// Unknown security type
		conn.Write([]byte{0, 0, 0, 1})
		return
	}

	// If we get here, send ServerInit
	h.sendServerInit(conn)

	// Read any client messages
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			break
		}

		if n > 0 {
			// Parse client message type
			msgType := buffer[0]
			eventType := "vnc_message"
			severity := "medium"

			switch msgType {
			case 0: // SetPixelFormat
				eventType = "vnc_pixel_format"
			case 2: // SetEncodings
				eventType = "vnc_encodings"
			case 3: // FramebufferUpdateRequest
				eventType = "vnc_framebuffer_request"
			case 4: // KeyEvent
				eventType = "vnc_key_event"
				severity = "high"
			case 5: // PointerEvent
				eventType = "vnc_pointer_event"
			case 6: // ClientCutText
				eventType = "vnc_clipboard"
				severity = "high"
			}

			event := &database.Event{
				EventType:   eventType,
				SourceIP:    sourceIP,
				DestPort:    h.config.Port,
				ServiceName: "vnc",
				Protocol:    "tcp",
				Command:     fmt.Sprintf("Message type: %d", msgType),
				Severity:    severity,
			}
			h.db.LogEvent(event)
		}
	}
}

func (h *Honeypot) sendServerInit(conn net.Conn) {
	msg := &bytes.Buffer{}

	// Framebuffer width
	msg.WriteByte(byte(h.config.ScreenWidth >> 8))
	msg.WriteByte(byte(h.config.ScreenWidth))

	// Framebuffer height
	msg.WriteByte(byte(h.config.ScreenHeight >> 8))
	msg.WriteByte(byte(h.config.ScreenHeight))

	// Pixel format (16 bytes)
	msg.WriteByte(32)  // Bits per pixel
	msg.WriteByte(24)  // Depth
	msg.WriteByte(0)   // Big endian
	msg.WriteByte(1)   // True color
	msg.WriteByte(255) // Red max (high)
	msg.WriteByte(255) // Red max (low)
	msg.WriteByte(255) // Green max (high)
	msg.WriteByte(255) // Green max (low)
	msg.WriteByte(255) // Blue max (high)
	msg.WriteByte(255) // Blue max (low)
	msg.WriteByte(16)  // Red shift
	msg.WriteByte(8)   // Green shift
	msg.WriteByte(0)   // Blue shift
	msg.WriteByte(0)   // Padding
	msg.WriteByte(0)   // Padding
	msg.WriteByte(0)   // Padding

	// Desktop name length
	nameLen := len(h.config.DesktopName)
	msg.WriteByte(byte(nameLen >> 24))
	msg.WriteByte(byte(nameLen >> 16))
	msg.WriteByte(byte(nameLen >> 8))
	msg.WriteByte(byte(nameLen))

	// Desktop name
	msg.WriteString(h.config.DesktopName)

	conn.Write(msg.Bytes())
}