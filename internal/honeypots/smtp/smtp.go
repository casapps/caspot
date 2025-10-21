package smtp

import (
	"bufio"
	"encoding/base64"
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
	Hostname     string
	Banner       string
	Capabilities []string
	AuthTypes    []string
	MaxMsgSize   int
}

type smtpSession struct {
	conn         net.Conn
	db           *database.DB
	config       *Config
	sourceIP     string
	heloName     string
	mailFrom     string
	rcptTo       []string
	authenticated bool
	username     string
	authMethod   string
	authStep     int
	authData     string
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
		return fmt.Errorf("SMTP honeypot already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.config.Port, err)
	}

	h.listener = listener
	h.running = true

	go h.acceptConnections()

	fmt.Printf("SMTP honeypot started on port %d\n", h.config.Port)
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
		ServiceName: "smtp",
		Protocol:    "tcp",
		Severity:    "low",
	}
	h.db.LogEvent(event)

	session := &smtpSession{
		conn:     conn,
		db:       h.db,
		config:   h.config,
		sourceIP: sourceIP,
		rcptTo:   []string{},
	}

	session.send(220, h.config.Banner)

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		command := strings.ToUpper(parts[0])
		args := ""
		if len(parts) > 1 {
			args = parts[1]
		}

		event := &database.Event{
			EventType:   "command",
			SourceIP:    sourceIP,
			DestPort:    h.config.Port,
			ServiceName: "smtp",
			Protocol:    "tcp",
			Command:     line,
			Severity:    "medium",
		}
		h.db.LogEvent(event)

		if !session.handleCommand(command, args) {
			break
		}
	}
}

func (s *smtpSession) handleCommand(command, args string) bool {
	switch command {
	case "HELO":
		return s.handleHelo(args)
	case "EHLO":
		return s.handleEhlo(args)
	case "AUTH":
		return s.handleAuth(args)
	case "MAIL":
		return s.handleMail(args)
	case "RCPT":
		return s.handleRcpt(args)
	case "DATA":
		return s.handleData()
	case "RSET":
		s.resetTransaction()
		s.send(250, "OK")
		return true
	case "NOOP":
		s.send(250, "OK")
		return true
	case "QUIT":
		s.send(221, "Bye")
		return false
	case "VRFY":
		s.send(252, "Cannot VRFY user, but will accept message and attempt delivery")
		return true
	case "STARTTLS":
		s.send(454, "TLS not available")
		return true
	default:
		if s.authStep > 0 {
			return s.handleAuthData(command + " " + args)
		}
		s.send(502, "Command not implemented")
		return true
	}
}

func (s *smtpSession) handleHelo(hostname string) bool {
	s.heloName = hostname
	s.send(250, s.config.Hostname)
	return true
}

func (s *smtpSession) handleEhlo(hostname string) bool {
	s.heloName = hostname

	response := []string{
		s.config.Hostname,
		"PIPELINING",
		"SIZE " + fmt.Sprintf("%d", s.config.MaxMsgSize),
		"VRFY",
		"ETRN",
		"AUTH " + strings.Join(s.config.AuthTypes, " "),
		"ENHANCEDSTATUSCODES",
		"8BITMIME",
		"DSN",
	}

	s.sendMultiline(250, response)
	return true
}

func (s *smtpSession) handleAuth(args string) bool {
	parts := strings.SplitN(args, " ", 2)
	authType := strings.ToUpper(parts[0])

	s.authMethod = authType
	s.authStep = 1

	switch authType {
	case "LOGIN":
		s.send(334, base64.StdEncoding.EncodeToString([]byte("Username:")))
		return true
	case "PLAIN":
		if len(parts) > 1 {
			return s.handleAuthData(parts[1])
		}
		s.send(334, "")
		return true
	default:
		s.authStep = 0
		s.send(504, "Unrecognized authentication type")
		return true
	}
}

func (s *smtpSession) handleAuthData(data string) bool {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data))
	if err != nil {
		s.authStep = 0
		s.send(501, "Invalid base64 encoding")
		return true
	}

	switch s.authMethod {
	case "LOGIN":
		if s.authStep == 1 {
			s.username = string(decoded)
			s.send(334, base64.StdEncoding.EncodeToString([]byte("Password:")))
			s.authStep = 2
			return true
		} else if s.authStep == 2 {
			password := string(decoded)

			event := &database.Event{
				EventType:   "authentication",
				SourceIP:    s.sourceIP,
				DestPort:    s.config.Port,
				ServiceName: "smtp",
				Protocol:    "tcp",
				Username:    s.username,
				Password:    password,
				Severity:    "high",
			}
			s.db.LogEvent(event)

			s.authStep = 0
			s.send(535, "Authentication failed")
			return true
		}

	case "PLAIN":
		parts := strings.Split(string(decoded), "\x00")
		if len(parts) >= 3 {
			username := parts[1]
			password := parts[2]

			event := &database.Event{
				EventType:   "authentication",
				SourceIP:    s.sourceIP,
				DestPort:    s.config.Port,
				ServiceName: "smtp",
				Protocol:    "tcp",
				Username:    username,
				Password:    password,
				Severity:    "high",
			}
			s.db.LogEvent(event)
		}

		s.authStep = 0
		s.send(535, "Authentication failed")
		return true
	}

	s.authStep = 0
	s.send(535, "Authentication failed")
	return true
}

func (s *smtpSession) handleMail(args string) bool {
	if !strings.HasPrefix(strings.ToUpper(args), "FROM:") {
		s.send(501, "Syntax error in parameters")
		return true
	}

	from := strings.TrimPrefix(strings.ToUpper(args), "FROM:")
	from = strings.Trim(from, "<> ")
	s.mailFrom = from

	event := &database.Event{
		EventType:   "email_attempt",
		SourceIP:    s.sourceIP,
		DestPort:    s.config.Port,
		ServiceName: "smtp",
		Protocol:    "tcp",
		Command:     "MAIL FROM",
		Payload:     from,
		Severity:    "medium",
	}
	s.db.LogEvent(event)

	s.send(250, "OK")
	return true
}

func (s *smtpSession) handleRcpt(args string) bool {
	if s.mailFrom == "" {
		s.send(503, "Bad sequence of commands")
		return true
	}

	if !strings.HasPrefix(strings.ToUpper(args), "TO:") {
		s.send(501, "Syntax error in parameters")
		return true
	}

	to := strings.TrimPrefix(strings.ToUpper(args), "TO:")
	to = strings.Trim(to, "<> ")
	s.rcptTo = append(s.rcptTo, to)

	event := &database.Event{
		EventType:   "email_attempt",
		SourceIP:    s.sourceIP,
		DestPort:    s.config.Port,
		ServiceName: "smtp",
		Protocol:    "tcp",
		Command:     "RCPT TO",
		Payload:     to,
		Severity:    "medium",
	}
	s.db.LogEvent(event)

	s.send(250, "OK")
	return true
}

func (s *smtpSession) handleData() bool {
	if s.mailFrom == "" || len(s.rcptTo) == 0 {
		s.send(503, "Bad sequence of commands")
		return true
	}

	s.send(354, "End data with <CR><LF>.<CR><LF>")

	scanner := bufio.NewScanner(s.conn)
	var emailBody strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		if line == "." {
			break
		}
		emailBody.WriteString(line + "\n")
	}

	event := &database.Event{
		EventType:   "email_received",
		SourceIP:    s.sourceIP,
		DestPort:    s.config.Port,
		ServiceName: "smtp",
		Protocol:    "tcp",
		Command:     fmt.Sprintf("FROM:%s TO:%s", s.mailFrom, strings.Join(s.rcptTo, ",")),
		Payload:     emailBody.String(),
		Severity:    "high",
	}
	s.db.LogEvent(event)

	s.send(250, "OK: queued as 12345")
	s.resetTransaction()
	return true
}

func (s *smtpSession) resetTransaction() {
	s.mailFrom = ""
	s.rcptTo = []string{}
}

func (s *smtpSession) send(code int, message string) {
	response := fmt.Sprintf("%d %s\r\n", code, message)
	s.conn.Write([]byte(response))
}

func (s *smtpSession) sendMultiline(code int, lines []string) {
	for i, line := range lines {
		if i == len(lines)-1 {
			s.conn.Write([]byte(fmt.Sprintf("%d %s\r\n", code, line)))
		} else {
			s.conn.Write([]byte(fmt.Sprintf("%d-%s\r\n", code, line)))
		}
	}
}