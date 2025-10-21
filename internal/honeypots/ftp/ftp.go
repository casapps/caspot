package ftp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

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
	Port           int
	Banner         string
	AllowAnonymous bool
	FakeFiles      map[string][]string
}

type ftpSession struct {
	conn         net.Conn
	db           *database.DB
	config       *Config
	authenticated bool
	username      string
	currentDir    string
	sourceIP      string
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
		return fmt.Errorf("FTP honeypot already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.config.Port, err)
	}

	h.listener = listener
	h.running = true

	go h.acceptConnections()

	fmt.Printf("FTP honeypot started on port %d\n", h.config.Port)
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
		ServiceName: "ftp",
		Protocol:    "tcp",
		Severity:    "low",
	}
	h.db.LogEvent(event)

	session := &ftpSession{
		conn:       conn,
		db:         h.db,
		config:     h.config,
		currentDir: "/",
		sourceIP:   sourceIP,
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
			ServiceName: "ftp",
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

func (s *ftpSession) handleCommand(command, args string) bool {
	switch command {
	case "USER":
		return s.handleUser(args)
	case "PASS":
		return s.handlePass(args)
	case "QUIT":
		s.send(221, "Goodbye.")
		return false
	case "SYST":
		s.send(215, "UNIX Type: L8")
		return true
	case "TYPE":
		s.send(200, "Type set to "+args)
		return true
	case "PWD", "XPWD":
		s.send(257, fmt.Sprintf(`"%s" is the current directory`, s.currentDir))
		return true
	case "CWD":
		return s.handleCwd(args)
	case "LIST", "NLST":
		return s.handleList()
	case "PASV":
		return s.handlePasv()
	case "PORT":
		s.send(200, "PORT command successful")
		return true
	case "RETR":
		return s.handleRetr(args)
	case "STOR":
		return s.handleStor(args)
	case "DELE":
		s.send(550, "Permission denied")
		return true
	case "MKD", "XMKD":
		s.send(550, "Permission denied")
		return true
	case "RMD", "XRMD":
		s.send(550, "Permission denied")
		return true
	case "NOOP":
		s.send(200, "NOOP ok")
		return true
	case "FEAT":
		s.sendMultiline(211, []string{
			"Features:",
			" PASV",
			" UTF8",
			" SIZE",
			"End",
		})
		return true
	default:
		s.send(502, "Command not implemented")
		return true
	}
}

func (s *ftpSession) handleUser(username string) bool {
	s.username = username

	event := &database.Event{
		EventType:   "authentication",
		SourceIP:    s.sourceIP,
		DestPort:    s.config.Port,
		ServiceName: "ftp",
		Protocol:    "tcp",
		Username:    username,
		Severity:    "high",
	}
	s.db.LogEvent(event)

	if strings.ToLower(username) == "anonymous" && s.config.AllowAnonymous {
		s.send(331, "Please specify the password")
	} else {
		s.send(331, "Password required for "+username)
	}
	return true
}

func (s *ftpSession) handlePass(password string) bool {
	event := &database.Event{
		EventType:   "authentication",
		SourceIP:    s.sourceIP,
		DestPort:    s.config.Port,
		ServiceName: "ftp",
		Protocol:    "tcp",
		Username:    s.username,
		Password:    password,
		Severity:    "high",
	}
	s.db.LogEvent(event)

	if strings.ToLower(s.username) == "anonymous" && s.config.AllowAnonymous {
		s.authenticated = true
		s.send(230, "Login successful")
	} else {
		s.send(530, "Login incorrect")
	}
	return true
}

func (s *ftpSession) handleCwd(dir string) bool {
	if !s.authenticated {
		s.send(530, "Please login first")
		return true
	}

	if dir == ".." {
		if s.currentDir != "/" {
			parts := strings.Split(s.currentDir, "/")
			s.currentDir = "/" + strings.Join(parts[:len(parts)-1], "/")
		}
	} else if strings.HasPrefix(dir, "/") {
		s.currentDir = dir
	} else {
		s.currentDir = strings.TrimRight(s.currentDir, "/") + "/" + dir
	}

	s.send(250, "Directory successfully changed")
	return true
}

func (s *ftpSession) handleList() bool {
	if !s.authenticated {
		s.send(530, "Please login first")
		return true
	}

	s.send(150, "Here comes the directory listing")

	listing := []string{
		"drwxr-xr-x    2 ftp      ftp          4096 Jan 01 12:00 pub",
		"drwxr-xr-x    2 ftp      ftp          4096 Jan 01 12:00 incoming",
		"-rw-r--r--    1 ftp      ftp          1024 Jan 01 12:00 readme.txt",
		"-rw-r--r--    1 ftp      ftp          2048 Jan 01 12:00 welcome.msg",
	}

	if files, ok := s.config.FakeFiles[s.currentDir]; ok {
		for _, file := range files {
			listing = append(listing, fmt.Sprintf("-rw-r--r--    1 ftp      ftp          %d Jan 01 12:00 %s",
				1024+len(file)*100, file))
		}
	}

	time.Sleep(100 * time.Millisecond)

	for _, line := range listing {
		s.conn.Write([]byte(line + "\r\n"))
	}

	s.send(226, "Directory send OK")
	return true
}

func (s *ftpSession) handlePasv() bool {
	if !s.authenticated {
		s.send(530, "Please login first")
		return true
	}

	s.send(227, "Entering Passive Mode (127,0,0,1,200,10)")
	return true
}

func (s *ftpSession) handleRetr(filename string) bool {
	if !s.authenticated {
		s.send(530, "Please login first")
		return true
	}

	event := &database.Event{
		EventType:   "data_access",
		SourceIP:    s.sourceIP,
		DestPort:    s.config.Port,
		ServiceName: "ftp",
		Protocol:    "tcp",
		Command:     "RETR " + filename,
		Severity:    "high",
	}
	s.db.LogEvent(event)

	s.send(550, "File not found")
	return true
}

func (s *ftpSession) handleStor(filename string) bool {
	if !s.authenticated {
		s.send(530, "Please login first")
		return true
	}

	event := &database.Event{
		EventType:   "file_upload",
		SourceIP:    s.sourceIP,
		DestPort:    s.config.Port,
		ServiceName: "ftp",
		Protocol:    "tcp",
		Command:     "STOR " + filename,
		Payload:     filename,
		Severity:    "critical",
	}
	s.db.LogEvent(event)

	s.send(150, "Ok to send data")
	time.Sleep(500 * time.Millisecond)
	s.send(226, "Transfer complete")
	return true
}

func (s *ftpSession) send(code int, message string) {
	response := fmt.Sprintf("%d %s\r\n", code, message)
	s.conn.Write([]byte(response))
}

func (s *ftpSession) sendMultiline(code int, lines []string) {
	for i, line := range lines {
		if i == len(lines)-1 {
			s.conn.Write([]byte(fmt.Sprintf("%d %s\r\n", code, line)))
		} else {
			s.conn.Write([]byte(fmt.Sprintf("%d-%s\r\n", code, line)))
		}
	}
}