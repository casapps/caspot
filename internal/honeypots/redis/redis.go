package redis

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
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
	data     map[string]string
}

type Config struct {
	Port        int
	Version     string
	AuthEnabled bool
	FakeKeys    []string
	Commands    []string
	Databases   int
}

func New(db *database.DB, config *Config) (*Honeypot, error) {
	h := &Honeypot{
		db:     db,
		config: config,
		data:   make(map[string]string),
	}

	// Initialize fake data
	for _, key := range config.FakeKeys {
		h.data[key] = fmt.Sprintf("value_%s", key)
	}

	return h, nil
}

func (h *Honeypot) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("Redis honeypot already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.config.Port, err)
	}

	h.listener = listener
	h.running = true

	go h.acceptConnections()

	fmt.Printf("Redis honeypot started on port %d\n", h.config.Port)
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
		ServiceName: "redis",
		Protocol:    "tcp",
		Severity:    "low",
	}
	h.db.LogEvent(event)

	authenticated := !h.config.AuthEnabled
	scanner := bufio.NewScanner(conn)
	writer := bufio.NewWriter(conn)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse RESP protocol
		parts := h.parseCommand(scanner, line)
		if len(parts) == 0 {
			continue
		}

		command := strings.ToUpper(parts[0])

		event := &database.Event{
			EventType:   "command",
			SourceIP:    sourceIP,
			DestPort:    h.config.Port,
			ServiceName: "redis",
			Protocol:    "tcp",
			Command:     strings.Join(parts, " "),
			Severity:    "medium",
		}

		// Check for dangerous commands
		if command == "CONFIG" || command == "EVAL" || command == "SCRIPT" {
			event.Severity = "high"
		}

		h.db.LogEvent(event)

		// Handle command
		response := h.handleCommand(command, parts[1:], &authenticated, sourceIP)
		writer.WriteString(response)
		writer.Flush()
	}
}

func (h *Honeypot) parseCommand(scanner *bufio.Scanner, line string) []string {
	if !strings.HasPrefix(line, "*") {
		// Inline command
		return strings.Fields(line)
	}

	// Array format
	count, _ := strconv.Atoi(line[1:])
	parts := make([]string, 0, count)

	for i := 0; i < count; i++ {
		if scanner.Scan() {
			bulkLine := scanner.Text()
			if strings.HasPrefix(bulkLine, "$") {
				length, _ := strconv.Atoi(bulkLine[1:])
				if scanner.Scan() && length > 0 {
					parts = append(parts, scanner.Text())
				}
			}
		}
	}

	return parts
}

func (h *Honeypot) handleCommand(command string, args []string, authenticated *bool, sourceIP string) string {
	if !*authenticated && command != "AUTH" {
		return "-NOAUTH Authentication required.\r\n"
	}

	switch command {
	case "PING":
		return "+PONG\r\n"

	case "AUTH":
		if len(args) > 0 {
			password := args[0]
			event := &database.Event{
				EventType:   "authentication",
				SourceIP:    sourceIP,
				DestPort:    h.config.Port,
				ServiceName: "redis",
				Protocol:    "tcp",
				Password:    password,
				Severity:    "high",
			}
			h.db.LogEvent(event)
		}
		return "-ERR invalid password\r\n"

	case "INFO":
		info := fmt.Sprintf("# Server\r\nredis_version:%s\r\nredis_mode:standalone\r\nprocess_id:1234\r\nuptime_in_seconds:86400\r\n", h.config.Version)
		return fmt.Sprintf("$%d\r\n%s\r\n", len(info), info)

	case "GET":
		if len(args) == 0 {
			return "-ERR wrong number of arguments for 'get' command\r\n"
		}
		h.mu.RLock()
		value, exists := h.data[args[0]]
		h.mu.RUnlock()
		if exists {
			return fmt.Sprintf("$%d\r\n%s\r\n", len(value), value)
		}
		return "$-1\r\n"

	case "SET":
		if len(args) < 2 {
			return "-ERR wrong number of arguments for 'set' command\r\n"
		}
		h.mu.Lock()
		h.data[args[0]] = args[1]
		h.mu.Unlock()
		return "+OK\r\n"

	case "KEYS":
		pattern := "*"
		if len(args) > 0 {
			pattern = args[0]
		}

		h.mu.RLock()
		keys := make([]string, 0)
		for key := range h.data {
			if pattern == "*" || strings.Contains(key, strings.Trim(pattern, "*")) {
				keys = append(keys, key)
			}
		}
		h.mu.RUnlock()

		response := fmt.Sprintf("*%d\r\n", len(keys))
		for _, key := range keys {
			response += fmt.Sprintf("$%d\r\n%s\r\n", len(key), key)
		}
		return response

	case "CONFIG":
		if len(args) > 0 && strings.ToUpper(args[0]) == "GET" {
			if len(args) > 1 && args[1] == "dir" {
				return "*2\r\n$3\r\ndir\r\n$4\r\n/tmp\r\n"
			}
		}
		return "-ERR Unknown CONFIG subcommand\r\n"

	case "EVAL", "SCRIPT":
		event := &database.Event{
			EventType:   "code_execution",
			SourceIP:    sourceIP,
			DestPort:    h.config.Port,
			ServiceName: "redis",
			Protocol:    "tcp",
			Command:     command + " " + strings.Join(args, " "),
			Severity:    "critical",
		}
		h.db.LogEvent(event)
		return "-ERR unknown command\r\n"

	case "QUIT":
		return "+OK\r\n"

	default:
		return fmt.Sprintf("-ERR unknown command '%s'\r\n", strings.ToLower(command))
	}
}