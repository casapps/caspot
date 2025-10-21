package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/casapps/caspot/internal/database"
	"golang.org/x/crypto/ssh"
)

type Honeypot struct {
	db       *database.DB
	config   *Config
	listener net.Listener
	hostKey  ssh.Signer
	mu       sync.RWMutex
	running  bool
}

type Config struct {
	Port        int
	Banner      string
	FakeUsers   []string
	Commands    []string
	FileSystem  map[string]string
}

func New(db *database.DB, config *Config) (*Honeypot, error) {
	hostKey, err := generateHostKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	return &Honeypot{
		db:      db,
		config:  config,
		hostKey: hostKey,
	}, nil
}

func (h *Honeypot) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("SSH honeypot already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.config.Port, err)
	}

	h.listener = listener
	h.running = true

	go h.acceptConnections()

	fmt.Printf("SSH honeypot started on port %d\n", h.config.Port)
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
		ServiceName: "ssh",
		Protocol:    "tcp",
		Severity:    "low",
	}
	h.db.LogEvent(event)

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			event := &database.Event{
				EventType:   "authentication",
				SourceIP:    sourceIP,
				DestPort:    h.config.Port,
				ServiceName: "ssh",
				Protocol:    "tcp",
				Username:    c.User(),
				Password:    string(pass),
				Severity:    "high",
			}
			h.db.LogEvent(event)

			return nil, fmt.Errorf("password rejected for %s", c.User())
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			event := &database.Event{
				EventType:   "authentication",
				SourceIP:    sourceIP,
				DestPort:    h.config.Port,
				ServiceName: "ssh",
				Protocol:    "tcp",
				Username:    c.User(),
				Severity:    "high",
			}
			h.db.LogEvent(event)

			return nil, fmt.Errorf("public key rejected for %s", c.User())
		},
		ServerVersion: h.config.Banner,
	}

	config.AddHostKey(h.hostKey)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go h.handleSession(channel, requests, sourceIP)
	}
}

func (h *Honeypot) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, sourceIP string) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "exec":
			var payload struct {
				Command string
			}
			ssh.Unmarshal(req.Payload, &payload)

			event := &database.Event{
				EventType:   "command",
				SourceIP:    sourceIP,
				DestPort:    h.config.Port,
				ServiceName: "ssh",
				Protocol:    "tcp",
				Command:     payload.Command,
				Severity:    "medium",
			}
			h.db.LogEvent(event)

			response := h.executeCommand(payload.Command)
			io.WriteString(channel, response)
			req.Reply(true, nil)
			channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			return

		case "shell":
			req.Reply(true, nil)
			io.WriteString(channel, "$ ")

			buf := make([]byte, 1024)
			for {
				n, err := channel.Read(buf)
				if err != nil {
					return
				}

				command := strings.TrimSpace(string(buf[:n]))
				if command == "exit" {
					return
				}

				if command != "" {
					event := &database.Event{
						EventType:   "command",
						SourceIP:    sourceIP,
						DestPort:    h.config.Port,
						ServiceName: "ssh",
						Protocol:    "tcp",
						Command:     command,
						Severity:    "medium",
					}
					h.db.LogEvent(event)

					response := h.executeCommand(command)
					io.WriteString(channel, response)
				}
				io.WriteString(channel, "$ ")
			}

		case "pty-req":
			req.Reply(true, nil)

		default:
			req.Reply(false, nil)
		}
	}
}

func (h *Honeypot) executeCommand(command string) string {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return ""
	}

	switch parts[0] {
	case "ls":
		return "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\n"
	case "pwd":
		return "/home/user\n"
	case "whoami":
		return "user\n"
	case "id":
		return "uid=1000(user) gid=1000(user) groups=1000(user)\n"
	case "uname":
		if len(parts) > 1 && parts[1] == "-a" {
			return "Linux honeypot 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\n"
		}
		return "Linux\n"
	case "cat":
		if len(parts) > 1 {
			if content, ok := h.config.FileSystem[parts[1]]; ok {
				return content + "\n"
			}
			return fmt.Sprintf("cat: %s: No such file or directory\n", parts[1])
		}
		return "cat: missing file operand\n"
	case "echo":
		if len(parts) > 1 {
			return strings.Join(parts[1:], " ") + "\n"
		}
		return "\n"
	case "ps":
		return `  PID TTY          TIME CMD
    1 ?        00:00:01 systemd
    2 ?        00:00:00 kthreadd
  100 ?        00:00:00 sshd
  150 pts/0    00:00:00 bash
  200 pts/0    00:00:00 ps
`
	case "netstat":
		return `Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
`
	case "cd":
		return ""
	case "history":
		return `    1  ls -la
    2  cd /var/log
    3  cat syslog
    4  ps aux
    5  netstat -an
`
	default:
		return fmt.Sprintf("bash: %s: command not found\n", parts[0])
	}
}

func generateHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)
	return ssh.ParsePrivateKey(privateKeyBytes)
}