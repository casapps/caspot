package services

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/casapps/caspot/internal/database"
	"github.com/casapps/caspot/internal/honeypots/dns"
	"github.com/casapps/caspot/internal/honeypots/ftp"
	"github.com/casapps/caspot/internal/honeypots/http"
	"github.com/casapps/caspot/internal/honeypots/mysql"
	"github.com/casapps/caspot/internal/honeypots/postgresql"
	"github.com/casapps/caspot/internal/honeypots/rdp"
	"github.com/casapps/caspot/internal/honeypots/redis"
	"github.com/casapps/caspot/internal/honeypots/smtp"
	"github.com/casapps/caspot/internal/honeypots/ssh"
	"github.com/casapps/caspot/internal/honeypots/telnet"
	"github.com/casapps/caspot/internal/honeypots/vnc"
)

type ServiceInterface interface {
	Start() error
	Stop() error
}

type Manager struct {
	db       *database.DB
	services map[string]ServiceInterface
	configs  map[string]interface{}
	mu       sync.RWMutex
}

func NewManager(db *database.DB) *Manager {
	return &Manager{
		db:       db,
		services: make(map[string]ServiceInterface),
		configs:  make(map[string]interface{}),
	}
}

func (m *Manager) Initialize() error {
	services, err := m.db.GetServices()
	if err != nil {
		return fmt.Errorf("failed to get services: %w", err)
	}

	for _, svc := range services {
		if !svc.Enabled {
			continue
		}

		err := m.createService(svc)
		if err != nil {
			fmt.Printf("Failed to create %s service: %v\n", svc.Name, err)
			continue
		}
	}

	return nil
}

func (m *Manager) createService(svc database.Service) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var service ServiceInterface
	var err error

	switch svc.Name {
	case "ssh":
		config := &ssh.Config{
			Port:   svc.Port,
			Banner: "SSH-2.0-OpenSSH_8.0",
			FakeUsers: []string{"root", "admin", "user", "guest"},
			Commands: []string{"ls", "pwd", "whoami", "ps", "netstat", "cat", "cd", "mkdir", "rm"},
			FileSystem: map[string]string{
				"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash",
				"/.bash_history": "ls -la\ncd /var/log\ncat syslog\n",
			},
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = ssh.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["ssh"] = config

	case "http":
		config := &http.Config{
			Port:       svc.Port,
			UseSSL:     false,
			ServerName: "Apache/2.4.41 (Ubuntu)",
			Templates:  []string{"login", "admin", "phpmyadmin", "wordpress"},
			UploadEnabled: true,
			FakeFiles: []string{"/admin.php", "/config.php", "/backup.sql", "/passwords.txt"},
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = http.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["http"] = config

	case "https":
		config := &http.Config{
			Port:       svc.Port,
			UseSSL:     true,
			ServerName: "Apache/2.4.41 (Ubuntu)",
			Templates:  []string{"login", "admin", "phpmyadmin", "wordpress"},
			UploadEnabled: true,
			FakeFiles: []string{"/admin.php", "/config.php", "/backup.sql", "/passwords.txt"},
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = http.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["https"] = config

	case "ftp":
		config := &ftp.Config{
			Port:           svc.Port,
			Banner:         "220 FTP Server ready",
			AllowAnonymous: true,
			FakeFiles: map[string][]string{
				"/":     {"readme.txt", "welcome.msg"},
				"/pub":  {"file1.txt", "file2.doc"},
				"/incoming": {},
			},
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = ftp.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["ftp"] = config

	case "telnet":
		config := &telnet.Config{
			Port:           svc.Port,
			LoginPrompt:    "Ubuntu 20.04.3 LTS\nlogin: ",
			PasswordPrompt: "Password: ",
			FakeSystem:     "Linux honeypot 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux",
			Commands:       []string{"ls", "pwd", "whoami", "ps", "netstat", "cat", "cd", "echo", "history"},
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = telnet.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["telnet"] = config

	case "smtp":
		config := &smtp.Config{
			Port:         svc.Port,
			Hostname:     "mail.example.com",
			Banner:       "220 mail.example.com ESMTP Postfix",
			Capabilities: []string{"EHLO", "AUTH LOGIN", "STARTTLS"},
			AuthTypes:    []string{"LOGIN", "PLAIN"},
			MaxMsgSize:   10485760,
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = smtp.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["smtp"] = config

	case "dns":
		config := &dns.Config{
			Port:               svc.Port,
			PoisonDomains:      []string{"malware", "phishing", "suspicious"},
			FakeRecords:        map[string]map[string]string{
				"A": {
					"admin.local": "192.168.1.100",
					"db.local":    "192.168.1.200",
				},
			},
			ZoneTransferEnabled: true,
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = dns.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["dns"] = config

	case "mysql":
		config := &mysql.Config{
			Port:          svc.Port,
			Version:       "5.7.34-0ubuntu0.18.04.1",
			FakeDatabases: []string{"information_schema", "mysql", "users", "products"},
			FakeTables:    map[string][]string{
				"users":    []string{"id", "username", "password", "email"},
				"products": []string{"id", "name", "price"},
			},
			AuthEnabled: true,
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = mysql.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["mysql"] = config

	case "redis":
		config := &redis.Config{
			Port:        svc.Port,
			Version:     "6.2.7",
			AuthEnabled: false,
			FakeKeys:    []string{"user:1001", "session:abc123", "cache:data"},
			Commands:    []string{"GET", "SET", "KEYS", "INFO", "CONFIG"},
			Databases:   16,
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = redis.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["redis"] = config

	case "rdp":
		config := &rdp.Config{
			Port:         svc.Port,
			ComputerName: "WIN-SERVER01",
			Domain:       "WORKGROUP",
			OSVersion:    "Windows Server 2019",
			FakeUsers:    []string{"Administrator", "Guest", "User"},
			NLAEnabled:   false,
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = rdp.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["rdp"] = config

	case "postgresql":
		config := &postgresql.Config{
			Port:          svc.Port,
			Version:       "PostgreSQL 13.7 on x86_64-pc-linux-gnu",
			FakeDatabases: []string{"postgres", "template0", "template1", "users", "inventory"},
			FakeSchemas:   map[string][]string{
				"public": []string{"users", "products", "orders"},
			},
			AuthMethods: []string{"md5", "trust"},
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = postgresql.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["postgresql"] = config

	case "vnc":
		config := &vnc.Config{
			Port:            svc.Port,
			ProtocolVersion: "RFB 003.008",
			AuthTypes:       []byte{1, 2},
			DesktopName:     "Ubuntu Desktop",
			ScreenWidth:     1920,
			ScreenHeight:    1080,
			PixelFormat:     "32bpp",
		}

		if svc.Config != "" {
			json.Unmarshal([]byte(svc.Config), config)
		}

		service, err = vnc.New(m.db, config)
		if err != nil {
			return err
		}

		m.configs["vnc"] = config

	default:
		return fmt.Errorf("unknown service: %s", svc.Name)
	}

	m.services[svc.Name] = service
	return nil
}

func (m *Manager) StartService(name string) error {
	m.mu.RLock()
	service, exists := m.services[name]
	m.mu.RUnlock()

	if !exists {
		// Try to create the service first
		services, err := m.db.GetServices()
		if err != nil {
			return err
		}

		for _, svc := range services {
			if svc.Name == name {
				if err := m.createService(svc); err != nil {
					return err
				}
				m.mu.RLock()
				service = m.services[name]
				m.mu.RUnlock()
				break
			}
		}

		if service == nil {
			return fmt.Errorf("service %s not found", name)
		}
	}

	if err := service.Start(); err != nil {
		return err
	}

	m.db.UpdateServiceStatus(name, "running")
	return nil
}

func (m *Manager) StopService(name string) error {
	m.mu.RLock()
	service, exists := m.services[name]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("service %s not found", name)
	}

	if err := service.Stop(); err != nil {
		return err
	}

	m.db.UpdateServiceStatus(name, "stopped")
	return nil
}

func (m *Manager) RestartService(name string) error {
	if err := m.StopService(name); err != nil {
		return err
	}
	return m.StartService(name)
}

func (m *Manager) StartAll() error {
	services, err := m.db.GetServices()
	if err != nil {
		return err
	}

	for _, svc := range services {
		if svc.Enabled {
			if err := m.StartService(svc.Name); err != nil {
				fmt.Printf("Failed to start %s: %v\n", svc.Name, err)
			}
		}
	}

	return nil
}

func (m *Manager) StopAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, service := range m.services {
		if err := service.Stop(); err != nil {
			fmt.Printf("Failed to stop %s: %v\n", name, err)
		}
		m.db.UpdateServiceStatus(name, "stopped")
	}

	return nil
}

func (m *Manager) GetStatus(name string) (string, error) {
	conn := m.db.Conn()

	var status string
	err := conn.QueryRow("SELECT status FROM honeypot_services WHERE name = ?", name).Scan(&status)
	return status, err
}

func (m *Manager) GetAllStatuses() (map[string]string, error) {
	services, err := m.db.GetServices()
	if err != nil {
		return nil, err
	}

	statuses := make(map[string]string)
	for _, svc := range services {
		statuses[svc.Name] = svc.Status
	}

	return statuses, nil
}