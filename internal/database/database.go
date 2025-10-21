package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
	path string
}

func New(path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	conn, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(0)
	conn.SetConnMaxIdleTime(0)

	db := &DB{
		conn: conn,
		path: path,
	}

	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return db, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) Conn() *sql.DB {
	return db.conn
}

func (db *DB) migrate() error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := db.createTables(tx); err != nil {
		return err
	}

	if err := db.insertDefaultData(tx); err != nil {
		return err
	}

	return tx.Commit()
}

func (db *DB) createTables(tx *sql.Tx) error {
	schema := `
	CREATE TABLE IF NOT EXISTS admin_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		email TEXT NOT NULL,
		full_name TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME,
		login_attempts INTEGER DEFAULT 0,
		locked_until DATETIME,
		active BOOLEAN DEFAULT TRUE,
		role TEXT DEFAULT 'admin',
		preferences TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_username ON admin_users(username);
	CREATE INDEX IF NOT EXISTS idx_email ON admin_users(email);

	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		ip_address TEXT NOT NULL,
		user_agent TEXT,
		last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
		active BOOLEAN DEFAULT TRUE,
		FOREIGN KEY (user_id) REFERENCES admin_users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_expires ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_user_id ON sessions(user_id);

	CREATE TABLE IF NOT EXISTS system_config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		description TEXT,
		category TEXT DEFAULT 'general',
		data_type TEXT DEFAULT 'string',
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_by INTEGER,
		FOREIGN KEY (updated_by) REFERENCES admin_users(id)
	);

	CREATE TABLE IF NOT EXISTS honeypot_services (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		display_name TEXT NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		enabled BOOLEAN DEFAULT TRUE,
		status TEXT DEFAULT 'stopped',
		bind_ip TEXT DEFAULT '0.0.0.0',
		max_connections INTEGER DEFAULT 100,
		connection_timeout INTEGER DEFAULT 30,
		banner TEXT,
		version_string TEXT,
		config TEXT,
		last_started DATETIME,
		last_stopped DATETIME,
		connection_count INTEGER DEFAULT 0,
		total_connections INTEGER DEFAULT 0,
		error_message TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_service_name ON honeypot_services(name);
	CREATE INDEX IF NOT EXISTS idx_service_port ON honeypot_services(port);
	CREATE INDEX IF NOT EXISTS idx_service_enabled ON honeypot_services(enabled);

	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		event_type TEXT NOT NULL,
		source_ip TEXT NOT NULL,
		source_port INTEGER,
		destination_port INTEGER NOT NULL,
		service_name TEXT NOT NULL,
		protocol TEXT NOT NULL,
		session_id TEXT,
		username TEXT,
		password TEXT,
		command TEXT,
		payload TEXT,
		payload_size INTEGER DEFAULT 0,
		response TEXT,
		severity TEXT DEFAULT 'medium',
		country_code TEXT,
		country_name TEXT,
		city TEXT,
		region TEXT,
		asn TEXT,
		asn_org TEXT,
		latitude REAL,
		longitude REAL,
		user_agent TEXT,
		request_headers TEXT,
		fingerprint TEXT,
		malware_detected BOOLEAN DEFAULT FALSE,
		honeypot_node TEXT DEFAULT 'local',
		tags TEXT,
		raw_data BLOB,
		processed BOOLEAN DEFAULT FALSE,
		archived BOOLEAN DEFAULT FALSE,
		FOREIGN KEY (service_name) REFERENCES honeypot_services(name)
	);

	CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_source_ip ON events(source_ip);
	CREATE INDEX IF NOT EXISTS idx_service ON events(service_name);
	CREATE INDEX IF NOT EXISTS idx_severity ON events(severity);
	CREATE INDEX IF NOT EXISTS idx_session_id ON events(session_id);
	CREATE INDEX IF NOT EXISTS idx_country ON events(country_code);
	CREATE INDEX IF NOT EXISTS idx_processed ON events(processed);

	CREATE TABLE IF NOT EXISTS attackers (
		ip TEXT PRIMARY KEY,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		total_attempts INTEGER DEFAULT 1,
		successful_logins INTEGER DEFAULT 0,
		services_targeted TEXT,
		countries TEXT,
		user_agents TEXT,
		usernames_tried TEXT,
		passwords_tried TEXT,
		commands_executed TEXT,
		attack_patterns TEXT,
		threat_level TEXT DEFAULT 'low',
		blocked BOOLEAN DEFAULT FALSE,
		blocked_until DATETIME,
		blocked_reason TEXT,
		whitelisted BOOLEAN DEFAULT FALSE,
		notes TEXT,
		last_country_code TEXT,
		last_asn TEXT,
		reputation_score INTEGER DEFAULT 0,
		campaign_id INTEGER
	);

	CREATE INDEX IF NOT EXISTS idx_last_seen ON attackers(last_seen);
	CREATE INDEX IF NOT EXISTS idx_blocked ON attackers(blocked);
	CREATE INDEX IF NOT EXISTS idx_threat_level ON attackers(threat_level);
	CREATE INDEX IF NOT EXISTS idx_reputation ON attackers(reputation_score);

	CREATE TABLE IF NOT EXISTS notifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL,
		category TEXT NOT NULL,
		title TEXT NOT NULL,
		message TEXT NOT NULL,
		severity TEXT DEFAULT 'medium',
		source_component TEXT,
		event_id INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		read_at DATETIME,
		acknowledged_at DATETIME,
		acknowledged_by INTEGER,
		dismissed BOOLEAN DEFAULT FALSE,
		auto_dismiss_at DATETIME,
		delivery_status TEXT,
		retry_count INTEGER DEFAULT 0,
		metadata TEXT,
		FOREIGN KEY (event_id) REFERENCES events(id),
		FOREIGN KEY (acknowledged_by) REFERENCES admin_users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_notif_created_at ON notifications(created_at);
	CREATE INDEX IF NOT EXISTS idx_notif_type ON notifications(type);
	CREATE INDEX IF NOT EXISTS idx_notif_severity ON notifications(severity);
	CREATE INDEX IF NOT EXISTS idx_notif_read_at ON notifications(read_at);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER,
		username TEXT NOT NULL,
		action TEXT NOT NULL,
		resource_type TEXT,
		resource_id TEXT,
		old_values TEXT,
		new_values TEXT,
		ip_address TEXT NOT NULL,
		user_agent TEXT,
		session_id TEXT,
		success BOOLEAN DEFAULT TRUE,
		error_message TEXT,
		FOREIGN KEY (user_id) REFERENCES admin_users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
	CREATE INDEX IF NOT EXISTS idx_audit_resource_type ON audit_log(resource_type);

	CREATE TABLE IF NOT EXISTS system_metrics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		metric_type TEXT NOT NULL,
		metric_name TEXT NOT NULL,
		metric_value REAL NOT NULL,
		unit TEXT,
		hostname TEXT DEFAULT 'local',
		service_name TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON system_metrics(timestamp);
	CREATE INDEX IF NOT EXISTS idx_metrics_type ON system_metrics(metric_type);
	CREATE INDEX IF NOT EXISTS idx_metrics_hostname ON system_metrics(hostname);
	`

	_, err := tx.Exec(schema)
	return err
}

func (db *DB) insertDefaultData(tx *sql.Tx) error {
	var count int
	err := tx.QueryRow("SELECT COUNT(*) FROM system_config").Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return nil
	}

	configs := []struct {
		key, value, description, category string
	}{
		{"server.bind_ip", "0.0.0.0", "Server bind IP address", "server"},
		{"server.admin_port", "8080", "Admin panel port", "server"},
		{"server.ssl_enabled", "false", "Enable SSL/TLS for admin panel", "server"},
		{"server.read_timeout", "30", "HTTP read timeout in seconds", "server"},
		{"server.write_timeout", "30", "HTTP write timeout in seconds", "server"},
		{"security.rate_limit_requests", "100", "Requests per minute per IP", "security"},
		{"security.rate_limit_window", "60", "Rate limit window in seconds", "security"},
		{"security.block_threshold", "10", "Failed attempts before IP block", "security"},
		{"security.block_duration", "3600", "IP block duration in seconds", "security"},
		{"security.session_timeout", "1800", "Session timeout in seconds", "security"},
		{"security.password_min_length", "12", "Minimum password length", "security"},
		{"security.bcrypt_cost", "12", "Bcrypt hashing cost", "security"},
		{"logging.level", "info", "Log level (debug, info, warn, error)", "logging"},
		{"logging.format", "json", "Log format (json, text)", "logging"},
		{"database.cleanup_interval", "86400", "Cleanup job interval in seconds", "database"},
		{"database.event_retention_days", "90", "Event retention period in days", "database"},
		{"alerts.enabled", "true", "Enable alerting system", "alerts"},
		{"honeypots.default_timeout", "30", "Default connection timeout", "honeypots"},
		{"honeypots.max_connections_per_ip", "10", "Max concurrent connections per IP", "honeypots"},
		{"ui.theme", "dark", "Default UI theme (light, dark)", "ui"},
		{"ui.items_per_page", "50", "Items per page in lists", "ui"},
		{"ui.refresh_interval", "5", "Dashboard refresh interval in seconds", "ui"},
	}

	for _, cfg := range configs {
		_, err = tx.Exec(
			"INSERT OR IGNORE INTO system_config (key, value, description, category) VALUES (?, ?, ?, ?)",
			cfg.key, cfg.value, cfg.description, cfg.category,
		)
		if err != nil {
			return err
		}
	}

	services := []struct {
		name, displayName, protocol, banner, version, config string
		port                                                  int
	}{
		{"ssh", "SSH Honeypot", "tcp", "SSH-2.0-OpenSSH_8.0", "OpenSSH_8.0", `{"motd":"Welcome to Ubuntu 20.04.3 LTS","fake_users":["root","admin","user","guest"],"commands":["ls","pwd","whoami","ps","netstat","cat","cd","mkdir","rm"]}`, 22},
		{"http", "HTTP Honeypot", "tcp", "Apache/2.4.41 (Ubuntu)", "Apache/2.4.41", `{"server_name":"Apache/2.4.41 (Ubuntu)","templates":["login","admin"],"upload_enabled":true}`, 80},
		{"https", "HTTPS Honeypot", "tcp", "Apache/2.4.41 (Ubuntu)", "Apache/2.4.41", `{"server_name":"Apache/2.4.41 (Ubuntu)","ssl_enabled":true,"templates":["login","admin"]}`, 443},
		{"ftp", "FTP Honeypot", "tcp", "220 FTP Server ready", "vsftpd 3.0.3", `{"welcome_message":"220 Welcome to FTP Server","allow_anonymous":true}`, 21},
		{"telnet", "Telnet Honeypot", "tcp", "Ubuntu 20.04.3 LTS", "Ubuntu 20.04.3", `{"login_prompt":"Ubuntu 20.04.3 LTS\\nlogin: ","password_prompt":"Password: "}`, 23},
		{"smtp", "SMTP Honeypot", "tcp", "220 mail.example.com ESMTP Postfix", "Postfix 3.4.13", `{"hostname":"mail.example.com","capabilities":["EHLO","AUTH LOGIN","STARTTLS"]}`, 25},
		{"dns", "DNS Honeypot", "udp", "", "BIND 9.16.1", `{"zone_transfer_enabled":true}`, 53},
		{"tftp", "TFTP Honeypot", "udp", "", "tftpd-hpa 5.2", `{"root_directory":"/tftpboot","timeout":5}`, 69},
		{"ldap", "LDAP Honeypot", "tcp", "", "OpenLDAP 2.4.50", `{"base_dn":"dc=example,dc=com","bind_dn":"cn=admin,dc=example,dc=com"}`, 389},
		{"smb", "SMB Honeypot", "tcp", "", "Samba 4.11.6", `{"shares":["Public","Users","Admin","Backup"],"workgroup":"WORKGROUP"}`, 445},
		{"syslog", "Syslog Honeypot", "udp", "", "rsyslog 8.2001.0", `{"facility_codes":[0,1,2,3,4,5,6]}`, 514},
		{"mysql", "MySQL Honeypot", "tcp", "5.7.34-0ubuntu0.18.04.1", "MySQL 5.7.34", `{"version":"5.7.34-0ubuntu0.18.04.1","auth_enabled":true}`, 3306},
		{"rdp", "RDP Honeypot", "tcp", "", "Windows Server 2019", `{"computer_name":"WIN-SERVER01","domain":"WORKGROUP"}`, 3389},
		{"postgresql", "PostgreSQL Honeypot", "tcp", "", "PostgreSQL 13.7", `{"version":"PostgreSQL 13.7","auth_methods":["md5","trust"]}`, 5432},
		{"vnc", "VNC Honeypot", "tcp", "RFB 003.008", "RealVNC 6.7.2", `{"protocol_version":"003.008","desktop_name":"Ubuntu Desktop"}`, 5900},
		{"redis", "Redis Honeypot", "tcp", "", "Redis 6.2.7", `{"version":"6.2.7","auth_enabled":false}`, 6379},
		{"snmp", "SNMP Honeypot", "udp", "", "Net-SNMP 5.8", `{"version":"v2c","community_strings":["public","private"]}`, 161},
	}

	for _, svc := range services {
		_, err = tx.Exec(
			`INSERT OR IGNORE INTO honeypot_services (name, display_name, port, protocol, banner, version_string, config)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			svc.name, svc.displayName, svc.port, svc.protocol, svc.banner, svc.version, svc.config,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (db *DB) IsFirstRun() (bool, error) {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM admin_users").Scan(&count)
	return count == 0, err
}

func (db *DB) CreateAdminUser(username, passwordHash, email, fullName string) error {
	_, err := db.conn.Exec(
		"INSERT INTO admin_users (username, password_hash, email, full_name) VALUES (?, ?, ?, ?)",
		username, passwordHash, email, fullName,
	)
	return err
}

func (db *DB) GetConfig(key string) (string, error) {
	var value string
	err := db.conn.QueryRow("SELECT value FROM system_config WHERE key = ?", key).Scan(&value)
	return value, err
}

func (db *DB) SetConfig(key, value string, userID int) error {
	_, err := db.conn.Exec(
		"UPDATE system_config SET value = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ? WHERE key = ?",
		value, userID, key,
	)
	return err
}

func (db *DB) LogEvent(event *Event) error {
	_, err := db.conn.Exec(
		`INSERT INTO events (event_type, source_ip, source_port, destination_port, service_name, protocol,
		session_id, username, password, command, payload, severity)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.EventType, event.SourceIP, event.SourcePort, event.DestPort, event.ServiceName, event.Protocol,
		event.SessionID, event.Username, event.Password, event.Command, event.Payload, event.Severity,
	)
	return err
}

type Event struct {
	ID          int64
	Timestamp   time.Time
	EventType   string
	SourceIP    string
	SourcePort  int
	DestPort    int
	ServiceName string
	Protocol    string
	SessionID   string
	Username    string
	Password    string
	Command     string
	Payload     string
	Severity    string
}

type Service struct {
	ID         int64
	Name       string
	Display    string
	Port       int
	Protocol   string
	Enabled    bool
	Status     string
	Config     string
}

func (db *DB) GetServices() ([]Service, error) {
	rows, err := db.conn.Query(
		"SELECT id, name, display_name, port, protocol, enabled, status, config FROM honeypot_services ORDER BY port",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []Service
	for rows.Next() {
		var s Service
		err := rows.Scan(&s.ID, &s.Name, &s.Display, &s.Port, &s.Protocol, &s.Enabled, &s.Status, &s.Config)
		if err != nil {
			return nil, err
		}
		services = append(services, s)
	}
	return services, rows.Err()
}

func (db *DB) UpdateServiceStatus(name, status string) error {
	_, err := db.conn.Exec(
		"UPDATE honeypot_services SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?",
		status, name,
	)
	return err
}