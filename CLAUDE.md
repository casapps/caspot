**caspot v1.0.0 - Complete Enterprise Honeypot Platform Specification**

## Project Overview
- **Name:** caspot
- **Organization:** casapps
- **License:** MIT (LICENSE.md)
- **Version:** 1.0.0 (production ready, no TODOs)
- **Distribution:** Static binary via GitHub releases
- **Binary naming:** `caspot-{os}-{arch}`

## Project Structure
```
caspot/
├── cmd/caspot/                 # Main application entry point
├── internal/
│   ├── admin/                 # Admin panel web interface
│   ├── auth/                  # Authentication & session management
│   ├── config/                # Database-based configuration
│   ├── database/              # SQLite database layer
│   ├── honeypots/             # All 17 honeypot services
│   │   ├── ssh/               # SSH honeypot (port 22)
│   │   ├── http/              # HTTP honeypot (port 80)
│   │   ├── https/             # HTTPS honeypot (port 443)
│   │   ├── ftp/               # FTP honeypot (port 21)
│   │   ├── telnet/            # Telnet honeypot (port 23)
│   │   ├── smtp/              # SMTP honeypot (port 25)
│   │   ├── dns/               # DNS honeypot (port 53)
│   │   ├── tftp/              # TFTP honeypot (port 69)
│   │   ├── ldap/              # LDAP honeypot (port 389/636)
│   │   ├── smb/               # SMB honeypot (port 445)
│   │   ├── syslog/            # Syslog honeypot (port 514)
│   │   ├── mysql/             # MySQL honeypot (port 3306)
│   │   ├── rdp/               # RDP honeypot (port 3389)
│   │   ├── postgresql/        # PostgreSQL honeypot (port 5432)
│   │   ├── vnc/               # VNC honeypot (port 5900)
│   │   ├── redis/             # Redis honeypot (port 6379)
│   │   └── snmp/              # SNMP honeypot (port 161)
│   ├── honeytokens/           # Honeytoken generation & management
│   ├── alerts/                # Multi-channel notification system
│   ├── scheduler/             # Built-in cron-like scheduler
│   ├── analytics/             # Attack correlation & analysis
│   ├── backup/                # Backup & recovery system
│   ├── api/                   # RESTful API endpoints
│   ├── clustering/            # High availability & distributed deployment
│   ├── deception/             # Advanced deception techniques
│   ├── forensics/             # Session recording & analysis
│   ├── geolocation/           # IP geolocation & blocking
│   ├── integrations/          # SIEM & external system connectors
│   ├── logging/               # Structured logging system
│   ├── metrics/               # Performance & monitoring metrics
│   ├── security/              # Security utilities & rate limiting
│   └── utils/                 # Common utilities
├── web/                       # Embedded admin panel assets
│   ├── static/                # CSS, JS, images
│   ├── templates/             # HTML templates
│   └── assets/                # Additional UI resources
├── configs/                   # Default configuration templates
├── scripts/                   # Installation & deployment scripts
├── docs/                      # Documentation
├── docker/                    # Docker configuration
├── kubernetes/                # K8s deployment manifests
├── cloud/                     # Cloud provider templates (AWS/Azure/GCP)
├── Makefile                   # Build system
├── Jenkinsfile               # CI/CD pipeline
├── Dockerfile                # Container build
├── docker-compose.yml        # Local development
├── go.mod                    # Go module definition
├── go.sum                    # Go module checksums
├── README.md                 # Project documentation
└── LICENSE.md                # MIT license
```

## Core Architecture

### 1. Single SQLite Database
- **File location (global):** `/var/lib/caspot/caspot.db`
- **File location (user):** `~/.caspot/caspot.db`
- **Configuration storage:** All settings in database tables
- **No config files:** Database-driven configuration
- **Embedded migrations:** Schema updates handled automatically

### 2. Static Binary Compilation
- **Pure Go:** `CGO_ENABLED=0` for static linking
- **SQLite driver:** `modernc.org/sqlite` (pure Go, no CGO)
- **Embedded assets:** Web UI, certificates, GeoIP data
- **Zero dependencies:** Single file deployment
- **Cross-platform:** Linux, Windows, macOS, ARM64, AMD64

### 3. Service Orchestration
- **Concurrent execution:** All services run simultaneously
- **Goroutine isolation:** Separate goroutine per service
- **Dynamic management:** Start/stop services without restart
- **Health monitoring:** Individual service status tracking
- **Auto-recovery:** Failed service automatic restart

## Database Schema

### Core Tables
```sql
-- Admin users and authentication
CREATE TABLE admin_users (
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
    preferences TEXT,  -- JSON user preferences
    INDEX idx_username (username),
    INDEX idx_email (email)
);

-- Session management
CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES admin_users(id),
    INDEX idx_expires (expires_at),
    INDEX idx_user_id (user_id)
);

-- System configuration
CREATE TABLE system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    category TEXT DEFAULT 'general',
    data_type TEXT DEFAULT 'string',  -- string, integer, boolean, json
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER,
    FOREIGN KEY (updated_by) REFERENCES admin_users(id)
);

-- Honeypot services configuration
CREATE TABLE honeypot_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,  -- tcp, udp, both
    enabled BOOLEAN DEFAULT TRUE,
    status TEXT DEFAULT 'stopped',  -- stopped, starting, running, error
    bind_ip TEXT DEFAULT '0.0.0.0',
    max_connections INTEGER DEFAULT 100,
    connection_timeout INTEGER DEFAULT 30,
    banner TEXT,
    version_string TEXT,
    config TEXT,  -- JSON service-specific configuration
    last_started DATETIME,
    last_stopped DATETIME,
    connection_count INTEGER DEFAULT 0,
    total_connections INTEGER DEFAULT 0,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_port (port),
    INDEX idx_enabled (enabled)
);

-- Attack events and logs
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,  -- connection, authentication, command, data_transfer
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
    severity TEXT DEFAULT 'medium',  -- low, medium, high, critical
    country_code TEXT,
    country_name TEXT,
    city TEXT,
    region TEXT,
    asn TEXT,
    asn_org TEXT,
    latitude REAL,
    longitude REAL,
    user_agent TEXT,
    request_headers TEXT,  -- JSON
    fingerprint TEXT,
    malware_detected BOOLEAN DEFAULT FALSE,
    honeypot_node TEXT DEFAULT 'local',
    tags TEXT,  -- JSON array
    raw_data BLOB,  -- Full packet capture if enabled
    processed BOOLEAN DEFAULT FALSE,
    archived BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (service_name) REFERENCES honeypot_services(name),
    INDEX idx_timestamp (timestamp),
    INDEX idx_source_ip (source_ip),
    INDEX idx_service (service_name),
    INDEX idx_severity (severity),
    INDEX idx_session_id (session_id),
    INDEX idx_country (country_code),
    INDEX idx_processed (processed)
);

-- Attacker tracking and profiling
CREATE TABLE attackers (
    ip TEXT PRIMARY KEY,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_attempts INTEGER DEFAULT 1,
    successful_logins INTEGER DEFAULT 0,
    services_targeted TEXT,  -- JSON array
    countries TEXT,  -- JSON array (if IP changes location)
    user_agents TEXT,  -- JSON array
    usernames_tried TEXT,  -- JSON array
    passwords_tried TEXT,  -- JSON array
    commands_executed TEXT,  -- JSON array
    attack_patterns TEXT,  -- JSON array
    threat_level TEXT DEFAULT 'low',  -- low, medium, high, critical
    blocked BOOLEAN DEFAULT FALSE,
    blocked_until DATETIME,
    blocked_reason TEXT,
    whitelisted BOOLEAN DEFAULT FALSE,
    notes TEXT,
    last_country_code TEXT,
    last_asn TEXT,
    reputation_score INTEGER DEFAULT 0,  -- 0-100 threat score
    campaign_id INTEGER,
    INDEX idx_last_seen (last_seen),
    INDEX idx_blocked (blocked),
    INDEX idx_threat_level (threat_level),
    INDEX idx_reputation (reputation_score),
    FOREIGN KEY (campaign_id) REFERENCES attack_campaigns(id)
);

-- Attack campaign tracking
CREATE TABLE attack_campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    first_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_attackers INTEGER DEFAULT 1,
    total_attempts INTEGER DEFAULT 1,
    services_targeted TEXT,  -- JSON array
    countries_involved TEXT,  -- JSON array
    attack_vectors TEXT,  -- JSON array
    malware_families TEXT,  -- JSON array
    iocs TEXT,  -- JSON array of indicators of compromise
    threat_actor TEXT,
    confidence_level TEXT DEFAULT 'low',  -- low, medium, high
    status TEXT DEFAULT 'active',  -- active, inactive, archived
    severity TEXT DEFAULT 'medium',
    analyst_notes TEXT,
    external_references TEXT,  -- JSON array
    mitre_tactics TEXT,  -- JSON array
    mitre_techniques TEXT,  -- JSON array
    INDEX idx_last_activity (last_activity),
    INDEX idx_status (status),
    INDEX idx_severity (severity)
);

-- Honeytokens management
CREATE TABLE honeytokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_type TEXT NOT NULL,  -- file, dns, credential, database, email, api
    token_name TEXT NOT NULL,
    token_value TEXT NOT NULL,
    deployment_location TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    deployed_at DATETIME,
    last_triggered DATETIME,
    trigger_count INTEGER DEFAULT 0,
    active BOOLEAN DEFAULT TRUE,
    auto_regenerate BOOLEAN DEFAULT FALSE,
    regenerate_interval INTEGER DEFAULT 2592000,  -- 30 days
    alert_enabled BOOLEAN DEFAULT TRUE,
    metadata TEXT,  -- JSON additional data
    INDEX idx_token_type (token_type),
    INDEX idx_active (active),
    INDEX idx_last_triggered (last_triggered)
);

-- Honeytoken trigger events
CREATE TABLE honeytoken_triggers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id INTEGER NOT NULL,
    triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT NOT NULL,
    source_details TEXT,  -- JSON with country, ASN, etc.
    trigger_context TEXT,  -- How token was accessed
    user_agent TEXT,
    request_data TEXT,  -- Full request that triggered
    response_sent TEXT,   -- Response given to attacker
    severity TEXT DEFAULT 'high',
    investigated BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,
    analyst_notes TEXT,
    FOREIGN KEY (token_id) REFERENCES honeytokens(id),
    INDEX idx_triggered_at (triggered_at),
    INDEX idx_token_id (token_id),
    INDEX idx_source_ip (source_ip),
    INDEX idx_investigated (investigated)
);

-- Scheduled jobs and automation
CREATE TABLE scheduled_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    job_type TEXT NOT NULL,  -- cleanup, backup, report, analysis, token_rotation
    cron_expression TEXT NOT NULL,
    job_config TEXT,  -- JSON configuration
    enabled BOOLEAN DEFAULT TRUE,
    last_run DATETIME,
    next_run DATETIME,
    run_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    retry_delay INTEGER DEFAULT 300,  -- seconds
    timeout INTEGER DEFAULT 3600,    -- seconds
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER,
    FOREIGN KEY (created_by) REFERENCES admin_users(id),
    INDEX idx_next_run (next_run),
    INDEX idx_enabled (enabled)
);

-- Job execution history
CREATE TABLE job_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    status TEXT NOT NULL,  -- running, completed, failed, timeout
    exit_code INTEGER,
    output TEXT,
    error_message TEXT,
    execution_time INTEGER,  -- milliseconds
    memory_used INTEGER,     -- bytes
    retry_attempt INTEGER DEFAULT 0,
    triggered_by TEXT DEFAULT 'scheduler',  -- scheduler, manual, api
    triggered_by_user INTEGER,
    FOREIGN KEY (job_id) REFERENCES scheduled_jobs(id),
    FOREIGN KEY (triggered_by_user) REFERENCES admin_users(id),
    INDEX idx_started_at (started_at),
    INDEX idx_job_id (job_id),
    INDEX idx_status (status)
);

-- Notifications and alerts
CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,  -- emergency, attack, service, system, token, campaign
    category TEXT NOT NULL,  -- real_time, email, webhook, sms
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',  -- low, medium, high, critical
    source_component TEXT,  -- honeypot service or system component
    event_id INTEGER,  -- Reference to related event
    token_id INTEGER,  -- Reference to honeytoken if applicable
    campaign_id INTEGER,  -- Reference to campaign if applicable
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    read_at DATETIME,
    acknowledged_at DATETIME,
    acknowledged_by INTEGER,
    dismissed BOOLEAN DEFAULT FALSE,
    auto_dismiss_at DATETIME,
    delivery_status TEXT,  -- JSON with email/webhook delivery status
    retry_count INTEGER DEFAULT 0,
    metadata TEXT,  -- JSON additional context
    FOREIGN KEY (event_id) REFERENCES events(id),
    FOREIGN KEY (token_id) REFERENCES honeytokens(id),
    FOREIGN KEY (campaign_id) REFERENCES attack_campaigns(id),
    FOREIGN KEY (acknowledged_by) REFERENCES admin_users(id),
    INDEX idx_created_at (created_at),
    INDEX idx_type (type),
    INDEX idx_severity (severity),
    INDEX idx_read_at (read_at)
);

-- Webhook configurations
CREATE TABLE webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'POST',
    headers TEXT,  -- JSON headers
    secret TEXT,   -- For HMAC signing
    event_types TEXT,  -- JSON array of event types to send
    severity_filter TEXT DEFAULT 'medium',  -- minimum severity
    service_filter TEXT,  -- JSON array of services
    enabled BOOLEAN DEFAULT TRUE,
    ssl_verify BOOLEAN DEFAULT TRUE,
    timeout INTEGER DEFAULT 30,
    retry_attempts INTEGER DEFAULT 3,
    retry_delay INTEGER DEFAULT 60,
    last_success DATETIME,
    last_failure DATETIME,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER,
    FOREIGN KEY (created_by) REFERENCES admin_users(id),
    INDEX idx_enabled (enabled),
    INDEX idx_name (name)
);

-- SMTP configurations
CREATE TABLE smtp_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    smtp_host TEXT NOT NULL,
    smtp_port INTEGER NOT NULL,
    security_type TEXT NOT NULL,  -- NONE, STARTTLS, SSL_TLS
    username TEXT,
    password_encrypted TEXT,
    from_name TEXT NOT NULL,
    from_address TEXT NOT NULL,
    admin_email TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    ssl_verify BOOLEAN DEFAULT TRUE,
    timeout INTEGER DEFAULT 30,
    max_retries INTEGER DEFAULT 3,
    retry_delay INTEGER DEFAULT 60,
    last_test DATETIME,
    test_success BOOLEAN,
    test_error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_enabled (enabled),
    INDEX idx_name (name)
);

-- Distributed honeypot nodes
CREATE TABLE honeypot_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_name TEXT UNIQUE NOT NULL,
    node_type TEXT DEFAULT 'agent',  -- master, agent, standalone
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    port INTEGER DEFAULT 8080,
    api_key TEXT NOT NULL,
    last_checkin DATETIME,
    status TEXT DEFAULT 'offline',  -- online, offline, error, maintenance
    version TEXT,
    os_type TEXT,
    architecture TEXT,
    services_running TEXT,  -- JSON array
    resource_usage TEXT,   -- JSON with CPU, memory, disk
    location TEXT,  -- Physical location description
    network_zone TEXT,
    contact_info TEXT,
    maintenance_window TEXT,  -- JSON schedule
    config_hash TEXT,  -- For config sync verification
    log_level TEXT DEFAULT 'info',
    max_events_per_hour INTEGER DEFAULT 10000,
    auto_update BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_last_checkin (last_checkin),
    INDEX idx_node_name (node_name)
);

-- Threat intelligence feeds
CREATE TABLE threat_intel_feeds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    feed_type TEXT NOT NULL,  -- ip_reputation, domain_reputation, malware_hash
    source_url TEXT NOT NULL,
    update_frequency INTEGER DEFAULT 3600,  -- seconds
    format TEXT DEFAULT 'json',  -- json, csv, xml, txt
    auth_type TEXT DEFAULT 'none',  -- none, api_key, basic_auth
    auth_config TEXT,  -- JSON auth configuration
    last_update DATETIME,
    next_update DATETIME,
    update_success BOOLEAN,
    update_error TEXT,
    record_count INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT TRUE,
    confidence_weight REAL DEFAULT 1.0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_next_update (next_update),
    INDEX idx_enabled (enabled)
);

-- Threat intelligence data
CREATE TABLE threat_intel_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_id INTEGER NOT NULL,
    indicator_type TEXT NOT NULL,  -- ip, domain, hash, url
    indicator_value TEXT NOT NULL,
    threat_type TEXT,  -- malware, phishing, botnet, scanner
    confidence INTEGER DEFAULT 50,  -- 0-100
    severity TEXT DEFAULT 'medium',
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    metadata TEXT,  -- JSON additional data
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (feed_id) REFERENCES threat_intel_feeds(id),
    INDEX idx_indicator (indicator_type, indicator_value),
    INDEX idx_threat_type (threat_type),
    INDEX idx_expires_at (expires_at),
    UNIQUE(feed_id, indicator_type, indicator_value)
);

-- File uploads and malware samples
CREATE TABLE file_uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT,
    md5_hash TEXT NOT NULL,
    sha1_hash TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    upload_ip TEXT NOT NULL,
    upload_service TEXT NOT NULL,
    upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    file_path TEXT NOT NULL,
    malware_scan_result TEXT,  -- JSON scan results
    is_malware BOOLEAN DEFAULT FALSE,
    quarantined BOOLEAN DEFAULT TRUE,
    analyzed BOOLEAN DEFAULT FALSE,
    analysis_results TEXT,  -- JSON analysis data
    honeypot_node TEXT DEFAULT 'local',
    session_id TEXT,
    event_id INTEGER,
    FOREIGN KEY (event_id) REFERENCES events(id),
    INDEX idx_upload_time (upload_time),
    INDEX idx_sha256 (sha256_hash),
    INDEX idx_is_malware (is_malware),
    INDEX idx_upload_ip (upload_ip)
);

-- Audit log for administrative actions
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT,  -- user, service, config, token, etc.
    resource_id TEXT,
    old_values TEXT,  -- JSON before change
    new_values TEXT,  -- JSON after change
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    session_id TEXT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    FOREIGN KEY (user_id) REFERENCES admin_users(id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_resource_type (resource_type)
);

-- System metrics and performance data
CREATE TABLE system_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    metric_type TEXT NOT NULL,  -- cpu, memory, disk, network, connections
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    unit TEXT,
    hostname TEXT DEFAULT 'local',
    service_name TEXT,
    INDEX idx_timestamp (timestamp),
    INDEX idx_metric_type (metric_type),
    INDEX idx_hostname (hostname)
);
```

## Default System Configuration

### 1. First User Flow
```sql
-- Default system settings inserted on first run
INSERT INTO system_config (key, value, description, category) VALUES
-- Server settings
('server.bind_ip', '0.0.0.0', 'Server bind IP address', 'server'),
('server.admin_port', '8080', 'Admin panel port', 'server'),
('server.ssl_enabled', 'true', 'Enable SSL/TLS for admin panel', 'server'),
('server.ssl_cert_path', '/etc/letsencrypt/live/domain/fullchain.pem', 'SSL certificate path', 'server'),
('server.ssl_key_path', '/etc/letsencrypt/live/domain/privkey.pem', 'SSL private key path', 'server'),
('server.read_timeout', '30', 'HTTP read timeout in seconds', 'server'),
('server.write_timeout', '30', 'HTTP write timeout in seconds', 'server'),

-- Security settings
('security.rate_limit_requests', '100', 'Requests per minute per IP', 'security'),
('security.rate_limit_window', '60', 'Rate limit window in seconds', 'security'),
('security.block_threshold', '10', 'Failed attempts before IP block', 'security'),
('security.block_duration', '3600', 'IP block duration in seconds', 'security'),
('security.session_timeout', '1800', 'Session timeout in seconds', 'security'),
('security.password_min_length', '12', 'Minimum password length', 'security'),
('security.password_require_special', 'true', 'Require special characters in passwords', 'security'),
('security.login_max_attempts', '5', 'Max login attempts before lockout', 'security'),
('security.lockout_duration', '900', 'Account lockout duration in seconds', 'security'),
('security.bcrypt_cost', '12', 'Bcrypt hashing cost', 'security'),

-- Logging settings
('logging.level', 'info', 'Log level (debug, info, warn, error)', 'logging'),
('logging.format', 'json', 'Log format (json, text)', 'logging'),
('logging.max_file_size', '100', 'Max log file size in MB', 'logging'),
('logging.max_backups', '5', 'Number of log backups to keep', 'logging'),
('logging.max_age', '30', 'Max age of log files in days', 'logging'),
('logging.compress_backups', 'true', 'Compress old log files', 'logging'),

-- Database settings
('database.cleanup_interval', '86400', 'Cleanup job interval in seconds', 'database'),
('database.event_retention_days', '90', 'Event retention period in days', 'database'),
('database.audit_retention_days', '365', 'Audit log retention in days', 'database'),
('database.metrics_retention_days', '30', 'Metrics retention in days', 'database'),
('database.backup_enabled', 'true', 'Enable automatic backups', 'database'),
('database.backup_interval', '86400', 'Backup interval in seconds', 'database'),
('database.backup_retention', '7', 'Number of backups to keep', 'database'),

-- Alert settings
('alerts.enabled', 'true', 'Enable alerting system', 'alerts'),
('alerts.default_severity', 'medium', 'Default alert severity', 'alerts'),
('alerts.rate_limit', '10', 'Max alerts per minute', 'alerts'),
('alerts.dedupe_window', '300', 'Alert deduplication window in seconds', 'alerts'),
('alerts.auto_dismiss_timeout', '86400', 'Auto-dismiss timeout in seconds', 'alerts'),

-- Geolocation settings
('geo.enabled', 'true', 'Enable IP geolocation', 'geo'),
('geo.block_countries', '[]', 'JSON array of blocked country codes', 'geo'),
('geo.allow_countries', '[]', 'JSON array of allowed country codes (empty = all)', 'geo'),
('geo.database_path', '/var/lib/caspot/GeoLite2-City.mmdb', 'GeoIP database path', 'geo'),

-- Honeypot global settings
('honeypots.default_timeout', '30', 'Default connection timeout', 'honeypots'),
('honeypots.max_connections_per_ip', '10', 'Max concurrent connections per IP', 'honeypots'),
('honeypots.session_recording', 'true', 'Enable session recording', 'honeypots'),
('honeypots.packet_capture', 'false', 'Enable packet capture', 'honeypots'),
('honeypots.response_delay_min', '100', 'Min response delay in ms', 'honeypots'),
('honeypots.response_delay_max', '500', 'Max response delay in ms', 'honeypots'),

-- Token settings
('tokens.auto_generate', 'true', 'Auto-generate honeytokens', 'tokens'),
('tokens.rotation_interval', '2592000', 'Token rotation interval in seconds', 'tokens'),
('tokens.dns_domain', 'honeypot.internal', 'DNS canary domain', 'tokens'),

-- Clustering settings
('cluster.enabled', 'false', 'Enable clustering mode', 'cluster'),
('cluster.node_name', 'primary', 'This node name', 'cluster'),
('cluster.api_key', '', 'Cluster API key', 'cluster'),

-- Integration settings
('integrations.prometheus_enabled', 'false', 'Enable Prometheus metrics', 'integrations'),
('integrations.prometheus_port', '9090', 'Prometheus metrics port', 'integrations'),
('integrations.syslog_enabled', 'false', 'Enable syslog forwarding', 'integrations'),
('integrations.syslog_server', '', 'Syslog server address', 'integrations'),

-- UI settings
('ui.theme', 'dark', 'Default UI theme (light, dark)', 'ui'),
('ui.items_per_page', '50', 'Items per page in lists', 'ui'),
('ui.refresh_interval', '5', 'Dashboard refresh interval in seconds', 'ui'),
('ui.timezone', 'UTC', 'Default timezone', 'ui');
```

### 2. Default Honeypot Services
```sql
-- Default honeypot service configurations
INSERT INTO honeypot_services (name, display_name, port, protocol, enabled, banner, version_string, config) VALUES
('ssh', 'SSH Honeypot', 22, 'tcp', true, 'SSH-2.0-OpenSSH_8.0', 'OpenSSH_8.0', '{"motd":"Welcome to Ubuntu 20.04.3 LTS","fake_users":["root","admin","user","guest"],"commands":["ls","pwd","whoami","ps","netstat","cat","cd","mkdir","rm"],"filesystem":{"/etc/passwd":"root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash","/.bash_history":"ls -la\ncd /var/log\ncat /etc/passwd\nsudo su"}}'),

('http', 'HTTP Honeypot', 80, 'tcp', true, 'Apache/2.4.41 (Ubuntu)', 'Apache/2.4.41', '{"server_name":"Apache/2.4.41 (Ubuntu)","templates":["login","admin","phpmyadmin","wordpress"],"upload_enabled":true,"fake_files":["/admin.php","/config.php","/backup.sql","/passwords.txt"],"vulnerabilities":["sql_injection","xss","lfi","rfi"]}'),

('https', 'HTTPS Honeypot', 443, 'tcp', true, 'Apache/2.4.41 (Ubuntu)', 'Apache/2.4.41', '{"server_name":"Apache/2.4.41 (Ubuntu)","ssl_enabled":true,"templates":["login","admin","phpmyadmin","wordpress"],"upload_enabled":true,"fake_files":["/admin.php","/config.php","/backup.sql","/passwords.txt"],"vulnerabilities":["sql_injection","xss","lfi","rfi"]}'),

('ftp', 'FTP Honeypot', 21, 'tcp', true, '220 FTP Server ready', 'vsftpd 3.0.3', '{"welcome_message":"220 Welcome to FTP Server","allow_anonymous":true,"fake_files":["/pub/readme.txt","/pub/backup.zip","/confidential/passwords.txt"],"commands":["LIST","RETR","STOR","CWD","PWD","DELE"]}'),

('telnet', 'Telnet Honeypot', 23, 'tcp', true, 'Ubuntu 20.04.3 LTS', 'Ubuntu 20.04.3', '{"login_prompt":"Ubuntu 20.04.3 LTS\\nlogin: ","password_prompt":"Password: ","fake_system":"Ubuntu 20.04.3 LTS kernel 5.4.0-74-generic","commands":["ls","pwd","whoami","ps","netstat","cat","cd"]}'),

('smtp', 'SMTP Honeypot', 25, 'tcp', true, '220 mail.example.com ESMTP Postfix', 'Postfix 3.4.13', '{"hostname":"mail.example.com","capabilities":["EHLO","AUTH LOGIN","STARTTLS"],"auth_types":["LOGIN","PLAIN"],"max_message_size":10485760}'),

('dns', 'DNS Honeypot', 53, 'udp', true, '', 'BIND 9.16.1', '{"poison_domains":["malware.example","phishing.test","suspicious.local"],"fake_records":{"A":{"admin.local":"192.168.1.100","db.local":"192.168.1.200"},"MX":{"local":"mail.local"}},"zone_transfer_enabled":true}'),

('tftp', 'TFTP Honeypot', 69, 'udp', true, '', 'tftpd-hpa 5.2', '{"root_directory":"/tftpboot","fake_files":["config.txt","firmware.bin","backup.cfg"],"allow_upload":true,"timeout":5}'),

('ldap', 'LDAP Honeypot', 389, 'tcp', true, '', 'OpenLDAP 2.4.50', '{"base_dn":"dc=example,dc=com","bind_dn":"cn=admin,dc=example,dc=com","fake_users":["cn=admin,dc=example,dc=com","cn=john,ou=users,dc=example,dc=com"],"allow_anonymous":true}'),

('smb', 'SMB Honeypot', 445, 'tcp', true, '', 'Samba 4.11.6', '{"shares":["Public","Users","Admin","Backup"],"workgroup":"WORKGROUP","server_name":"FILE-SERVER","fake_files":{"Public":["readme.txt","info.doc"],"Admin":["passwords.xlsx","config.xml"]}}'),

('syslog', 'Syslog Honeypot', 514, 'udp', true, '', 'rsyslog 8.2001.0', '{"facility_codes":[0,1,2,3,4,5,6],"severity_levels":[0,1,2,3,4,5,6,7],"fake_sources":["router","firewall","server"],"log_everything":true}'),

('mysql', 'MySQL Honeypot', 3306, 'tcp', true, '5.7.34-0ubuntu0.18.04.1', 'MySQL 5.7.34', '{"version":"5.7.34-0ubuntu0.18.04.1","fake_databases":["information_schema","mysql","performance_schema","users","products"],"fake_tables":{"users":["id","username","password","email"],"products":["id","name","price"]},"auth_enabled":true}'),

('rdp', 'RDP Honeypot', 3389, 'tcp', true, '', 'Windows Server 2019', '{"computer_name":"WIN-SERVER01","domain":"WORKGROUP","os_version":"Windows Server 2019","fake_users":["Administrator","Guest","User"],"nla_enabled":false}'),

('postgresql', 'PostgreSQL Honeypot', 5432, 'tcp', true, '', 'PostgreSQL 13.7', '{"version":"PostgreSQL 13.7 on x86_64-pc-linux-gnu","fake_databases":["postgres","template0","template1","users","inventory"],"fake_schemas":{"public":["users","products","orders"]},"auth_methods":["md5","trust"]}'),

('vnc', 'VNC Honeypot', 5900, 'tcp', true, 'RFB 003.008', 'RealVNC 6.7.2', '{"protocol_version":"003.008","authentication_types":[1,2],"desktop_name":"Ubuntu Desktop","screen_width":1920,"screen_height":1080,"pixel_format":"32bpp"}'),

('redis', 'Redis Honeypot', 6379, 'tcp', true, '', 'Redis 6.2.7', '{"version":"6.2.7","auth_enabled":false,"fake_keys":["user:1001","session:abc123","cache:data"],"commands":["GET","SET","KEYS","INFO","CONFIG"],"databases":16}'),

('snmp', 'SNMP Honeypot', 161, 'udp', true, '', 'Net-SNMP 5.8', '{"version":"v2c","community_strings":["public","private"],"system_description":"Linux router 4.15.0-142-generic","fake_oids":{"1.3.6.1.2.1.1.1.0":"Linux router 4.15.0-142-generic","1.3.6.1.2.1.1.5.0":"router.local"}}');
```

### 3. Default Scheduled Jobs
```sql
INSERT INTO scheduled_jobs (name, description, job_type, cron_expression, job_config, enabled) VALUES
-- Daily cleanup at 2 AM
('daily_cleanup', 'Clean up old events and logs', 'cleanup', '0 2 * * *', '{"event_retention_days":90,"audit_retention_days":365,"metrics_retention_days":30}', true),

-- Hourly database optimization
('hourly_optimize', 'Optimize database performance', 'optimize', '0 * * * *', '{"vacuum":true,"analyze":true,"reindex":false}', true),

-- Daily backup at 3 AM
('daily_backup', 'Create daily database backup', 'backup', '0 3 * * *', '{"compression":true,"retention_days":7,"include_uploads":false}', true),

-- Weekly report on Sundays at 6 AM
('weekly_report', 'Generate weekly attack report', 'report', '0 6 * * 0', '{"report_type":"weekly","include_charts":true,"email_enabled":true}', true),

-- Monthly honeytoken rotation
('monthly_token_rotation', 'Rotate honeytokens monthly', 'token_rotation', '0 0 1 * *', '{"token_types":["dns","credential"],"force_regenerate":true}', true),

-- Threat intelligence feed updates every 4 hours
('threat_intel_update', 'Update threat intelligence feeds', 'threat_intel', '0 */4 * * *', '{"feeds":["all"],"confidence_threshold":70}', true),

-- Service health check every 5 minutes
('service_health_check', 'Check honeypot service health', 'health_check', '*/5 * * * *', '{"restart_failed":true,"alert_on_failure":true}', true),

-- GeoIP database update weekly
('geoip_update', 'Update GeoIP database', 'geoip_update', '0 4 * * 1', '{"source":"maxmind","auto_download":true}', true);
```

### 4. Default SMTP Configuration (Disabled)
```sql
INSERT INTO smtp_configs (name, smtp_host, smtp_port, security_type, from_name, from_address, admin_email, enabled) VALUES
('default', 'localhost', 587, 'STARTTLS', 'caspot Honeypot', 'caspot@localhost', 'admin@localhost', false);
```

### 5. Default Webhooks (None)
```sql
-- No default webhooks - user must configure
```

### 6. Default Admin User
```sql
-- Created during first-time setup wizard
-- Username: administrator
-- Password: User-defined during setup
-- Email: User-defined during setup
```

## First User Flow - Setup Wizard

### Step 1: Administrator Account Creation
- **Username:** `administrator` (pre-filled, non-editable)
- **Password:** Minimum 12 characters, complexity validation
- **Confirm Password:** Real-time validation
- **Email:** For alerts and recovery (required)
- **Full Name:** (optional)

### Step 2: Network Configuration
- **Server Bind IP:** Default `0.0.0.0`
- **Admin Panel Port:** Default `8080`
- **SSL Certificate Path:** Default `/etc/letsencrypt/live/domain/fullchain.pem`
- **SSL Private Key Path:** Default `/etc/letsencrypt/live/domain/privkey.pem`
- **Enable SSL:** Auto-detect if certificates exist
- **Connection Test:** Validate network settings

### Step 3: Security Settings
- **Rate Limiting:** Default 100 requests/minute per IP
- **Auto-block Threshold:** Default 10 failed attempts
- **Block Duration:** Default 3600 seconds (1 hour)
- **Session Timeout:** Default 1800 seconds (30 minutes)
- **Password Policy:** Configurable complexity requirements

### Step 4: Alert Configuration
- **Email Alerts:** Enable/disable with SMTP configuration
- **Provider Quick Setup:** Gmail, Yahoo, Custom options
- **SMTP Settings:** Host, port, security, authentication
- **Test Email:** Send test alert to verify configuration
- **Webhook Integration:** Optional webhook URL configuration
- **Notification Types:** Select which events trigger alerts

### Step 5: Honeypot Services
- **Service Selection:** Checkboxes for all 17 services (all enabled by default)
- **Port Configuration:** Modify default ports if needed
- **Bulk Actions:** Enable/disable all, reset to defaults
- **Advanced Settings:** Per-service configuration options
- **Conflict Detection:** Warn about port conflicts

### Step 6: Data Management
- **Storage Location:** Global (`/var/lib/caspot/`) or user (`~/.caspot/`)
- **Data Retention:** Events (90 days), Audit logs (365 days), Metrics (30 days)
- **Backup Settings:** Enable automatic backups, retention policy
- **Log Management:** Log level, rotation, compression

### Step 7: Review & Launch
- **Configuration Summary:** Review all settings
- **Validation Check:** Ensure all settings are valid
- **Service Test:** Test honeypot service binding
- **Launch Services:** Start all enabled honeypots
- **Setup Completion:** Redirect to main dashboard

## Honeypot Service Specifications

### 1. SSH Honeypot (Port 22)
- **Protocol:** SSH 2.0
- **Banner:** `SSH-2.0-OpenSSH_8.0`
- **Authentication:** Always fails after credential capture
- **Shell Simulation:** Bash-like command interface
- **File System:** Realistic Linux directory structure
- **Commands Supported:** `ls`, `pwd`, `whoami`, `ps`, `netstat`, `cat`, `cd`, `mkdir`, `rm`, `chmod`, `chown`, `grep`, `find`, `top`, `history`
- **Session Recording:** Full terminal session capture
- **Key Exchange:** Complete SSH handshake simulation

### 2. HTTP Honeypot (Port 80)
- **Server:** Apache/2.4.41 simulation
- **Templates:** Login forms, admin panels, phpMyAdmin, WordPress
- **Vulnerabilities:** SQL injection, XSS, LFI, RFI endpoints
- **File Upload:** Malware capture and analysis
- **Session Management:** Cookies, CSRF tokens
- **Response Codes:** Realistic HTTP status responses
- **Directory Listing:** Fake sensitive directories

### 3. HTTPS Honeypot (Port 443)
- **SSL/TLS:** Self-signed or Let's Encrypt certificates
- **Cipher Suites:** Modern and legacy cipher support
- **Same as HTTP:** All HTTP features with encryption
- **Certificate Spoofing:** Mimic legitimate services
- **SNI Support:** Multiple virtual hosts

### 4. FTP Honeypot (Port 21)
- **Protocol:** FTP (RFC 959)
- **Modes:** Active and passive mode support
- **Anonymous Access:** Enabled by default
- **Authentication:** Username/password collection
- **Commands:** `LIST`, `RETR`, `STOR`, `CWD`, `PWD`, `DELE`, `MKD`, `RMD`
- **File System:** Fake file structure with enticing files
- **Transfer Simulation:** File upload/download logging

### 5. Telnet Honeypot (Port 23)
- **Protocol:** Telnet (RFC 854)
- **Login Simulation:** Unix/Linux login prompts
- **Terminal Emulation:** Basic VT100 compatibility
- **Command Logging:** Full session capture
- **System Information:** Fake system details and users

### 6. SMTP Honeypot (Port 25)
- **Protocol:** SMTP (RFC 5321)
- **Extensions:** EHLO, AUTH, STARTTLS
- **Open Relay:** Accepts all emails
- **Authentication:** SMTP AUTH credential capture
- **Commands:** `HELO`, `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`
- **Spam Collection:** Email content and attachment logging

### 7. DNS Honeypot (Port 53)
- **Protocol:** DNS (RFC 1035)
- **Transport:** UDP and TCP support
- **Query Types:** A, AAAA, MX, NS, TXT, PTR
- **Poisoned Responses:** Configurable fake records
- **Zone Transfer:** AXFR simulation with fake zone data
- **Recursive Queries:** Fake recursive resolver

### 8. TFTP Honeypot (Port 69)
- **Protocol:** TFTP (RFC 1350)
- **Operations:** Read and write requests
- **File System:** Fake firmware and configuration files
- **Block Size:** Configurable block size support
- **Timeout Handling:** Realistic timeout behavior

### 9. LDAP Honeypot (Port 389/636)
- **Protocol:** LDAP v3 (RFC 4511)
- **Authentication:** Anonymous and simple bind
- **Operations:** Search, bind, compare
- **Schema:** Fake organizational directory structure
- **SSL/TLS:** LDAPS support on port 636

### 10. SMB Honeypot (Port 445)
- **Protocol:** SMB/CIFS (SMB1/2/3)
- **Shares:** Configurable share names and contents
- **Authentication:** NTLM credential capture
- **File Operations:** Directory listing, file access simulation
- **Dialect Negotiation:** Multiple SMB version support

### 11. Syslog Honeypot (Port 514)
- **Protocol:** Syslog (RFC 3164/5424)
- **Transport:** UDP and TCP support
- **Facilities:** All standard syslog facilities
- **Severity Levels:** All severity levels supported
- **Log Processing:** Store and analyze received logs

### 12. MySQL Honeypot (Port 3306)
- **Protocol:** MySQL wire protocol
- **Authentication:** MySQL native authentication
- **Handshake:** Complete MySQL handshake simulation
- **Commands:** Query, prepare, execute, ping
- **Database Simulation:** Fake schemas and tables
- **Error Responses:** Authentic MySQL error messages

### 13. RDP Honeypot (Port 3389)
- **Protocol:** RDP (Remote Desktop Protocol)
- **Versions:** RDP 5.0, 7.0, 8.0 support
- **Authentication:** NLA and standard authentication
- **Certificates:** SSL certificate handling
- **Session Simulation:** Windows desktop environment
- **Clipboard:** Clipboard data capture

### 14. PostgreSQL Honeypot (Port 5432)
- **Protocol:** PostgreSQL wire protocol v3.0
- **Authentication:** MD5, plaintext, trust methods
- **Commands:** Query, prepare, execute, copy
- **Database Simulation:** Fake databases and schemas
- **Functions:** Built-in function simulation
- **Extensions:** Common PostgreSQL extensions

### 15. VNC Honeypot (Port 5900)
- **Protocol:** RFB (Remote Framebuffer)
- **Versions:** RFB 3.3, 3.7, 3.8
- **Authentication:** None, VNC, Ultra
- **Desktop Simulation:** Fake desktop environment
- **Input Capture:** Mouse and keyboard logging
- **Screen Updates:** Fake screen content

### 16. Redis Honeypot (Port 6379)
- **Protocol:** Redis Serialization Protocol (RESP)
- **Commands:** GET, SET, KEYS, INFO, CONFIG, EVAL
- **Data Types:** Strings, lists, sets, hashes, sorted sets
- **Authentication:** AUTH command support
- **Database Selection:** Multiple database simulation
- **Pub/Sub:** Basic publish/subscribe support

### 17. SNMP Honeypot (Port 161)
- **Protocol:** SNMP v1/v2c/v3
- **Operations:** GET, SET, GETNEXT, GETBULK, TRAP
- **Community Strings:** Configurable public/private strings
- **MIB Objects:** Fake system and network MIB data
- **Trap Generation:** Fake SNMP traps
- **Authentication:** SNMPv3 USM authentication

## Advanced Deception Features

### 1. Honeytokens
- **File Tokens:** Word documents, PDFs with tracking pixels
- **Database Tokens:** Fake user records, credit cards, SSNs
- **Credential Tokens:** Fake usernames/passwords for breach detection
- **DNS Tokens:** Unique subdomains that alert when resolved
- **Email Tokens:** Fake email addresses that trigger on delivery
- **API Tokens:** Fake authentication keys that alert when used
- **URL Tokens:** Unique URLs that trigger when accessed

### 2. Dynamic Deception
- **Response Variation:** Randomize banners and responses
- **Timing Jitter:** Realistic response timing patterns
- **Content Rotation:** Periodically change fake content
- **Port Hopping:** Dynamic service port reassignment
- **Decoy Services:** Additional fake services on random ports

### 3. Behavioral Simulation
- **Resource Constraints:** Simulate server load and timeouts
- **Connection Limits:** Realistic concurrent connection handling
- **Authentication Delays:** Believable login processing times
- **File Access Patterns:** Realistic file permissions and access

### 4. Network-Level Deception
- **TCP Stack Simulation:** Proper TCP handshake behavior
- **Service Detection Evasion:** Respond to Nmap realistically
- **Packet Fragmentation:** Proper packet reassembly
- **Keep-Alive Behavior:** Realistic connection persistence

## Alert and Notification System

### 1. Real-Time Notifications
- **WebSocket Connection:** Live updates to admin panel
- **Notification Bell:** Unread alert counter with dropdown
- **Toast Notifications:** Non-intrusive popup alerts
- **Sound Alerts:** Optional audio notifications
- **Desktop Notifications:** Browser notification API support

### 2. Email Notifications
- **SMTP Integration:** Full SMTP client with authentication
- **Security Options:** NONE, STARTTLS, SSL/TLS support
- **Provider Templates:** Gmail, Yahoo, Outlook quick setup
- **HTML Templates:** Rich email formatting
- **Attachment Support:** Include logs and screenshots
- **Delivery Tracking:** Monitor email delivery status

### 3. Webhook Integration
- **Multiple Endpoints:** Support for multiple webhook URLs
- **HTTP Methods:** GET, POST, PUT, PATCH support
- **Custom Headers:** Configurable HTTP headers
- **Authentication:** Bearer tokens, API keys, HMAC signing
- **Payload Formats:** JSON, XML, form-encoded
- **Retry Logic:** Exponential backoff on failures
- **Filtering:** Event-type and severity-based filtering

### 4. Notification Types
- **Emergency Alerts:** Critical system failures
- **Attack Alerts:** High-severity intrusion attempts
- **Service Alerts:** Honeypot service status changes
- **Token Alerts:** Honeytoken trigger notifications
- **Campaign Alerts:** New attack campaign detection
- **System Alerts:** System health and maintenance

### 5. Alert Intelligence
- **Deduplication:** Prevent alert spam
- **Correlation:** Link related events
- **Severity Escalation:** Auto-escalate based on patterns
- **False Positive Reduction:** Smart filtering
- **Contextual Information:** Rich alert context

## Analytics and Reporting

### 1. Attack Analytics
- **Real-Time Dashboard:** Live attack monitoring
- **Geographic Visualization:** World map with attack origins
- **Service Statistics:** Attack distribution by service
- **Timeline Analysis:** Attack patterns over time
- **Top Attackers:** Most active source IPs
- **Attack Vectors:** Common attack methods and tools

### 2. Threat Intelligence
- **IP Reputation:** Built-in IP reputation checking
- **Country Blocking:** Geographic access controls
- **ASN Analysis:** Autonomous System Number tracking
- **User Agent Analysis:** Browser and tool fingerprinting
- **Attack Correlation:** Cross-service attack linking
- **Campaign Tracking:** Multi-stage attack identification

### 3. Reporting Engine
- **Automated Reports:** Scheduled report generation
- **Custom Reports:** User-defined report templates
- **Export Formats:** PDF, HTML, CSV, JSON
- **Email Delivery:** Automatic report distribution
- **Report Scheduling:** Flexible scheduling options
- **Interactive Charts:** Dynamic data visualization

### 4. Forensic Analysis
- **Session Recording:** Complete attack session capture
- **Packet Capture:** Network-level traffic analysis
- **File Analysis:** Uploaded malware examination
- **Command History:** Full command sequence logging
- **Timeline Reconstruction:** Complete attack timeline

## Security Features

### 1. Authentication and Authorization
- **bcrypt Hashing:** Secure password storage
- **Session Management:** Secure session token handling
- **Role-Based Access:** Configurable user roles
- **Multi-Factor Authentication:** TOTP support
- **Account Lockout:** Brute force protection
- **Password Policies:** Configurable complexity requirements

### 2. Rate Limiting and Protection
- **Per-IP Rate Limiting:** Configurable request limits
- **Service-Level Limits:** Individual service protection
- **Automatic IP Blocking:** Threshold-based blocking
- **Whitelist Management:** Trusted IP exemptions
- **DDoS Protection:** Basic DDoS mitigation
- **Connection Throttling:** Resource consumption control

### 3. Data Protection
- **Encryption at Rest:** SQLite database encryption
- **Secure Communication:** TLS for admin panel
- **Credential Encryption:** Encrypted SMTP passwords
- **Audit Logging:** Complete administrative action logging
- **Data Anonymization:** PII protection features
- **Secure Deletion:** Cryptographic data wiping

### 4. Network Security
- **SSL/TLS Support:** Strong cipher suites
- **Certificate Management:** Let's Encrypt integration
- **Network Isolation:** Service process isolation
- **Firewall Integration:** iptables rule generation
- **VPN Support:** Compatible with VPN deployments

## Performance and Scalability

### 1. Resource Management
- **Connection Pooling:** Efficient database connections
- **Memory Management:** Configurable memory limits
- **CPU Optimization:** Efficient goroutine management
- **Disk Usage:** Log rotation and compression
- **Network Optimization:** Connection reuse and pooling

### 2. Monitoring and Metrics
- **System Metrics:** CPU, memory, disk, network monitoring
- **Service Metrics:** Per-service performance tracking
- **Database Metrics:** Query performance and optimization
- **Real-Time Graphs:** Live performance visualization
- **Alerting Thresholds:** Performance-based alerts

### 3. Clustering and High Availability
- **Multi-Node Deployment:** Distributed honeypot deployment
- **Load Balancing:** Traffic distribution across nodes
- **Failover Support:** Automatic failover mechanisms
- **Data Synchronization:** Cross-node data replication
- **Health Monitoring:** Node health and status tracking

### 4. Backup and Recovery
- **Automated Backups:** Scheduled database backups
- **Incremental Backups:** Efficient backup strategies
- **Point-in-Time Recovery:** Database restore capabilities
- **Configuration Export:** Portable configuration backups
- **Disaster Recovery:** Complete system recovery procedures

## Integration Capabilities

### 1. SIEM Integration
- **Syslog Output:** RFC 3164/5424 compliant syslog
- **JSON Exports:** Structured data export
- **API Endpoints:** RESTful API for data access
- **Real-Time Streaming:** Live event streaming
- **Custom Formats:** Configurable output formats

### 2. Threat Intelligence Platforms
- **MISP Integration:** Malware Information Sharing Platform
- **STIX/TAXII Support:** Structured threat information
- **IOC Feeds:** Indicator of Compromise feeds
- **Reputation Services:** External reputation checking
- **Threat Hunting:** Advanced threat detection

### 3. Ticketing and Workflow
- **Webhook Integration:** Generic webhook support
- **REST API:** Full CRUD operations
- **Event Triggers:** Custom automation triggers
- **Workflow Integration:** External workflow systems
- **Incident Response:** Automated response playbooks

### 4. Cloud and Container Platforms
- **Docker Support:** Container deployment
- **Kubernetes:** K8s deployment manifests
- **Cloud Templates:** AWS, Azure, GCP deployment
- **Auto-Scaling:** Dynamic resource scaling
- **Service Discovery:** Automatic service registration

## Build and Deployment

### 1. Build System (Makefile)
```makefile
# Variables
VERSION ?= 1.0.0
BINARY_NAME = caspot
BUILD_DIR = build
CGO_ENABLED = 0
LDFLAGS = -ldflags '-extldflags "-static" -s -w -X main.version=$(VERSION) -X main.buildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'

# Default target
.DEFAULT_GOAL := build

# Build for all platforms
build: clean
	@echo "Building $(BINARY_NAME) v$(VERSION) for all platforms..."
	@mkdir -p $(BUILD_DIR)
	
	# Linux AMD64
	@echo "Building for Linux AMD64..."
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/caspot
	
	# Linux ARM64
	@echo "Building for Linux ARM64..."
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/caspot
	
	# Windows AMD64
	@echo "Building for Windows AMD64..."
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/caspot
	
	# macOS AMD64
	@echo "Building for macOS AMD64..."
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/caspot
	
	# macOS ARM64 (Apple Silicon)
	@echo "Building for macOS ARM64..."
	@CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/caspot
	
	# Host binary
	@echo "Building host binary..."
	@CGO_ENABLED=$(CGO_ENABLED) go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/caspot
	
	@echo "Build complete. Binaries available in $(BUILD_DIR)/"

# Release to GitHub
release: build
	@echo "Creating checksums..."
	@cd $(BUILD_DIR) && sha256sum $(BINARY_NAME)-* > checksums.txt
	@echo "Release artifacts ready in $(BUILD_DIR)/"
	@echo "Upload to GitHub releases manually or use 'gh release create v$(VERSION) $(BUILD_DIR)/*'"

# Docker build and push
docker:
	@echo "Building Docker image..."
	@docker build -t ghcr.io/casapps/$(BINARY_NAME):$(VERSION) .
	@docker build -t ghcr.io/casapps/$(BINARY_NAME):latest .
	@echo "Pushing to registry..."
	@docker push ghcr.io/casapps/$(BINARY_NAME):$(VERSION)
	@docker push ghcr.io/casapps/$(BINARY_NAME):latest

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Test coverage report: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html

# Development server
dev:
	@echo "Starting development server..."
	@go run ./cmd/caspot --dev

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod verify

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@goimports -w .

# Lint code
lint:
	@echo "Running linters..."
	@golangci-lint run

# Generate documentation
docs:
	@echo "Generating documentation..."
	@godoc -http=:6060
	@echo "Documentation server running at http://localhost:6060"

# Install locally
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "Installation complete. Run '$(BINARY_NAME)' to start."

# Uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstallation complete."

# Help
help:
	@echo "Available targets:"
	@echo "  build    - Build binaries for all platforms"
	@echo "  release  - Prepare release artifacts"
	@echo "  docker   - Build and push Docker image"
	@echo "  test     - Run tests with coverage"
	@echo "  clean    - Clean build artifacts"
	@echo "  dev      - Start development server"
	@echo "  deps     - Install dependencies"
	@echo "  fmt      - Format code"
	@echo "  lint     - Run linters"
	@echo "  docs     - Generate documentation"
	@echo "  install  - Install locally"
	@echo "  uninstall- Uninstall"
	@echo "  help     - Show this help"

.PHONY: build release docker test clean dev deps fmt lint docs install uninstall help
```

### 2. Jenkins Pipeline (Jenkinsfile)
```groovy
pipeline {
    agent none
    
    environment {
        BINARY_NAME = 'caspot'
        REGISTRY = 'ghcr.io/casapps'
        BRANCH_NAME = "${env.BRANCH_NAME}"
        BUILD_NUMBER = "${env.BUILD_NUMBER}"
    }
    
    stages {
        stage('Parallel Build') {
            parallel {
                stage('Build AMD64') {
                    agent { label 'amd64' }
                    steps {
                        script {
                            checkout scm
                            sh 'make clean'
                            sh 'make build'
                            archiveArtifacts artifacts: 'build/*', fingerprint: true
                            stash includes: 'build/*amd64*', name: 'amd64-binaries'
                        }
                    }
                }
                
                stage('Build ARM64') {
                    agent { label 'arm64' }
                    steps {
                        script {
                            checkout scm
                            sh 'make clean'
                            sh 'make build'
                            archiveArtifacts artifacts: 'build/*', fingerprint: true
                            stash includes: 'build/*arm64*', name: 'arm64-binaries'
                        }
                    }
                }
            }
        }
        
        stage('Test') {
            agent { label 'amd64' }
            steps {
                checkout scm
                sh 'make test'
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'coverage.html',
                    reportName: 'Coverage Report'
                ])
            }
        }
        
        stage('Security Scan') {
            agent { label 'amd64' }
            steps {
                checkout scm
                sh 'go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest'
                sh 'gosec -fmt json -out security-report.json ./...'
                archiveArtifacts artifacts: 'security-report.json', fingerprint: true
            }
        }
        
        stage('Release') {
            when {
                tag 'v*'
            }
            agent { label 'amd64' }
            steps {
                script {
                    unstash 'amd64-binaries'
                    unstash 'arm64-binaries'
                    sh 'cd build && sha256sum caspot-* > checksums.txt'
                    
                    // Create GitHub release
                    withCredentials([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
                        sh '''
                            gh release create ${TAG_NAME} \
                                build/caspot-* \
                                build/checksums.txt \
                                --title "Release ${TAG_NAME}" \
                                --generate-notes
                        '''
                    }
                }
            }
        }
        
        stage('Docker Build') {
            agent { label 'amd64' }
            steps {
                script {
                    def version = env.TAG_NAME ?: 'latest'
                    sh "make docker VERSION=${version}"
                }
            }
        }
        
        stage('Deploy to Staging') {
            when {
                branch 'main'
            }
            agent { label 'amd64' }
            steps {
                script {
                    // Deploy to staging environment
                    sh '''
                        kubectl apply -f kubernetes/staging/ -n caspot-staging
                        kubectl rollout status deployment/caspot -n caspot-staging
                    '''
                }
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        success {
            script {
                if (env.TAG_NAME) {
                    slackSend(
                        channel: '#releases',
                        color: 'good',
                        message: "✅ ${BINARY_NAME} ${env.TAG_NAME} released successfully!"
                    )
                }
            }
        }
        failure {
            slackSend(
                channel: '#alerts',
                color: 'danger',
                message: "❌ ${BINARY_NAME} build failed: ${env.BUILD_URL}"
            )
        }
    }
}
```

### 3. Docker Configuration
```dockerfile
# Multi-stage build
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags '-extldflags "-static" -s -w' \
    -o caspot ./cmd/caspot

# Final stage
FROM scratch

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy binary
COPY --from=builder /app/caspot /caspot

# Create non-root user
USER 1000:1000

# Expose ports
EXPOSE 22 23 25 53 69 80 389 443 445 514 3306 3389 5432 5900 6379 8080 161

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ["/caspot", "health"]

# Run application
ENTRYPOINT ["/caspot"]
```

### 4. Kubernetes Deployment
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: caspot
  namespace: honeypot
  labels:
    app: caspot
    version: v1.0.0
spec:
  replicas: 3
  selector:
    matchLabels:
      app: caspot
  template:
    metadata:
      labels:
        app: caspot
        version: v1.0.0
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: caspot
        image: ghcr.io/casapps/caspot:v1.0.0
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
          name: admin
        - containerPort: 22
          name: ssh
        - containerPort: 80
          name: http
        - containerPort: 443
          name: https
        env:
        - name: CASPOT_NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        volumeMounts:
        - name: data
          mountPath: /var/lib/caspot
        - name: logs
          mountPath: /var/log/caspot
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: caspot-data
      - name: logs
        persistentVolumeClaim:
          claimName: caspot-logs
---
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: caspot
  namespace: honeypot
spec:
  selector:
    app: caspot
  ports:
  - name: admin
    port: 8080
    targetPort: 8080
  - name: ssh
    port: 22
    targetPort: 22
  - name: http
    port: 80
    targetPort: 80
  - name: https
    port: 443
    targetPort: 443
  type: LoadBalancer
```

## API Specification

### 1. Authentication Endpoints
```
POST /api/v1/auth/login
POST /api/v1/auth/logout
POST /api/v1/auth/refresh
GET  /api/v1/auth/profile
PUT  /api/v1/auth/profile
POST /api/v1/auth/change-password
```

### 2. Events and Analytics
```
GET    /api/v1/events
GET    /api/v1/events/{id}
DELETE /api/v1/events/{id}
POST   /api/v1/events/export
GET    /api/v1/analytics/dashboard
GET    /api/v1/analytics/geolocation
GET    /api/v1/analytics/top-attackers
GET    /api/v1/analytics/attack-timeline
```

### 3. Honeypot Services
```
GET    /api/v1/services
GET    /api/v1/services/{name}
PUT    /api/v1/services/{name}
POST   /api/v1/services/{name}/start
POST   /api/v1/services/{name}/stop
POST   /api/v1/services/{name}/restart
GET    /api/v1/services/{name}/status
GET    /api/v1/services/{name}/logs
```

### 4. Configuration Management
```
GET    /api/v1/config
PUT    /api/v1/config
GET    /api/v1/config/{category}
PUT    /api/v1/config/{category}
POST   /api/v1/config/export
POST   /api/v1/config/import
POST   /api/v1/config/reset
```

### 5. Honeytokens
```
GET    /api/v1/tokens
POST   /api/v1/tokens
GET    /api/v1/tokens/{id}
PUT    /api/v1/tokens/{id}
DELETE /api/v1/tokens/{id}
POST   /api/v1/tokens/{id}/regenerate
GET    /api/v1/tokens/{id}/triggers
```

### 6. Notifications and Alerts
```
GET    /api/v1/notifications
POST   /api/v1/notifications
GET    /api/v1/notifications/{id}
PUT    /api/v1/notifications/{id}
DELETE /api/v1/notifications/{id}
POST   /api/v1/notifications/{id}/acknowledge
GET    /api/v1/webhooks
POST   /api/v1/webhooks
PUT    /api/v1/webhooks/{id}
DELETE /api/v1/webhooks/{id}
POST   /api/v1/webhooks/{id}/test
```

### 7. Clustering and Nodes
```
GET    /api/v1/nodes
POST   /api/v1/nodes
GET    /api/v1/nodes/{id}
PUT    /api/v1/nodes/{id}
DELETE /api/v1/nodes/{id}
GET    /api/v1/nodes/{id}/status
POST   /api/v1/nodes/{id}/sync
```

### 8. Scheduled Jobs
```
GET    /api/v1/jobs
POST   /api/v1/jobs
GET    /api/v1/jobs/{id}
PUT    /api/v1/jobs/{id}
DELETE /api/v1/jobs/{id}
POST   /api/v1/jobs/{id}/run
GET    /api/v1/jobs/{id}/executions
```

### 9. System Health and Metrics
```
GET    /api/v1/health
GET    /api/v1/ready
GET    /api/v1/metrics
GET    /api/v1/system/info
GET    /api/v1/system/status
POST   /api/v1/system/backup
GET    /api/v1/system/logs
```

## Installation and Usage

### 1. Quick Start
```bash
# Download latest release
wget https://github.com/casapps/caspot/releases/latest/download/caspot-linux-amd64

# Make executable
chmod +x caspot-linux-amd64

# Run setup wizard
./caspot-linux-amd64

# Access admin panel
# https://localhost:8080 (or configured port)
```

### 2. System Service Installation
```bash
# Install binary
sudo cp caspot-linux-amd64 /usr/local/bin/caspot
sudo chmod +x /usr/local/bin/caspot

# Create user and directories
sudo useradd -r -s /bin/false caspot
sudo mkdir -p /var/lib/caspot /var/log/caspot
sudo chown caspot:caspot /var/lib/caspot /var/log/caspot

# Create systemd service
sudo tee /etc/systemd/system/caspot.service << EOF
[Unit]
Description=caspot Honeypot Server
After=network.target

[Service]
Type=simple
User=caspot
Group=caspot
ExecStart=/usr/local/bin/caspot
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=caspot

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/caspot /var/log/caspot
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

# Capabilities for low ports
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable caspot
sudo systemctl start caspot
sudo systemctl status caspot
```

### 3. Docker Deployment
```bash
# Run with Docker
docker run -d \
  --name caspot \
  -p 8080:8080 \
  -p 22:22 \
  -p 80:80 \
  -p 443:443 \
  -v caspot-data:/var/lib/caspot \
  -v caspot-logs:/var/log/caspot \
  ghcr.io/casapps/caspot:latest

# Using Docker Compose
cat > docker-compose.yml << EOF
version: '3.8'
services:
  caspot:
    image: ghcr.io/casapps/caspot:latest
    container_name: caspot
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "22:22"
      - "23:23"
      - "25:25"
      - "53:53/udp"
      - "69:69/udp"
      - "80:80"
      - "389:389"
      - "443:443"
      - "445:445"
      - "514:514/udp"
      - "3306:3306"
      - "3389:3389"
      - "5432:5432"
      - "5900:5900"
      - "6379:6379"
      - "161:161/udp"
    volumes:
      - caspot-data:/var/lib/caspot
      - caspot-logs:/var/log/caspot
    environment:
      - CASPOT_NODE_NAME=docker-node
    healthcheck:
      test: ["/caspot", "health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  caspot-data:
  caspot-logs:
EOF

docker-compose up -d
```

### 4. Cloud Deployment Templates

**AWS CloudFormation:**
```yaml
# aws-template.yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'caspot Honeypot Deployment'

Parameters:
  InstanceType:
    Type: String
    Default: t3.medium
    AllowedValues: [t3.small, t3.medium, t3.large]
    
  KeyPairName:
    Type: AWS::EC2::KeyPair::KeyName
    Description: EC2 Key Pair for SSH access

Resources:
  CaspotSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for caspot honeypot
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 8080
          ToPort: 8080
          CidrIp: 0.0.0.0/0
          
  CaspotInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0c02fb55956c7d316  # Amazon Linux 2
      InstanceType: !Ref InstanceType
      KeyName: !Ref KeyPairName
      SecurityGroupIds:
        - !Ref CaspotSecurityGroup
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          yum update -y
          wget https://github.com/casapps/caspot/releases/latest/download/caspot-linux-amd64 -O /usr/local/bin/caspot
          chmod +x /usr/local/bin/caspot
          useradd -r -s /bin/false caspot
          mkdir -p /var/lib/caspot /var/log/caspot
          chown caspot:caspot /var/lib/caspot /var/log/caspot
          # Start caspot
          /usr/local/bin/caspot &

Outputs:
  InstancePublicIP:
    Description: Public IP address of the caspot instance
    Value: !GetAtt CaspotInstance.PublicIp
    
  AdminPanelURL:
    Description: URL to access the admin panel
    Value: !Sub 'https://${CaspotInstance.PublicIp}:8080'
```

## Documentation and Support

### 1. User Documentation
- **Quick Start Guide:** Getting started in 5 minutes
- **Installation Guide:** Detailed installation instructions
- **Configuration Reference:** Complete configuration options
- **API Documentation:** RESTful API reference
- **Troubleshooting Guide:** Common issues and solutions

### 2. Administrator Documentation
- **Security Hardening:** Best practices for secure deployment
- **Performance Tuning:** Optimization recommendations
- **Monitoring Setup:** Integration with monitoring systems
- **Backup and Recovery:** Data protection strategies
- **Upgrade Procedures:** Version upgrade instructions

### 3. Developer Documentation
- **Architecture Overview:** System design and components
- **Contributing Guide:** Development workflow and standards
- **Testing Guidelines:** Unit and integration testing
- **Release Process:** Versioning and release procedures
- **Code Style:** Coding standards and conventions

### 4. Community and Support
- **GitHub Issues:** Bug reports and feature requests
- **Documentation Wiki:** Community-maintained documentation
- **Security Advisories:** Security vulnerability reports
- **Changelog:** Version history and changes
- **Roadmap:** Future development plans

---

**This completes the comprehensive caspot v1.0.0 specification. The platform provides enterprise-grade honeypot capabilities with advanced deception techniques, comprehensive monitoring, and seamless integration options, all delivered as a single static binary for maximum portability and ease of deployment.**

