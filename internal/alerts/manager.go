package alerts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"sync"
	"time"

	"github.com/casapps/caspot/internal/database"
)

type Manager struct {
	db         *database.DB
	webhooks   []WebhookConfig
	smtpConfig *SMTPConfig
	mu         sync.RWMutex
	queue      chan Alert
	workers    int
	running    bool
}

type Alert struct {
	ID            int64
	Type          string
	Category      string
	Title         string
	Message       string
	Severity      string
	SourceComponent string
	EventID       int64
	TokenID       int64
	CampaignID    int64
	CreatedAt     time.Time
	Metadata      map[string]interface{}
}

type WebhookConfig struct {
	ID             int64
	Name           string
	URL            string
	Method         string
	Headers        map[string]string
	Secret         string
	EventTypes     []string
	SeverityFilter string
	ServiceFilter  []string
	Enabled        bool
	SSLVerify      bool
	Timeout        int
	RetryAttempts  int
	RetryDelay     int
}

type SMTPConfig struct {
	ID           int64
	Name         string
	Host         string
	Port         int
	SecurityType string
	Username     string
	Password     string
	FromName     string
	FromAddress  string
	AdminEmail   string
	Enabled      bool
	SSLVerify    bool
	Timeout      int
}

func NewManager(db *database.DB) *Manager {
	return &Manager{
		db:      db,
		queue:   make(chan Alert, 1000),
		workers: 5,
	}
}

func (m *Manager) Initialize() error {
	if err := m.loadConfigurations(); err != nil {
		return err
	}

	m.mu.Lock()
	m.running = true
	m.mu.Unlock()

	// Start worker goroutines
	for i := 0; i < m.workers; i++ {
		go m.worker()
	}

	return nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	m.running = false
	m.mu.Unlock()

	close(m.queue)
}

func (m *Manager) loadConfigurations() error {
	conn := m.db.Conn()

	// Load SMTP configuration
	var smtp SMTPConfig
	err := conn.QueryRow(`
		SELECT id, name, smtp_host, smtp_port, security_type,
		       username, from_name, from_address, admin_email,
		       enabled, ssl_verify, timeout
		FROM smtp_configs
		WHERE enabled = TRUE
		LIMIT 1
	`).Scan(
		&smtp.ID, &smtp.Name, &smtp.Host, &smtp.Port, &smtp.SecurityType,
		&smtp.Username, &smtp.FromName, &smtp.FromAddress, &smtp.AdminEmail,
		&smtp.Enabled, &smtp.SSLVerify, &smtp.Timeout,
	)

	if err == nil {
		m.smtpConfig = &smtp
	}

	// Load webhook configurations
	rows, err := conn.Query(`
		SELECT id, name, url, method, headers, secret,
		       event_types, severity_filter, service_filter,
		       enabled, ssl_verify, timeout, retry_attempts, retry_delay
		FROM webhooks
		WHERE enabled = TRUE
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	m.webhooks = []WebhookConfig{}
	for rows.Next() {
		var w WebhookConfig
		var headers, eventTypes, serviceFilter sql.NullString

		err := rows.Scan(
			&w.ID, &w.Name, &w.URL, &w.Method, &headers, &w.Secret,
			&eventTypes, &w.SeverityFilter, &serviceFilter,
			&w.Enabled, &w.SSLVerify, &w.Timeout, &w.RetryAttempts, &w.RetryDelay,
		)
		if err != nil {
			continue
		}

		if headers.Valid {
			json.Unmarshal([]byte(headers.String), &w.Headers)
		}
		if eventTypes.Valid {
			json.Unmarshal([]byte(eventTypes.String), &w.EventTypes)
		}
		if serviceFilter.Valid {
			json.Unmarshal([]byte(serviceFilter.String), &w.ServiceFilter)
		}

		m.webhooks = append(m.webhooks, w)
	}

	return rows.Err()
}

func (m *Manager) SendAlert(alertType, title, message, severity string, metadata map[string]interface{}) error {
	alert := Alert{
		Type:         alertType,
		Category:     m.getCategoryForType(alertType),
		Title:        title,
		Message:      message,
		Severity:     severity,
		CreatedAt:    time.Now(),
		Metadata:     metadata,
	}

	// Store in database
	if err := m.storeNotification(alert); err != nil {
		return err
	}

	// Queue for delivery
	select {
	case m.queue <- alert:
		return nil
	default:
		return fmt.Errorf("alert queue full")
	}
}

func (m *Manager) getCategoryForType(alertType string) string {
	switch alertType {
	case "emergency", "critical":
		return "real_time"
	case "attack", "honeytoken":
		return "email"
	default:
		return "webhook"
	}
}

func (m *Manager) storeNotification(alert Alert) error {
	conn := m.db.Conn()

	metadataJSON, _ := json.Marshal(alert.Metadata)

	_, err := conn.Exec(`
		INSERT INTO notifications (type, category, title, message, severity,
		                          source_component, event_id, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, alert.Type, alert.Category, alert.Title, alert.Message, alert.Severity,
		alert.SourceComponent, alert.EventID, string(metadataJSON))

	return err
}

func (m *Manager) worker() {
	for alert := range m.queue {
		m.processAlert(alert)
	}
}

func (m *Manager) processAlert(alert Alert) {
	// Send email if configured and severity matches
	if m.smtpConfig != nil && m.smtpConfig.Enabled {
		if m.shouldSendEmail(alert) {
			if err := m.sendEmail(alert); err != nil {
				fmt.Printf("Failed to send email alert: %v\n", err)
			}
		}
	}

	// Send to webhooks
	for _, webhook := range m.webhooks {
		if m.shouldSendWebhook(alert, webhook) {
			if err := m.sendWebhook(alert, webhook); err != nil {
				fmt.Printf("Failed to send webhook to %s: %v\n", webhook.Name, err)
			}
		}
	}
}

func (m *Manager) shouldSendEmail(alert Alert) bool {
	// Send emails for high and critical severity
	return alert.Severity == "high" || alert.Severity == "critical"
}

func (m *Manager) shouldSendWebhook(alert Alert, webhook WebhookConfig) bool {
	// Check severity filter
	severityLevel := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	if severityLevel[alert.Severity] < severityLevel[webhook.SeverityFilter] {
		return false
	}

	// Check event type filter
	if len(webhook.EventTypes) > 0 {
		found := false
		for _, t := range webhook.EventTypes {
			if t == alert.Type {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (m *Manager) sendEmail(alert Alert) error {
	if m.smtpConfig == nil {
		return fmt.Errorf("SMTP not configured")
	}

	subject := fmt.Sprintf("[caspot Alert] %s - %s", alert.Severity, alert.Title)

	body := fmt.Sprintf(`
Alert Type: %s
Severity: %s
Time: %s

%s

Details:
%s

--
caspot Honeypot Platform
`, alert.Type, alert.Severity, alert.CreatedAt.Format(time.RFC3339), alert.Message,
		m.formatMetadata(alert.Metadata))

	msg := fmt.Sprintf("From: %s <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", m.smtpConfig.FromName, m.smtpConfig.FromAddress,
		m.smtpConfig.AdminEmail, subject, body)

	auth := smtp.PlainAuth("", m.smtpConfig.Username, m.smtpConfig.Password, m.smtpConfig.Host)

	addr := fmt.Sprintf("%s:%d", m.smtpConfig.Host, m.smtpConfig.Port)
	return smtp.SendMail(addr, auth, m.smtpConfig.FromAddress, []string{m.smtpConfig.AdminEmail}, []byte(msg))
}

func (m *Manager) sendWebhook(alert Alert, webhook WebhookConfig) error {
	payload := map[string]interface{}{
		"type":      alert.Type,
		"severity":  alert.Severity,
		"title":     alert.Title,
		"message":   alert.Message,
		"timestamp": alert.CreatedAt.Unix(),
		"metadata":  alert.Metadata,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(webhook.Method, webhook.URL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "caspot/1.0.0")

	// Add custom headers
	for k, v := range webhook.Headers {
		req.Header.Set(k, v)
	}

	// Add HMAC signature if secret is configured
	if webhook.Secret != "" {
		h := hmac.New(sha256.New, []byte(webhook.Secret))
		h.Write(jsonPayload)
		signature := hex.EncodeToString(h.Sum(nil))
		req.Header.Set("X-Signature", signature)
	}

	client := &http.Client{
		Timeout: time.Duration(webhook.Timeout) * time.Second,
	}

	if !webhook.SSLVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// Retry logic
	var lastErr error
	for attempt := 0; attempt <= webhook.RetryAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(webhook.RetryDelay) * time.Second)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Success - update webhook stats
			m.updateWebhookStats(webhook.ID, true)
			return nil
		}

		lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	// All attempts failed
	m.updateWebhookStats(webhook.ID, false)
	return lastErr
}

func (m *Manager) updateWebhookStats(webhookID int64, success bool) {
	conn := m.db.Conn()

	if success {
		conn.Exec(`
			UPDATE webhooks
			SET last_success = CURRENT_TIMESTAMP,
			    success_count = success_count + 1
			WHERE id = ?
		`, webhookID)
	} else {
		conn.Exec(`
			UPDATE webhooks
			SET last_failure = CURRENT_TIMESTAMP,
			    failure_count = failure_count + 1
			WHERE id = ?
		`, webhookID)
	}
}

func (m *Manager) formatMetadata(metadata map[string]interface{}) string {
	if len(metadata) == 0 {
		return "No additional details"
	}

	var buffer bytes.Buffer
	for k, v := range metadata {
		buffer.WriteString(fmt.Sprintf("%s: %v\n", k, v))
	}
	return buffer.String()
}

// Alert convenience functions
func (m *Manager) AlertCritical(title, message string, metadata map[string]interface{}) {
	m.SendAlert("emergency", title, message, "critical", metadata)
}

func (m *Manager) AlertAttack(sourceIP, service, details string) {
	metadata := map[string]interface{}{
		"source_ip": sourceIP,
		"service":   service,
		"details":   details,
	}
	m.SendAlert("attack", "Attack Detected",
		fmt.Sprintf("Attack from %s on %s service: %s", sourceIP, service, details),
		"high", metadata)
}

func (m *Manager) AlertHoneytoken(tokenName, sourceIP, context string) {
	metadata := map[string]interface{}{
		"token_name": tokenName,
		"source_ip":  sourceIP,
		"context":    context,
	}
	m.SendAlert("honeytoken", "Honeytoken Triggered",
		fmt.Sprintf("Honeytoken '%s' triggered by %s: %s", tokenName, sourceIP, context),
		"critical", metadata)
}

func (m *Manager) AlertService(service, status, message string) {
	severity := "low"
	if status == "error" || status == "stopped" {
		severity = "medium"
	}

	metadata := map[string]interface{}{
		"service": service,
		"status":  status,
	}
	m.SendAlert("service", fmt.Sprintf("Service %s: %s", service, status),
		message, severity, metadata)
}