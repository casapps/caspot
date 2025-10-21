package honeytokens

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/casapps/caspot/internal/database"
)

type Manager struct {
	db       *database.DB
	tokens   map[string]*Token
	mu       sync.RWMutex
	watchers map[string]chan TokenTrigger
}

type Token struct {
	ID               int64
	Type             string
	Name             string
	Value            string
	DeploymentLocation string
	Description      string
	CreatedAt        time.Time
	DeployedAt       *time.Time
	LastTriggered    *time.Time
	TriggerCount     int
	Active           bool
	AutoRegenerate   bool
	RegenerateInterval int
	AlertEnabled     bool
	Metadata         map[string]interface{}
}

type TokenTrigger struct {
	TokenID        int64
	TriggeredAt    time.Time
	SourceIP       string
	SourceDetails  map[string]interface{}
	TriggerContext string
	UserAgent      string
	RequestData    string
	ResponseSent   string
	Severity       string
}

func NewManager(db *database.DB) *Manager {
	return &Manager{
		db:       db,
		tokens:   make(map[string]*Token),
		watchers: make(map[string]chan TokenTrigger),
	}
}

func (m *Manager) Initialize() error {
	if err := m.createTables(); err != nil {
		return err
	}

	return m.loadTokens()
}

func (m *Manager) createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS honeytokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token_type TEXT NOT NULL,
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
		regenerate_interval INTEGER DEFAULT 2592000,
		alert_enabled BOOLEAN DEFAULT TRUE,
		metadata TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_token_type ON honeytokens(token_type);
	CREATE INDEX IF NOT EXISTS idx_active ON honeytokens(active);
	CREATE INDEX IF NOT EXISTS idx_last_triggered ON honeytokens(last_triggered);

	CREATE TABLE IF NOT EXISTS honeytoken_triggers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token_id INTEGER NOT NULL,
		triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		source_ip TEXT NOT NULL,
		source_details TEXT,
		trigger_context TEXT,
		user_agent TEXT,
		request_data TEXT,
		response_sent TEXT,
		severity TEXT DEFAULT 'high',
		investigated BOOLEAN DEFAULT FALSE,
		false_positive BOOLEAN DEFAULT FALSE,
		analyst_notes TEXT,
		FOREIGN KEY (token_id) REFERENCES honeytokens(id)
	);

	CREATE INDEX IF NOT EXISTS idx_triggered_at ON honeytoken_triggers(triggered_at);
	CREATE INDEX IF NOT EXISTS idx_token_id ON honeytoken_triggers(token_id);
	CREATE INDEX IF NOT EXISTS idx_source_ip ON honeytoken_triggers(source_ip);
	CREATE INDEX IF NOT EXISTS idx_investigated ON honeytoken_triggers(investigated);
	`

	conn := m.db.Conn()
	_, err := conn.Exec(schema)
	return err
}

func (m *Manager) loadTokens() error {
	conn := m.db.Conn()
	rows, err := conn.Query(`
		SELECT id, token_type, token_name, token_value, deployment_location,
		       description, created_at, deployed_at, last_triggered,
		       trigger_count, active, auto_regenerate, regenerate_interval,
		       alert_enabled, metadata
		FROM honeytokens WHERE active = TRUE
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	m.mu.Lock()
	defer m.mu.Unlock()

	for rows.Next() {
		token := &Token{}
		var deployedAt, lastTriggered sql.NullTime
		var metadata sql.NullString

		err := rows.Scan(
			&token.ID, &token.Type, &token.Name, &token.Value,
			&token.DeploymentLocation, &token.Description,
			&token.CreatedAt, &deployedAt, &lastTriggered,
			&token.TriggerCount, &token.Active, &token.AutoRegenerate,
			&token.RegenerateInterval, &token.AlertEnabled, &metadata,
		)
		if err != nil {
			continue
		}

		if deployedAt.Valid {
			token.DeployedAt = &deployedAt.Time
		}
		if lastTriggered.Valid {
			token.LastTriggered = &lastTriggered.Time
		}
		if metadata.Valid {
			json.Unmarshal([]byte(metadata.String), &token.Metadata)
		}

		m.tokens[token.Value] = token
	}

	return rows.Err()
}

func (m *Manager) CreateToken(tokenType, name, location, description string) (*Token, error) {
	value := m.generateTokenValue(tokenType)

	metadata := map[string]interface{}{
		"type":     tokenType,
		"created":  time.Now().Unix(),
		"location": location,
	}

	metadataJSON, _ := json.Marshal(metadata)

	conn := m.db.Conn()
	result, err := conn.Exec(`
		INSERT INTO honeytokens (token_type, token_name, token_value,
		                        deployment_location, description, metadata)
		VALUES (?, ?, ?, ?, ?, ?)
	`, tokenType, name, value, location, description, string(metadataJSON))

	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()

	token := &Token{
		ID:                 id,
		Type:               tokenType,
		Name:               name,
		Value:              value,
		DeploymentLocation: location,
		Description:        description,
		CreatedAt:          time.Now(),
		Active:             true,
		AlertEnabled:       true,
		Metadata:           metadata,
	}

	m.mu.Lock()
	m.tokens[value] = token
	m.mu.Unlock()

	return token, nil
}

func (m *Manager) generateTokenValue(tokenType string) string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	randHex := hex.EncodeToString(randBytes)

	switch tokenType {
	case "file":
		return fmt.Sprintf("SECRET_%s.txt", randHex[:8])
	case "dns":
		return fmt.Sprintf("canary-%s.honeypot.internal", randHex[:12])
	case "credential":
		return fmt.Sprintf("admin_%s", randHex[:8])
	case "database":
		return fmt.Sprintf("user_%s", randHex[:12])
	case "email":
		return fmt.Sprintf("trap_%s@honeypot.local", randHex[:8])
	case "api":
		return fmt.Sprintf("sk_live_%s", randHex)
	case "url":
		return fmt.Sprintf("/trap/%s", randHex[:16])
	default:
		return randHex
	}
}

func (m *Manager) CheckToken(value string) (*Token, bool) {
	m.mu.RLock()
	token, exists := m.tokens[value]
	m.mu.RUnlock()

	return token, exists
}

func (m *Manager) TriggerToken(tokenID int64, sourceIP, context, userAgent, requestData string) error {
	conn := m.db.Conn()

	// Update token trigger count and last triggered
	_, err := conn.Exec(`
		UPDATE honeytokens
		SET trigger_count = trigger_count + 1,
		    last_triggered = CURRENT_TIMESTAMP
		WHERE id = ?
	`, tokenID)

	if err != nil {
		return err
	}

	// Get source details (would include geolocation in full implementation)
	sourceDetails := map[string]interface{}{
		"ip":         sourceIP,
		"user_agent": userAgent,
		"timestamp":  time.Now().Unix(),
	}

	sourceDetailsJSON, _ := json.Marshal(sourceDetails)

	// Insert trigger record
	_, err = conn.Exec(`
		INSERT INTO honeytoken_triggers (token_id, source_ip, source_details,
		                                trigger_context, user_agent, request_data,
		                                severity)
		VALUES (?, ?, ?, ?, ?, ?, 'critical')
	`, tokenID, sourceIP, string(sourceDetailsJSON), context, userAgent, requestData)

	if err != nil {
		return err
	}

	// Notify watchers
	m.mu.RLock()
	defer m.mu.RUnlock()

	trigger := TokenTrigger{
		TokenID:        tokenID,
		TriggeredAt:    time.Now(),
		SourceIP:       sourceIP,
		SourceDetails:  sourceDetails,
		TriggerContext: context,
		UserAgent:      userAgent,
		RequestData:    requestData,
		Severity:       "critical",
	}

	for _, ch := range m.watchers {
		select {
		case ch <- trigger:
		default:
			// Don't block if channel is full
		}
	}

	// Log to main events table as well
	event := &database.Event{
		EventType:   "honeytoken_triggered",
		SourceIP:    sourceIP,
		DestPort:    0,
		ServiceName: "honeytoken",
		Protocol:    "token",
		Command:     context,
		Payload:     requestData,
		Severity:    "critical",
	}
	m.db.LogEvent(event)

	return nil
}

func (m *Manager) RegenerateToken(tokenID int64) (*Token, error) {
	conn := m.db.Conn()

	// Get current token
	var token Token
	err := conn.QueryRow(`
		SELECT token_type, token_name, deployment_location, description
		FROM honeytokens WHERE id = ?
	`, tokenID).Scan(&token.Type, &token.Name, &token.DeploymentLocation, &token.Description)

	if err != nil {
		return nil, err
	}

	// Generate new value
	newValue := m.generateTokenValue(token.Type)

	// Update token
	_, err = conn.Exec(`
		UPDATE honeytokens
		SET token_value = ?, created_at = CURRENT_TIMESTAMP, trigger_count = 0
		WHERE id = ?
	`, newValue, tokenID)

	if err != nil {
		return nil, err
	}

	// Update in-memory cache
	m.mu.Lock()
	// Remove old value
	for k, v := range m.tokens {
		if v.ID == tokenID {
			delete(m.tokens, k)
			break
		}
	}
	// Add new value
	token.ID = tokenID
	token.Value = newValue
	token.CreatedAt = time.Now()
	token.TriggerCount = 0
	m.tokens[newValue] = &token
	m.mu.Unlock()

	return &token, nil
}

func (m *Manager) ListTokens(active bool) ([]*Token, error) {
	conn := m.db.Conn()

	query := `
		SELECT id, token_type, token_name, token_value, deployment_location,
		       description, created_at, deployed_at, last_triggered,
		       trigger_count, active, auto_regenerate, regenerate_interval,
		       alert_enabled, metadata
		FROM honeytokens
	`
	if active {
		query += " WHERE active = TRUE"
	}
	query += " ORDER BY created_at DESC"

	rows, err := conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*Token
	for rows.Next() {
		token := &Token{}
		var deployedAt, lastTriggered sql.NullTime
		var metadata sql.NullString

		err := rows.Scan(
			&token.ID, &token.Type, &token.Name, &token.Value,
			&token.DeploymentLocation, &token.Description,
			&token.CreatedAt, &deployedAt, &lastTriggered,
			&token.TriggerCount, &token.Active, &token.AutoRegenerate,
			&token.RegenerateInterval, &token.AlertEnabled, &metadata,
		)
		if err != nil {
			continue
		}

		if deployedAt.Valid {
			token.DeployedAt = &deployedAt.Time
		}
		if lastTriggered.Valid {
			token.LastTriggered = &lastTriggered.Time
		}
		if metadata.Valid {
			json.Unmarshal([]byte(metadata.String), &token.Metadata)
		}

		tokens = append(tokens, token)
	}

	return tokens, rows.Err()
}

func (m *Manager) GetTriggers(tokenID int64, limit int) ([]TokenTrigger, error) {
	conn := m.db.Conn()

	rows, err := conn.Query(`
		SELECT triggered_at, source_ip, source_details, trigger_context,
		       user_agent, request_data, response_sent, severity
		FROM honeytoken_triggers
		WHERE token_id = ?
		ORDER BY triggered_at DESC
		LIMIT ?
	`, tokenID, limit)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var triggers []TokenTrigger
	for rows.Next() {
		var trigger TokenTrigger
		var sourceDetails, responseS sql.NullString

		err := rows.Scan(
			&trigger.TriggeredAt, &trigger.SourceIP, &sourceDetails,
			&trigger.TriggerContext, &trigger.UserAgent,
			&trigger.RequestData, &responseS, &trigger.Severity,
		)
		if err != nil {
			continue
		}

		trigger.TokenID = tokenID
		if sourceDetails.Valid {
			json.Unmarshal([]byte(sourceDetails.String), &trigger.SourceDetails)
		}
		if responseS.Valid {
			trigger.ResponseSent = responseS.String
		}

		triggers = append(triggers, trigger)
	}

	return triggers, rows.Err()
}

func (m *Manager) WatchTriggers() <-chan TokenTrigger {
	ch := make(chan TokenTrigger, 100)

	m.mu.Lock()
	id := fmt.Sprintf("watcher_%d", len(m.watchers))
	m.watchers[id] = ch
	m.mu.Unlock()

	return ch
}

// Check tokens in various contexts (DNS, HTTP, etc.)
func (m *Manager) CheckDNSToken(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for value, token := range m.tokens {
		if token.Type == "dns" && strings.Contains(domain, value) {
			go m.TriggerToken(token.ID, "", "DNS query", "", domain)
			return true
		}
	}
	return false
}

func (m *Manager) CheckURLToken(path string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for value, token := range m.tokens {
		if token.Type == "url" && strings.Contains(path, value) {
			return true
		}
	}
	return false
}

func (m *Manager) CheckCredentialToken(username, password string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for value, token := range m.tokens {
		if token.Type == "credential" && (value == username || value == password) {
			return true
		}
	}
	return false
}