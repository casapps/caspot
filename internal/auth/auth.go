package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/casapps/caspot/internal/database"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is locked")
	ErrSessionExpired     = errors.New("session has expired")
)

type Manager struct {
	db *database.DB
}

func NewManager(db *database.DB) *Manager {
	return &Manager{db: db}
}

func (m *Manager) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (m *Manager) VerifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func (m *Manager) CreateUser(username, password, email, fullName string) error {
	passwordHash, err := m.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	return m.db.CreateAdminUser(username, passwordHash, email, fullName)
}

func (m *Manager) Authenticate(username, password, ipAddress, userAgent string) (string, error) {
	conn := m.db.Conn()

	var userID int
	var passwordHash string
	var active bool
	var lockedUntil sql.NullTime
	var loginAttempts int

	err := conn.QueryRow(
		`SELECT id, password_hash, active, locked_until, login_attempts
		FROM admin_users WHERE username = ?`,
		username,
	).Scan(&userID, &passwordHash, &active, &lockedUntil, &loginAttempts)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrInvalidCredentials
		}
		return "", err
	}

	if !active {
		return "", ErrInvalidCredentials
	}

	if lockedUntil.Valid && lockedUntil.Time.After(time.Now()) {
		return "", ErrAccountLocked
	}

	if !m.VerifyPassword(passwordHash, password) {
		_, err = conn.Exec(
			`UPDATE admin_users SET login_attempts = login_attempts + 1,
			locked_until = CASE WHEN login_attempts >= 4 THEN datetime('now', '+15 minutes') ELSE NULL END
			WHERE id = ?`,
			userID,
		)
		return "", ErrInvalidCredentials
	}

	token, err := generateSessionToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}

	expiresAt := time.Now().Add(30 * time.Minute)

	tx, err := conn.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT INTO sessions (token, user_id, expires_at, ip_address, user_agent)
		VALUES (?, ?, ?, ?, ?)`,
		token, userID, expiresAt, ipAddress, userAgent,
	)
	if err != nil {
		return "", err
	}

	_, err = tx.Exec(
		`UPDATE admin_users SET last_login = CURRENT_TIMESTAMP, login_attempts = 0, locked_until = NULL
		WHERE id = ?`,
		userID,
	)
	if err != nil {
		return "", err
	}

	if err = tx.Commit(); err != nil {
		return "", err
	}

	return token, nil
}

func (m *Manager) ValidateSession(token string) (*User, error) {
	conn := m.db.Conn()

	var user User
	var expiresAt time.Time
	var active bool

	err := conn.QueryRow(
		`SELECT u.id, u.username, u.email, u.full_name, u.role, s.expires_at, s.active
		FROM sessions s
		JOIN admin_users u ON s.user_id = u.id
		WHERE s.token = ?`,
		token,
	).Scan(&user.ID, &user.Username, &user.Email, &user.FullName, &user.Role, &expiresAt, &active)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionExpired
		}
		return nil, err
	}

	if !active || expiresAt.Before(time.Now()) {
		return nil, ErrSessionExpired
	}

	_, err = conn.Exec(
		"UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE token = ?",
		token,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (m *Manager) Logout(token string) error {
	conn := m.db.Conn()
	_, err := conn.Exec("UPDATE sessions SET active = FALSE WHERE token = ?", token)
	return err
}

func (m *Manager) CleanupSessions() error {
	conn := m.db.Conn()
	_, err := conn.Exec(
		"DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP OR active = FALSE",
	)
	return err
}

func generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

type User struct {
	ID       int
	Username string
	Email    string
	FullName string
	Role     string
}

func (m *Manager) GetUserByUsername(username string) (*User, error) {
	conn := m.db.Conn()

	var user User
	err := conn.QueryRow(
		"SELECT id, username, email, full_name, role FROM admin_users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.FullName, &user.Role)

	if err != nil {
		return nil, err
	}

	return &user, nil
}