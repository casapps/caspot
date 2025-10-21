package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/caspot/internal/auth"
	"github.com/casapps/caspot/internal/database"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type Server struct {
	db       *database.DB
	auth     *auth.Manager
	services interface{} // Will be set to services.Manager
	router   *mux.Router
	server   *http.Server
	upgrader websocket.Upgrader
}

func NewServer(db *database.DB, authManager *auth.Manager) *Server {
	s := &Server{
		db:   db,
		auth: authManager,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}

	s.setupRoutes()
	return s
}

func (s *Server) SetServiceManager(manager interface{}) {
	s.services = manager
}

func (s *Server) setupRoutes() {
	s.router = mux.NewRouter()

	s.router.HandleFunc("/", s.handleIndex).Methods("GET")
	s.router.HandleFunc("/setup", s.handleSetup).Methods("GET", "POST")
	s.router.HandleFunc("/login", s.handleLogin).Methods("GET", "POST")
	s.router.HandleFunc("/logout", s.handleLogout).Methods("POST")

	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.authMiddleware)

	api.HandleFunc("/dashboard", s.handleDashboard).Methods("GET")
	api.HandleFunc("/events", s.handleEvents).Methods("GET")
	api.HandleFunc("/services", s.handleServices).Methods("GET")
	api.HandleFunc("/services/{name}", s.handleServiceControl).Methods("POST")
	api.HandleFunc("/config", s.handleConfig).Methods("GET", "PUT")
	api.HandleFunc("/ws", s.handleWebSocket)

	s.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
}

func (s *Server) Start(port int) error {
	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Printf("Admin panel starting on http://localhost:%d\n", port)
	return s.server.ListenAndServe()
}

func (s *Server) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	isFirstRun, err := s.db.IsFirstRun()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if isFirstRun {
		http.Redirect(w, r, "/setup", http.StatusTemporaryRedirect)
		return
	}

	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	user, err := s.auth.ValidateSession(cookie.Value)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	s.renderDashboard(w, user)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	isFirstRun, err := s.db.IsFirstRun()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if !isFirstRun {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if r.Method == "GET" {
		s.renderTemplate(w, "setup", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")
	fullName := r.FormValue("fullName")

	if username == "" || password == "" || email == "" {
		s.renderTemplate(w, "setup", map[string]interface{}{
			"Error": "All fields are required",
		})
		return
	}

	if len(password) < 12 {
		s.renderTemplate(w, "setup", map[string]interface{}{
			"Error": "Password must be at least 12 characters",
		})
		return
	}

	err = s.auth.CreateUser(username, password, email, fullName)
	if err != nil {
		s.renderTemplate(w, "setup", map[string]interface{}{
			"Error": "Failed to create user: " + err.Error(),
		})
		return
	}

	http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.renderTemplate(w, "login", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	token, err := s.auth.Authenticate(username, password, r.RemoteAddr, r.UserAgent())
	if err != nil {
		s.renderTemplate(w, "login", map[string]interface{}{
			"Error": "Invalid username or password",
		})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   1800,
	})

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		s.auth.Logout(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	conn := s.db.Conn()

	stats := struct {
		TotalEvents    int
		ActiveServices int
		UniqueIPs      int
		Last24Hours    int
	}{}

	conn.QueryRow("SELECT COUNT(*) FROM events").Scan(&stats.TotalEvents)
	conn.QueryRow("SELECT COUNT(*) FROM honeypot_services WHERE status = 'running'").Scan(&stats.ActiveServices)
	conn.QueryRow("SELECT COUNT(DISTINCT source_ip) FROM events").Scan(&stats.UniqueIPs)
	conn.QueryRow("SELECT COUNT(*) FROM events WHERE timestamp > datetime('now', '-1 day')").Scan(&stats.Last24Hours)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	conn := s.db.Conn()

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	rows, err := conn.Query(
		`SELECT id, timestamp, event_type, source_ip, source_port, destination_port,
		service_name, username, password, command, severity
		FROM events ORDER BY timestamp DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var e database.Event
		var username, password, command sql.NullString

		err := rows.Scan(&e.ID, &e.Timestamp, &e.EventType, &e.SourceIP, &e.SourcePort,
			&e.DestPort, &e.ServiceName, &username, &password, &command, &e.Severity)
		if err != nil {
			continue
		}

		event := map[string]interface{}{
			"id":        e.ID,
			"timestamp": e.Timestamp,
			"type":      e.EventType,
			"sourceIP":  e.SourceIP,
			"sourcePort": e.SourcePort,
			"destPort":  e.DestPort,
			"service":   e.ServiceName,
			"severity":  e.Severity,
		}

		if username.Valid {
			event["username"] = username.String
		}
		if password.Valid {
			event["password"] = password.String
		}
		if command.Valid {
			event["command"] = command.String
		}

		events = append(events, event)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	services, err := s.db.GetServices()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

func (s *Server) handleServiceControl(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
	action := r.FormValue("action")

	var status string
	switch action {
	case "start":
		status = "running"
	case "stop":
		status = "stopped"
	case "restart":
		status = "running"
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	err := s.db.UpdateServiceStatus(name, status)
	if err != nil {
		http.Error(w, "Failed to update service", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
		"service": name,
		"action": action,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		conn := s.db.Conn()
		rows, err := conn.Query("SELECT key, value, description, category FROM system_config ORDER BY category, key")
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		configs := make(map[string][]map[string]string)
		for rows.Next() {
			var key, value, description, category string
			rows.Scan(&key, &value, &description, &category)

			if configs[category] == nil {
				configs[category] = []map[string]string{}
			}

			configs[category] = append(configs[category], map[string]string{
				"key":         key,
				"value":       value,
				"description": description,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(configs)
		return
	}

	var updates map[string]string
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user := r.Context().Value("user").(*auth.User)

	for key, value := range updates {
		s.db.SetConfig(key, value, user.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dbConn := s.db.Conn()

			var count int
			dbConn.QueryRow("SELECT COUNT(*) FROM events WHERE timestamp > datetime('now', '-5 seconds')").Scan(&count)

			if count > 0 {
				conn.WriteJSON(map[string]interface{}{
					"type": "new_events",
					"count": count,
				})
			}
		}
	}
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			token := r.Header.Get("Authorization")
			if token == "" {
				cookie, err := r.Cookie("session")
				if err != nil {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				token = cookie.Value
			} else {
				token = strings.TrimPrefix(token, "Bearer ")
			}

			user, err := s.auth.ValidateSession(token)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "user", user)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, err := template.ParseFiles(fmt.Sprintf("web/templates/%s.html", name), "web/templates/base.html")
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.ExecuteTemplate(w, "base", data)
}

func (s *Server) renderDashboard(w http.ResponseWriter, user *auth.User) {
	data := map[string]interface{}{
		"User": user,
		"Title": "caspot Dashboard",
	}
	s.renderTemplate(w, "dashboard", data)
}