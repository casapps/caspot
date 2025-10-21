package http

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/casapps/caspot/internal/database"
	"github.com/gorilla/mux"
)

type Honeypot struct {
	db       *database.DB
	config   *Config
	server   *http.Server
	router   *mux.Router
	mu       sync.RWMutex
	running  bool
}

type Config struct {
	Port         int
	UseSSL       bool
	ServerName   string
	Templates    []string
	UploadEnabled bool
	FakeFiles    []string
}

func New(db *database.DB, config *Config) (*Honeypot, error) {
	h := &Honeypot{
		db:     db,
		config: config,
		router: mux.NewRouter(),
	}

	h.setupRoutes()
	return h, nil
}

func (h *Honeypot) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("HTTP honeypot already running")
	}

	h.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", h.config.Port),
		Handler: h.router,
	}

	h.running = true

	go func() {
		var err error
		if h.config.UseSSL {
			tlsConfig := &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
			h.server.TLSConfig = tlsConfig
			err = h.server.ListenAndServeTLS("", "")
		} else {
			err = h.server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	protocol := "HTTP"
	if h.config.UseSSL {
		protocol = "HTTPS"
	}
	fmt.Printf("%s honeypot started on port %d\n", protocol, h.config.Port)
	return nil
}

func (h *Honeypot) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.running = false
	if h.server != nil {
		return h.server.Close()
	}

	return nil
}

func (h *Honeypot) setupRoutes() {
	h.router.HandleFunc("/", h.handleRoot)
	h.router.HandleFunc("/admin", h.handleAdmin)
	h.router.HandleFunc("/login", h.handleLogin).Methods("GET", "POST")
	h.router.HandleFunc("/admin.php", h.handleAdmin)
	h.router.HandleFunc("/phpmyadmin", h.handlePhpMyAdmin)
	h.router.HandleFunc("/wp-admin", h.handleWordPress)
	h.router.HandleFunc("/wp-login.php", h.handleWordPress)
	h.router.HandleFunc("/.env", h.handleSensitiveFile)
	h.router.HandleFunc("/config.php", h.handleSensitiveFile)
	h.router.HandleFunc("/backup.sql", h.handleSensitiveFile)
	h.router.HandleFunc("/passwords.txt", h.handleSensitiveFile)

	if h.config.UploadEnabled {
		h.router.HandleFunc("/upload", h.handleUpload).Methods("POST")
		h.router.HandleFunc("/upload.php", h.handleUpload).Methods("POST")
	}

	h.router.PathPrefix("/").HandlerFunc(h.handleCatchAll)
}

func (h *Honeypot) logRequest(r *http.Request, eventType string) {
	sourceIP := strings.Split(r.RemoteAddr, ":")[0]

	headers, _ := json.Marshal(r.Header)

	event := &database.Event{
		EventType:   eventType,
		SourceIP:    sourceIP,
		DestPort:    h.config.Port,
		ServiceName: "http",
		Protocol:    "tcp",
		Command:     r.URL.Path,
		Payload:     r.Method + " " + r.URL.String() + " UA:" + r.UserAgent() + " Headers:" + string(headers),
		Severity:    "medium",
	}

	if r.Method == "POST" {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			event.Payload = string(body)
			event.Severity = "high"
		}
	}

	if username, password, ok := r.BasicAuth(); ok {
		event.Username = username
		event.Password = password
		event.EventType = "authentication"
		event.Severity = "high"
	}

	h.db.LogEvent(event)
}

func (h *Honeypot) handleRoot(w http.ResponseWriter, r *http.Request) {
	h.logRequest(r, "web_access")

	w.Header().Set("Server", h.config.ServerName)
	w.Header().Set("Content-Type", "text/html")

	html := `<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Welcome to Server</h1>
    <p>Please <a href="/login">login</a> to continue.</p>
</body>
</html>`

	w.Write([]byte(html))
}

func (h *Honeypot) handleLogin(w http.ResponseWriter, r *http.Request) {
	h.logRequest(r, "login_attempt")

	if r.Method == "POST" {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username != "" || password != "" {
			event := &database.Event{
				EventType:   "authentication",
				SourceIP:    strings.Split(r.RemoteAddr, ":")[0],
				DestPort:    h.config.Port,
				ServiceName: "http",
				Protocol:    "tcp",
				Username:    username,
				Password:    password,
				Severity:    "high",
			}
			h.db.LogEvent(event)
		}

		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Server", h.config.ServerName)
	w.Header().Set("Content-Type", "text/html")

	html := `<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>`

	w.Write([]byte(html))
}

func (h *Honeypot) handleAdmin(w http.ResponseWriter, r *http.Request) {
	h.logRequest(r, "admin_access")

	if username, password, ok := r.BasicAuth(); ok {
		event := &database.Event{
			EventType:   "authentication",
			SourceIP:    strings.Split(r.RemoteAddr, ":")[0],
			DestPort:    h.config.Port,
			ServiceName: "http",
			Protocol:    "tcp",
			Username:    username,
			Password:    password,
			Command:     "/admin",
			Severity:    "high",
		}
		h.db.LogEvent(event)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("WWW-Authenticate", `Basic realm="Admin Area"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (h *Honeypot) handlePhpMyAdmin(w http.ResponseWriter, r *http.Request) {
	h.logRequest(r, "phpmyadmin_access")

	w.Header().Set("Server", h.config.ServerName)
	w.Header().Set("Content-Type", "text/html")

	html := `<!DOCTYPE html>
<html>
<head>
    <title>phpMyAdmin</title>
    <style>
        body { font-family: sans-serif; background: #f5f5f5; }
        .container { width: 400px; margin: 100px auto; background: white; padding: 20px; }
        input { width: 100%; padding: 8px; margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h2>phpMyAdmin</h2>
        <form method="POST">
            <input type="text" name="pma_username" placeholder="Username" required>
            <input type="password" name="pma_password" placeholder="Password" required>
            <input type="text" name="server" placeholder="Server" value="localhost">
            <button type="submit">Go</button>
        </form>
    </div>
</body>
</html>`

	if r.Method == "POST" {
		r.ParseForm()
		username := r.FormValue("pma_username")
		password := r.FormValue("pma_password")

		if username != "" || password != "" {
			event := &database.Event{
				EventType:   "authentication",
				SourceIP:    strings.Split(r.RemoteAddr, ":")[0],
				DestPort:    h.config.Port,
				ServiceName: "http",
				Protocol:    "tcp",
				Username:    username,
				Password:    password,
				Command:     "/phpmyadmin",
				Severity:    "high",
			}
			h.db.LogEvent(event)
		}
	}

	w.Write([]byte(html))
}

func (h *Honeypot) handleWordPress(w http.ResponseWriter, r *http.Request) {
	h.logRequest(r, "wordpress_access")

	w.Header().Set("Server", h.config.ServerName)
	w.Header().Set("Content-Type", "text/html")

	html := `<!DOCTYPE html>
<html>
<head>
    <title>WordPress Login</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f1f1f1; }
        .login { width: 320px; margin: 100px auto; background: white; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.13); }
        input { width: 100%; padding: 8px; margin: 8px 0; border: 1px solid #ddd; }
        .button { background: #007cba; color: white; padding: 10px; border: none; width: 100%; cursor: pointer; }
    </style>
</head>
<body>
    <div class="login">
        <h1 style="text-align: center;">WordPress</h1>
        <form method="POST">
            <label>Username or Email Address</label>
            <input type="text" name="log" required>
            <label>Password</label>
            <input type="password" name="pwd" required>
            <button type="submit" class="button">Log In</button>
        </form>
    </div>
</body>
</html>`

	if r.Method == "POST" {
		r.ParseForm()
		username := r.FormValue("log")
		password := r.FormValue("pwd")

		if username != "" || password != "" {
			event := &database.Event{
				EventType:   "authentication",
				SourceIP:    strings.Split(r.RemoteAddr, ":")[0],
				DestPort:    h.config.Port,
				ServiceName: "http",
				Protocol:    "tcp",
				Username:    username,
				Password:    password,
				Command:     "/wp-admin",
				Severity:    "high",
			}
			h.db.LogEvent(event)
		}
	}

	w.Write([]byte(html))
}

func (h *Honeypot) handleSensitiveFile(w http.ResponseWriter, r *http.Request) {
	h.logRequest(r, "sensitive_file_access")

	event := &database.Event{
		EventType:   "data_access",
		SourceIP:    strings.Split(r.RemoteAddr, ":")[0],
		DestPort:    h.config.Port,
		ServiceName: "http",
		Protocol:    "tcp",
		Command:     r.URL.Path,
		Severity:    "critical",
	}
	h.db.LogEvent(event)

	content := ""
	switch r.URL.Path {
	case "/.env":
		content = "DB_HOST=localhost\nDB_USER=root\nDB_PASS=password123\nAPI_KEY=sk-1234567890abcdef"
	case "/config.php":
		content = "<?php\n$db_host = 'localhost';\n$db_user = 'root';\n$db_pass = 'admin123';\n?>"
	case "/backup.sql":
		content = "-- MySQL dump\nINSERT INTO users VALUES ('admin', 'password123');"
	case "/passwords.txt":
		content = "admin:password123\nuser:12345678\nroot:toor"
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(content))
}

func (h *Honeypot) handleUpload(w http.ResponseWriter, r *http.Request) {
	h.logRequest(r, "file_upload")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseMultipartForm(10 << 20)

	file, handler, err := r.FormFile("file")
	if err == nil {
		defer file.Close()

		fileContent, _ := io.ReadAll(file)

		event := &database.Event{
			EventType:   "file_upload",
			SourceIP:    strings.Split(r.RemoteAddr, ":")[0],
			DestPort:    h.config.Port,
			ServiceName: "http",
			Protocol:    "tcp",
			Command:     "/upload",
			Payload:     fmt.Sprintf("filename=%s size=%d", handler.Filename, len(fileContent)),
			Severity:    "critical",
		}
		h.db.LogEvent(event)
	}

	w.Write([]byte("Upload successful"))
}

func (h *Honeypot) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	h.logRequest(r, "web_scan")

	w.Header().Set("Server", h.config.ServerName)
	http.Error(w, "Not Found", http.StatusNotFound)
}