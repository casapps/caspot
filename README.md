# caspot - Enterprise Honeypot Platform

caspot is a comprehensive honeypot platform that simulates various network services to detect, log, and analyze malicious activities. It provides a single static binary with an embedded SQLite database for easy deployment and management.

## Features

- **17 Honeypot Services**: SSH, HTTP/HTTPS, FTP, Telnet, SMTP, DNS, TFTP, LDAP, SMB, Syslog, MySQL, RDP, PostgreSQL, VNC, Redis, SNMP
- **Web Admin Panel**: Real-time monitoring and management interface
- **SQLite Database**: All configuration and events stored in a single database
- **Static Binary**: Single executable with zero dependencies
- **Cross-Platform**: Linux, Windows, macOS (AMD64/ARM64)
- **Authentication System**: Secure admin authentication with session management
- **Event Tracking**: Comprehensive logging of all attack attempts
- **Real-time Monitoring**: WebSocket-based live updates

## Quick Start

### Download and Run

```bash
# Download latest release
wget https://github.com/casapps/caspot/releases/latest/download/caspot-linux-amd64

# Make executable
chmod +x caspot-linux-amd64

# Run the honeypot
./caspot-linux-amd64

# Access admin panel at http://localhost:8080
```

### Build from Source

```bash
# Clone repository
git clone https://github.com/casapps/caspot.git
cd caspot

# Build for current platform
make build-host

# Run the binary
./build/caspot
```

## Configuration

On first run, caspot will:
1. Create a database at `/var/lib/caspot/caspot.db` (or `~/.caspot/caspot.db` for non-root users)
2. Guide you through the setup wizard at http://localhost:8080/setup
3. Create an administrator account
4. Initialize all honeypot services

## Usage

```bash
# Show version
caspot --version

# Specify custom database path
caspot --db /path/to/database.db

# Change admin panel port
caspot --port 9000

# Development mode
caspot --dev
```

## Admin Panel

Access the admin panel at http://localhost:8080 (default) to:
- View real-time attack events
- Monitor service status
- Start/stop individual honeypots
- Configure system settings
- View attack statistics

## Services

Currently implemented:
- SSH Honeypot (Port 22) - Simulates SSH server with fake filesystem

Additional services are being developed and will be available in future releases.

## Building

### Build all platforms
```bash
make build
```

### Build specific platform
```bash
# Linux AMD64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o caspot-linux-amd64 ./cmd/caspot

# Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o caspot-windows-amd64.exe ./cmd/caspot

# macOS ARM64 (Apple Silicon)
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o caspot-darwin-arm64 ./cmd/caspot
```

## Security

- All passwords are hashed using bcrypt
- Session tokens are cryptographically secure
- Rate limiting prevents brute force attacks
- IP blocking after repeated failed attempts
- No external dependencies or network calls

## License

MIT License - See LICENSE.md for details

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## Support

For issues and questions, please use the GitHub issue tracker.