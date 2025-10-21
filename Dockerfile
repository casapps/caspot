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

# Copy web assets
COPY --from=builder /app/web /web

# Create data directory
VOLUME ["/var/lib/caspot"]

# Expose ports
# Admin panel
EXPOSE 8080

# Honeypot services
EXPOSE 21 22 23 25 53/udp 69/udp 80 161/udp 389 443 445 514/udp 636 \
       3306 3389 5432 5900 6379

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ["/caspot", "--version"]

# Run application
ENTRYPOINT ["/caspot"]
CMD ["--db", "/var/lib/caspot/caspot.db"]