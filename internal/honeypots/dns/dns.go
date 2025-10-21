package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/casapps/caspot/internal/database"
)

type Honeypot struct {
	db       *database.DB
	config   *Config
	conn     *net.UDPConn
	mu       sync.RWMutex
	running  bool
}

type Config struct {
	Port               int
	PoisonDomains      []string
	FakeRecords        map[string]map[string]string
	ZoneTransferEnabled bool
}

func New(db *database.DB, config *Config) (*Honeypot, error) {
	return &Honeypot{
		db:     db,
		config: config,
	}, nil
}

func (h *Honeypot) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("DNS honeypot already running")
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", h.config.Port))
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", h.config.Port, err)
	}

	h.conn = conn
	h.running = true

	go h.handleRequests()

	fmt.Printf("DNS honeypot started on port %d\n", h.config.Port)
	return nil
}

func (h *Honeypot) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.running = false
	if h.conn != nil {
		h.conn.Close()
	}

	return nil
}

func (h *Honeypot) handleRequests() {
	buffer := make([]byte, 512)

	for h.running {
		n, addr, err := h.conn.ReadFromUDP(buffer)
		if err != nil {
			if h.running {
				fmt.Printf("Failed to read UDP: %v\n", err)
			}
			continue
		}

		go h.handleQuery(buffer[:n], addr)
	}
}

func (h *Honeypot) handleQuery(query []byte, addr *net.UDPAddr) {
	if len(query) < 12 {
		return
	}

	sourceIP := strings.Split(addr.String(), ":")[0]

	// Parse DNS query
	domain, qtype := h.parseDNSQuery(query)

	event := &database.Event{
		EventType:   "dns_query",
		SourceIP:    sourceIP,
		DestPort:    h.config.Port,
		ServiceName: "dns",
		Protocol:    "udp",
		Command:     fmt.Sprintf("Query: %s Type: %s", domain, h.getQueryType(qtype)),
		Severity:    "low",
	}

	// Check if it's a poisoned domain
	for _, poison := range h.config.PoisonDomains {
		if strings.Contains(domain, poison) {
			event.Severity = "high"
			event.EventType = "dns_poisoned_query"
			break
		}
	}

	h.db.LogEvent(event)

	// Build response
	response := h.buildResponse(query, domain, qtype)
	h.conn.WriteToUDP(response, addr)
}

func (h *Honeypot) parseDNSQuery(query []byte) (string, uint16) {
	// Skip header (12 bytes)
	pos := 12
	domain := ""

	// Read domain name
	for pos < len(query) {
		length := int(query[pos])
		if length == 0 {
			pos++
			break
		}
		if domain != "" {
			domain += "."
		}
		pos++
		if pos+length <= len(query) {
			domain += string(query[pos : pos+length])
			pos += length
		}
	}

	// Read query type
	var qtype uint16
	if pos+2 <= len(query) {
		qtype = binary.BigEndian.Uint16(query[pos : pos+2])
	}

	return domain, qtype
}

func (h *Honeypot) buildResponse(query []byte, domain string, qtype uint16) []byte {
	response := make([]byte, len(query))
	copy(response, query)

	// Set response flags
	response[2] = 0x81 // Standard query response
	response[3] = 0x80 // No error

	// Answer count
	response[6] = 0
	response[7] = 1

	// Add answer
	answer := h.buildAnswer(domain, qtype)
	response = append(response, answer...)

	return response
}

func (h *Honeypot) buildAnswer(domain string, qtype uint16) []byte {
	answer := []byte{}

	// Pointer to domain name in question
	answer = append(answer, 0xc0, 0x0c)

	// Type and class
	answer = append(answer, byte(qtype>>8), byte(qtype))
	answer = append(answer, 0x00, 0x01) // Class IN

	// TTL (300 seconds)
	answer = append(answer, 0x00, 0x00, 0x01, 0x2c)

	// Add data based on query type
	switch qtype {
	case 1: // A record
		ip := "192.168.1.100"
		if records, ok := h.config.FakeRecords["A"]; ok {
			if fakeIP, ok := records[domain]; ok {
				ip = fakeIP
			}
		}
		ipBytes := net.ParseIP(ip).To4()
		answer = append(answer, 0x00, 0x04) // Data length
		answer = append(answer, ipBytes...)

	case 15: // MX record
		answer = append(answer, 0x00, 0x09) // Data length
		answer = append(answer, 0x00, 0x0a) // Priority 10
		answer = append(answer, 0x04)       // Length of "mail"
		answer = append(answer, []byte("mail")...)
		answer = append(answer, 0xc0, 0x0c) // Pointer to domain

	case 16: // TXT record
		txt := "v=spf1 -all"
		answer = append(answer, 0x00, byte(len(txt)+1))
		answer = append(answer, byte(len(txt)))
		answer = append(answer, []byte(txt)...)

	default:
		// No data for unsupported types
		answer = append(answer, 0x00, 0x00)
	}

	return answer
}

func (h *Honeypot) getQueryType(qtype uint16) string {
	types := map[uint16]string{
		1:  "A",
		2:  "NS",
		5:  "CNAME",
		6:  "SOA",
		12: "PTR",
		15: "MX",
		16: "TXT",
		28: "AAAA",
		33: "SRV",
	}

	if t, ok := types[qtype]; ok {
		return t
	}
	return fmt.Sprintf("TYPE%d", qtype)
}