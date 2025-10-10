package main

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"sort"

	"encoding/json"

	"github.com/hashicorp/mdns"
)

// Configuration represents peernix configuration settings
type Config struct {
	UDPPort           string        `conf:"udp-port"`
	HTTPPort          string        `conf:"http-port"`
	SigningEnabled    bool          `conf:"signing-enabled"`
	KeyFile           string        `conf:"key-file"`
	KeyName           string        `conf:"key-name"`
	DiscoveryInterval time.Duration `conf:"discovery-interval"`
	PeerTTL           time.Duration `conf:"peer-ttl"`
	CompressionEnabled bool         `conf:"compression-enabled"`
	MaxConnections    int           `conf:"max-connections"`
	RequestTimeout    time.Duration `conf:"request-timeout"`
}

// Default configuration
var config = Config{
	UDPPort:           "9999",
	HTTPPort:          "9999",
	SigningEnabled:    true,
	KeyFile:           "peernix-signing.key",
	KeyName:           "peernix-1",
	DiscoveryInterval: 30 * time.Second,
	PeerTTL:           2 * time.Minute,
	CompressionEnabled: true,
	MaxConnections:    100,
	RequestTimeout:    5 * time.Minute, // Allow 5 minutes for large file transfers
}

type Peer struct {
	Addr         string
	TTL          time.Time
	Version      string // Peernix version
	NixVersion   string // Nix version
	Platform     string // OS/arch info
	Features     []string // Supported features
	PublicKey    string // Ed25519 public key
	LastSeen     time.Time // Last successful response
	FailureCount int // Consecutive failure count
	ResponseTime time.Duration // Average response time
}

// DiscoveryMessage represents the enhanced UDP discovery protocol
type DiscoveryMessage struct {
	Command       string   `json:"cmd"`
	PeernixVersion string   `json:"peernix_version"`
	NixVersion     string   `json:"nix_version,omitempty"`
	Platform       string   `json:"platform,omitempty"`
	Features       []string `json:"features,omitempty"`
	PublicKey      string   `json:"public_key,omitempty"`
	Port           int      `json:"port,omitempty"`
}

// Metrics holds all the metrics for Prometheus
type Metrics struct {
	Hits                  atomic.Uint64
	Misses                atomic.Uint64
	FilesSent             atomic.Uint64
	BytesSent             atomic.Uint64
	FilesReceived         atomic.Uint64
	BytesReceived         atomic.Uint64
	UDPQueriesReceived    atomic.Uint64 // Total UDP query requests received
	UDPQueriesFound       atomic.Uint64 // UDP queries we responded "yes" to
	PeerQueriesAttempted  atomic.Uint64 // Queries we made to peers
	PeerQueriesSuccessful atomic.Uint64 // Successful peer queries
	RequestTimes          []time.Duration
	RequestMux            sync.RWMutex
}

var (
	peers        []Peer
	peersMux     sync.RWMutex
	logger       *syslog.Writer
	localIPs     []string
	metrics      = &Metrics{}
	peerClients  = make(map[string]*http.Client)
	clientsMux   sync.RWMutex
	signingKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	keyName      = "peernix-1" // Key identifier for signatures
	signingEnabled = false

	// mDNS server instance (global to prevent leaks)
	mdnsServer   *mdns.Server
	mdnsShutdown context.CancelFunc

	// Request deduplication
	pendingRequests = make(map[string]chan *net.UDPAddr)
	requestsMux     sync.RWMutex

	// Store operation cache for resource conservation
	storeCache     = make(map[string]storeResult)
	storeCacheMux  sync.RWMutex

	// narInfoPeerCache caches which peer served a .narinfo file
	narInfoPeerCache    = make(map[string]string)
	narInfoPeerCacheMux sync.RWMutex
)

// storeResult caches nix-store operation results
type storeResult struct {
	result    interface{}
	timestamp time.Time
	err       error
}

// getLocalIPs returns all local IP addresses
func getLocalIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ips = append(ips, ipnet.IP.String())
		}
	}
	return ips
}

// isLocalIP checks if an IP is one of our local IPs
func isLocalIP(ip string) bool {
	for _, localIP := range localIPs {
		if localIP == ip {
			return true
		}
	}
	return false
}

// supportsCompression checks if client accepts gzip compression
func supportsCompression(acceptEncoding string) bool {
	return strings.Contains(strings.ToLower(acceptEncoding), "gzip")
}

// getPeerClient returns a pooled HTTP client for a peer, creating one if needed
func getPeerClient(peerAddr string) *http.Client {
	clientsMux.RLock()
	client, exists := peerClients[peerAddr]
	clientsMux.RUnlock()

	if exists {
		return client
	}

	// Create new client with connection pooling
	clientsMux.Lock()
	defer clientsMux.Unlock()

	// Double-check after acquiring write lock
	if client, exists := peerClients[peerAddr]; exists {
		return client
	}

	client = &http.Client{
		Timeout: config.RequestTimeout, // Configurable timeout for large file transfers
		Transport: &http.Transport{
			// Connection pool settings optimized for peer-to-peer usage
			MaxIdleConns:        config.MaxConnections,
			MaxIdleConnsPerHost: 20, // Limit per host to prevent resource exhaustion
			IdleConnTimeout:     60 * time.Second, // Keep connections longer for efficiency
			DisableKeepAlives:   false,

			// Aggressive timeouts for P2P - fail fast on unresponsive peers
			DialContext: (&net.Dialer{
				Timeout: 1 * time.Second, // Quick connection establishment
			}).DialContext,
			TLSHandshakeTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 2 * time.Second, // Fast header response

			// Connection reuse settings
			MaxConnsPerHost:     3, // Limit concurrent connections per peer
			ForceAttemptHTTP2:   false, // Disable HTTP/2 for simplicity
		},
	}

	peerClients[peerAddr] = client
	log.Printf("[DEBUG] Created HTTP client for peer %s with timeout %v", peerAddr, config.RequestTimeout)
	return client
}

// initializeSigning sets up Ed25519 signing keys and writes nix.peernix.conf
func initializeSigning() error {
	keyFile := config.KeyFile
	keyName = config.KeyName

	// Try to load existing key
	if keyData, err := os.ReadFile(keyFile); err == nil {
		if len(keyData) == ed25519.PrivateKeySize {
			signingKey = ed25519.PrivateKey(keyData)
			publicKey = signingKey.Public().(ed25519.PublicKey)
			signingEnabled = true
			log.Printf("[INFO] Loaded existing signing key from %s", keyFile)
			return writePeernixConf()
		}
	}

	// Generate new key
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate signing key: %v", err)
	}

	// Save key to file
	if err := os.WriteFile(keyFile, privateKey, 0600); err != nil {
		log.Printf("[WARN] Failed to save signing key: %v", err)
	} else {
		log.Printf("[INFO] Generated and saved new signing key to %s", keyFile)
	}

signingKey = privateKey
	publicKey = privateKey.Public().(ed25519.PublicKey)
	signingEnabled = true
	return writePeernixConf()
}

// writePeernixConf writes a standalone nix config fragment for peernix
func writePeernixConf() error {
	substituterURL := fmt.Sprintf("http://localhost:%s/nix-cache/?trusted=1", config.HTTPPort)
	confFile := "nix.peernix.conf"

	var b strings.Builder
	fmt.Fprintf(&b, "extra-substituters = %s\n", substituterURL)
	fmt.Fprintf(&b, "extra-trusted-substituters = %s\n", substituterURL)

	if signingEnabled {
		publicKeyEncoded := base64.StdEncoding.EncodeToString(publicKey)
		fmt.Fprintf(&b, "extra-trusted-public-keys = %s:%s\n", keyName, publicKeyEncoded)
	}

	if err := os.WriteFile(confFile, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %v", confFile, err)
	}

	log.Printf("[INFO] Wrote peernix config fragment to %s (add `!include %s` in nix.conf)", confFile, confFile)
	return nil
}

// signNarInfo generates a signature for narinfo content using Nix format
func signNarInfo(content string) string {
	if !signingEnabled {
		return ""
	}

signature := ed25519.Sign(signingKey, []byte(content))
	return keyName + ":" + base64.StdEncoding.EncodeToString(signature)
}

// getNixVersion gets the local Nix version
func getNixVersion() string {
	cmd := exec.Command("nix", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// getSupportedFeatures returns list of features this peernix instance supports
func getSupportedFeatures() []string {
	features := []string{"compression", "parallel", "health"}
	if signingEnabled {
		features = append(features, "signing")
	}
	return features
}

// createDiscoveryMessage creates a discovery message with current instance info
func createDiscoveryMessage(command string) DiscoveryMessage {
	msg := DiscoveryMessage{
		Command:       command,
		PeernixVersion: "2.0.0", // Version with enhanced discovery
		Platform:      fmt.Sprintf("%s-%s", runtime.GOARCH, runtime.GOOS),
		Features:      getSupportedFeatures(),
		Port:          mustParseInt(config.HTTPPort),
	}

	// Add optional fields
	if command == "announce" {
		msg.NixVersion = getNixVersion()
		if signingEnabled {
			publicKeyEncoded := base64.StdEncoding.EncodeToString(publicKey)
			msg.PublicKey = keyName + ":" + publicKeyEncoded
		}
	}

	return msg
}

// mustParseInt parses int or returns 0
func mustParseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

// loadConfig loads configuration from peernix.conf in nix.conf format
func loadConfig() error {
	configFile := "peernix.conf"

	// Check if config file exists
	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[INFO] No config file found, using defaults")
			return nil
		}
		return fmt.Errorf("failed to read config file: %v", err)
	}

	log.Printf("[INFO] Loading configuration from %s", configFile)

	// Parse nix.conf style configuration (key = value)
	lines := strings.Split(string(data), "\n")
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key = value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("[WARN] Invalid config line %d: %s", lineNum+1, line)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Apply configuration values
		switch key {
		case "udp-port":
			config.UDPPort = value
		case "http-port":
			config.HTTPPort = value
		case "signing-enabled":
			config.SigningEnabled = value == "true" || value == "1" || value == "yes"
		case "key-file":
			config.KeyFile = value
		case "key-name":
			config.KeyName = value
		case "discovery-interval":
			if duration, err := time.ParseDuration(value); err == nil {
				config.DiscoveryInterval = duration
			} else {
				log.Printf("[WARN] Invalid discovery-interval: %s", value)
			}
		case "peer-ttl":
			if duration, err := time.ParseDuration(value); err == nil {
				config.PeerTTL = duration
			} else {
				log.Printf("[WARN] Invalid peer-ttl: %s", value)
			}
		case "compression-enabled":
			config.CompressionEnabled = value == "true" || value == "1" || value == "yes"
		case "max-connections":
			if num, err := strconv.Atoi(value); err == nil {
				config.MaxConnections = num
			} else {
				log.Printf("[WARN] Invalid max-connections: %s", value)
			}
		case "request-timeout":
			if duration, err := time.ParseDuration(value); err == nil {
				config.RequestTimeout = duration
			} else {
				log.Printf("[WARN] Invalid request-timeout: %s", value)
			}
		default:
			log.Printf("[WARN] Unknown config key: %s", key)
		}
	}

	log.Printf("[INFO] Configuration loaded: UDP=%s HTTP=%s Signing=%t Compression=%t RequestTimeout=%v",
		config.UDPPort, config.HTTPPort, config.SigningEnabled, config.CompressionEnabled, config.RequestTimeout)
	return nil
}

// detectNixDaemon detects which Nix daemon is running and returns restart command
func detectNixDaemon() string {
	// Check if Determinate Nix daemon is running
	cmd := exec.Command("launchctl", "list", "systems.determinate.nix-daemon")
	if err := cmd.Run(); err == nil {
		return "sudo launchctl kickstart -k system/systems.determinate.nix-daemon"
	}

	// Check if standard Nix daemon is running
	cmd = exec.Command("launchctl", "list", "org.nixos.nix-daemon")
	if err := cmd.Run(); err == nil {
		return "sudo launchctl kickstart -k system/org.nixos.nix-daemon"
	}

	// Fallback to standard Nix daemon
	return "sudo launchctl kickstart -k system/org.nixos.nix-daemon"
}

// checkNixConfig checks if peernix is configured as a substituter and trusted key
func checkNixConfig() {
	substituterURL := fmt.Sprintf("http://localhost:%s/nix-cache/", config.HTTPPort)

	// Check substituters
	cmd := exec.Command("nix", "config", "show", "substituters")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("[WARN] Failed to check nix config: %v", err)
		return
	}
	hasSubstituter := strings.Contains(string(output), substituterURL)

	// Check trusted-public-keys
	cmd = exec.Command("nix", "config", "show", "trusted-public-keys")
	keyOutput, err := cmd.Output()
	if err != nil {
		log.Printf("[WARN] Failed to check nix trusted-public-keys: %v", err)
		return
	}
	hasTrustedKey := true
	if signingEnabled {
		publicKeyEncoded := base64.StdEncoding.EncodeToString(publicKey)
		expectedKey := fmt.Sprintf("%s:%s", keyName, publicKeyEncoded)
		hasTrustedKey = strings.Contains(string(keyOutput), expectedKey)
	}

	if hasSubstituter && hasTrustedKey {
		log.Printf("[INFO] peernix is configured as a substituter ✓")
	} else {
		log.Printf("[WARN] ========================================")
		log.Printf("[WARN] peernix is not fully configured!")
		log.Printf("[WARN] To enable peernix, ensure your nix.conf contains:")
		log.Printf("[WARN]   !include /etc/nix/nix.peernix.conf")
		log.Printf("[WARN] Then restart the nix daemon: %s", detectNixDaemon())
		log.Printf("[WARN] ========================================")
	}
}

func main() {
	var err error

	// Load configuration first
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	logger, err = syslog.New(syslog.LOG_INFO, "org.zw3rk.peernix")
	if err != nil {
		// Fall back to console logging if syslog fails
		log.Printf("Failed to setup syslog: %v, using console logging\n", err)
	} else {
		defer logger.Close()
	}

	logInfo := func(msg string) {
		if logger != nil {
			logger.Info(msg)
		}
		log.Printf("[INFO] %s", msg)
	}

	// Get local IPs to avoid self-pinging
	localIPs = getLocalIPs()
	logInfo(fmt.Sprintf("Local IPs: %v", localIPs))

	logInfo("Starting peernix server on ports UDP:" + config.UDPPort + " HTTP:" + config.HTTPPort)

	// Initialize signing (optional) - do this before config check
	if config.SigningEnabled {
		if err := initializeSigning(); err != nil {
			log.Printf("[WARN] Signing disabled: %v", err)
			signingEnabled = false
		}
	} else {
		log.Printf("[INFO] Signing disabled by configuration")
		signingEnabled = false
	}

	// Check nix configuration
	checkNixConfig()

	// Start mDNS service advertising once
	if err := startMDNSServer(); err != nil {
		log.Printf("[WARN] Failed to start mDNS server: %v", err)
	}

	go udpServer()
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/status", handleStatus)
	http.HandleFunc("/ping", handlePing)
	http.HandleFunc("/nix-cache/nix-cache-info", handleNixCacheInfo)
	http.HandleFunc("/nix-cache/", handleNixCache)
	http.HandleFunc("/public-key", handlePublicKey)

	// Create HTTP server with controlled concurrency to prevent resource exhaustion
	server := &http.Server{
		Addr: ":" + config.HTTPPort,
		// Limit concurrent connections based on max-connections setting
		MaxHeaderBytes: 1024 * 16, // 16KB header limit
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   300 * time.Second, // Allow time for large file transfers
		IdleTimeout:    60 * time.Second,
	}

	log.Printf("[INFO] HTTP server starting on :%s (max concurrent: ~%d)", config.HTTPPort, config.MaxConnections*10)
	if err := server.ListenAndServe(); err != nil {
		log.Printf("[ERROR] HTTP server failed: %v", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	// Only respond to exact root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("peernix server running\n"))
}

func handleNixCacheInfo(w http.ResponseWriter, r *http.Request) {
	// Nix binary cache info endpoint - required by Nix protocol
	w.Header().Set("Content-Type", "text/x-nix-cache-info")
	fmt.Fprintf(w, "StoreDir: /nix/store\n")
	fmt.Fprintf(w, "WantMassQuery: 0\n")
	fmt.Fprintf(w, "Priority: 10\n")
	log.Printf("[DEBUG] Served nix-cache-info to %s", r.RemoteAddr)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	// Calculate average latency and trim request times
	metrics.RequestMux.Lock()
	var avgLatency time.Duration
	if len(metrics.RequestTimes) > 0 {
		var total time.Duration
		for _, t := range metrics.RequestTimes {
			total += t
		}
		avgLatency = total / time.Duration(len(metrics.RequestTimes))

		// Keep only last 1000 request times (now safe under write lock)
		if len(metrics.RequestTimes) > 1000 {
			metrics.RequestTimes = metrics.RequestTimes[len(metrics.RequestTimes)-1000:]
		}
	}
	metrics.RequestMux.Unlock()

	// Get peer count
	peersMux.RLock()
	peerCount := len(peers)
	peersMux.RUnlock()

	// Generate Prometheus metrics
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP peernix_hits_total Total number of cache hits\n")
	fmt.Fprintf(w, "# TYPE peernix_hits_total counter\n")
	fmt.Fprintf(w, "peernix_hits_total %d\n", metrics.Hits.Load())

	fmt.Fprintf(w, "# HELP peernix_misses_total Total number of cache misses\n")
	fmt.Fprintf(w, "# TYPE peernix_misses_total counter\n")
	fmt.Fprintf(w, "peernix_misses_total %d\n", metrics.Misses.Load())

	fmt.Fprintf(w, "# HELP peernix_files_sent_total Total number of files sent\n")
	fmt.Fprintf(w, "# TYPE peernix_files_sent_total counter\n")
	fmt.Fprintf(w, "peernix_files_sent_total %d\n", metrics.FilesSent.Load())

	fmt.Fprintf(w, "# HELP peernix_bytes_sent_total Total bytes sent\n")
	fmt.Fprintf(w, "# TYPE peernix_bytes_sent_total counter\n")
	fmt.Fprintf(w, "peernix_bytes_sent_total %d\n", metrics.BytesSent.Load())

	fmt.Fprintf(w, "# HELP peernix_files_received_total Total number of files received from peers\n")
	fmt.Fprintf(w, "# TYPE peernix_files_received_total counter\n")
	fmt.Fprintf(w, "peernix_files_received_total %d\n", metrics.FilesReceived.Load())

	fmt.Fprintf(w, "# HELP peernix_bytes_received_total Total bytes received from peers\n")
	fmt.Fprintf(w, "# TYPE peernix_bytes_received_total counter\n")
	fmt.Fprintf(w, "peernix_bytes_received_total %d\n", metrics.BytesReceived.Load())

	fmt.Fprintf(w, "# HELP peernix_udp_queries_received_total Total UDP query requests received\n")
	fmt.Fprintf(w, "# TYPE peernix_udp_queries_received_total counter\n")
	fmt.Fprintf(w, "peernix_udp_queries_received_total %d\n", metrics.UDPQueriesReceived.Load())

	fmt.Fprintf(w, "# HELP peernix_udp_queries_found_total UDP queries we responded yes to\n")
	fmt.Fprintf(w, "# TYPE peernix_udp_queries_found_total counter\n")
	fmt.Fprintf(w, "peernix_udp_queries_found_total %d\n", metrics.UDPQueriesFound.Load())

	fmt.Fprintf(w, "# HELP peernix_peer_queries_attempted_total Queries we made to peers\n")
	fmt.Fprintf(w, "# TYPE peernix_peer_queries_attempted_total counter\n")
	fmt.Fprintf(w, "peernix_peer_queries_attempted_total %d\n", metrics.PeerQueriesAttempted.Load())

	fmt.Fprintf(w, "# HELP peernix_peer_queries_successful_total Successful peer queries\n")
	fmt.Fprintf(w, "# TYPE peernix_peer_queries_successful_total counter\n")
	fmt.Fprintf(w, "peernix_peer_queries_successful_total %d\n", metrics.PeerQueriesSuccessful.Load())

	fmt.Fprintf(w, "# HELP peernix_peers_current Current number of known peers\n")
	fmt.Fprintf(w, "# TYPE peernix_peers_current gauge\n")
	fmt.Fprintf(w, "peernix_peers_current %d\n", peerCount)

	fmt.Fprintf(w, "# HELP peernix_request_latency_ms Average request latency in milliseconds\n")
	fmt.Fprintf(w, "# TYPE peernix_request_latency_ms gauge\n")
	fmt.Fprintf(w, "peernix_request_latency_ms %d\n", avgLatency.Milliseconds())
}

func handlePublicKey(w http.ResponseWriter, r *http.Request) {
	if !signingEnabled {
		http.Error(w, "Signing not enabled", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	publicKeyEncoded := base64.StdEncoding.EncodeToString(publicKey)
	fmt.Fprintf(w, "%s:%s\n", keyName, publicKeyEncoded)
	log.Printf("[DEBUG] Served public key to %s", r.RemoteAddr)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	// System information
	fmt.Fprintf(w, "Peernix Status\n")
	fmt.Fprintf(w, "==============\n\n")
	fmt.Fprintf(w, "Version: 2.0.0\n")
	fmt.Fprintf(w, "Platform: %s-%s\n", runtime.GOARCH, runtime.GOOS)
	fmt.Fprintf(w, "Features: %s\n", strings.Join(getSupportedFeatures(), ", "))
	fmt.Fprintf(w, "Signing: %t\n", signingEnabled)
	if signingEnabled {
		publicKeyEncoded := base64.StdEncoding.EncodeToString(publicKey)
		fmt.Fprintf(w, "Public Key: %s:%s\n", keyName, publicKeyEncoded)
	}
	fmt.Fprintf(w, "Ports: UDP=%s HTTP=%s\n", config.UDPPort, config.HTTPPort)
	fmt.Fprintf(w, "Compression: %t\n", config.CompressionEnabled)
	fmt.Fprintf(w, "Discovery Interval: %s\n", config.DiscoveryInterval)
	fmt.Fprintf(w, "Peer TTL: %s\n\n", config.PeerTTL)

	// Metrics summary
	fmt.Fprintf(w, "Metrics\n")
	fmt.Fprintf(w, "-------\n")
	fmt.Fprintf(w, "Cache Hits: %d\n", metrics.Hits.Load())
	fmt.Fprintf(w, "Cache Misses: %d\n", metrics.Misses.Load())
	fmt.Fprintf(w, "Files Sent: %d\n", metrics.FilesSent.Load())
	fmt.Fprintf(w, "Bytes Sent: %d\n", metrics.BytesSent.Load())
	fmt.Fprintf(w, "Files Received: %d\n", metrics.FilesReceived.Load())
	fmt.Fprintf(w, "Bytes Received: %d\n", metrics.BytesReceived.Load())

	// Average latency
	metrics.RequestMux.RLock()
	var avgLatency time.Duration
	if len(metrics.RequestTimes) > 0 {
		var total time.Duration
		for _, t := range metrics.RequestTimes {
			total += t
		}
		avgLatency = total / time.Duration(len(metrics.RequestTimes))
	}
	metrics.RequestMux.RUnlock()
	fmt.Fprintf(w, "Avg Latency: %s\n\n", avgLatency.String())

	// Discovered peers
	peersMux.RLock()
	peerCount := len(peers)
	currentPeers := make([]Peer, len(peers))
	copy(currentPeers, peers)
	peersMux.RUnlock()

	fmt.Fprintf(w, "Discovered Peers (%d)\n", peerCount)
	fmt.Fprintf(w, "----------------\n")
	if peerCount == 0 {
		fmt.Fprintf(w, "No peers discovered yet.\n")
	} else {
		for _, peer := range currentPeers {
			fmt.Fprintf(w, "Peer: %s\n", peer.Addr)
			if peer.Version != "" {
				fmt.Fprintf(w, "  Peernix Version: %s\n", peer.Version)
			}
			if peer.NixVersion != "" {
				fmt.Fprintf(w, "  Nix Version: %s\n", peer.NixVersion)
			}
			if peer.Platform != "" {
				fmt.Fprintf(w, "  Platform: %s\n", peer.Platform)
			}
			if len(peer.Features) > 0 {
				fmt.Fprintf(w, "  Features: %s\n", strings.Join(peer.Features, ", "))
			}
			if peer.PublicKey != "" {
				fmt.Fprintf(w, "  Public Key: %s\n", peer.PublicKey)
			}
			fmt.Fprintf(w, "  Last Seen: %s\n", peer.TTL.Add(-config.PeerTTL).Format("15:04:05"))
			fmt.Fprintf(w, "  Expires: %s\n", peer.TTL.Format("15:04:05"))
			fmt.Fprintf(w, "\n")
		}
	}

	log.Printf("[DEBUG] Served status to %s", r.RemoteAddr)
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "pong\n")
}

func udpServer() {
	port, _ := strconv.Atoi(config.UDPPort)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		log.Printf("[ERROR] Failed to start UDP server: %v", err)
		return
	}
	defer conn.Close()
	conn.SetWriteBuffer(1024)
	log.Printf("[INFO] UDP server started on :%s", config.UDPPort)

	// Announce presence immediately on startup
	log.Printf("[INFO] " + "Running initial peer discovery")
	go updatePeers()

	// Reduced initial discovery: 2 attempts at 5-second intervals for lower idle load
	go func() {
		for i := 0; i < 2; i++ {
			time.Sleep(5 * time.Second)
			log.Printf("[INFO] Running initial discovery %d/2", i+1)
			updatePeers()
		}
		log.Printf("[INFO] " + "Initial discovery phase completed")
	}()

	// Start periodic discovery after initial phase
	go func() {
		// Wait for initial phase to complete
		time.Sleep(15 * time.Second)

		for range time.Tick(config.DiscoveryInterval) {
			log.Printf("[DEBUG] " + "Running periodic peer discovery")
			updatePeers()
		}
	}()

	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[WARN] UDP read error: %v", err)
			continue
		}

		// Handle each message concurrently to prevent blocking
		go func(msg string, addr *net.UDPAddr) {
			if strings.HasPrefix(msg, "has_path?") {
				hash := strings.TrimPrefix(msg, "has_path?")
				metrics.UDPQueriesReceived.Add(1)
				// Reduced logging verbosity - only log successful responses to reduce noise
				if hasPath(hash) {
					metrics.UDPQueriesFound.Add(1)
					log.Printf("[INFO] Responding YES to %s for hash: %s", addr, hash)
					conn.WriteToUDP([]byte("yes"), addr)
				}
			} else if msg == "ping" {
				// Backward compatibility: simple ping/pong
				if isLocalIP(addr.IP.String()) {
					log.Printf("[DEBUG] Ignoring ping from self (%s)", addr)
				} else {
					log.Printf("[DEBUG] Received ping from %s, sending pong", addr)
					conn.WriteToUDP([]byte("pong"), addr)
				}
			} else if strings.HasPrefix(msg, "{") {
				// Enhanced discovery protocol: JSON message
				var discoveryMsg DiscoveryMessage
				if err := json.Unmarshal([]byte(msg), &discoveryMsg); err != nil {
					log.Printf("[WARN] Invalid JSON discovery message from %s: %v", addr, err)
					return
				}

				if discoveryMsg.Command == "announce" && !isLocalIP(addr.IP.String()) {
					log.Printf("[INFO] Enhanced peer announcement from %s: %s v%s (%s)",
						addr.IP.String(), discoveryMsg.Platform, discoveryMsg.PeernixVersion,
						strings.Join(discoveryMsg.Features, ","))

					// Add enhanced peer info
					peersMux.Lock()
					found := false
					for i, peer := range peers {
						if peer.Addr == addr.IP.String() {
							// Update existing peer with enhanced info
							peers[i].TTL = time.Now().Add(config.PeerTTL)
							peers[i].Version = discoveryMsg.PeernixVersion
							peers[i].NixVersion = discoveryMsg.NixVersion
							peers[i].Platform = discoveryMsg.Platform
							peers[i].Features = discoveryMsg.Features
							peers[i].PublicKey = discoveryMsg.PublicKey
							found = true
							break
						}
					}
					if !found {
						peers = append(peers, Peer{
							Addr:       addr.IP.String(),
							TTL:        time.Now().Add(config.PeerTTL),
							Version:    discoveryMsg.PeernixVersion,
							NixVersion: discoveryMsg.NixVersion,
							Platform:   discoveryMsg.Platform,
							Features:   discoveryMsg.Features,
							PublicKey:  discoveryMsg.PublicKey,
						})
					}
					peersMux.Unlock()

					// Send back our announcement
					response := createDiscoveryMessage("announce")
					if responseBytes, err := json.Marshal(response); err == nil {
						conn.WriteToUDP(responseBytes, addr)
					}
				}
			} else {
				log.Printf("[DEBUG] Unknown UDP message from %s: %s", addr, msg)
			}
		}(string(buf[:n]), addr)
	}
}

func updatePeers() {
	// Run UDP discovery with enhanced protocol
	go updatePeersUDP()
	// Run mDNS discovery
	go updatePeersMDNS()
}

func updatePeersUDP() {
	addr, err := net.ResolveUDPAddr("udp", "255.255.255.255:"+config.UDPPort)
	if err != nil {
		log.Printf("[WARN] Failed to resolve broadcast address: %v", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("[WARN] Failed to dial UDP broadcast: %v", err)
		return
	}
	defer conn.Close()

	// Send enhanced discovery message
	discoveryMsg := createDiscoveryMessage("announce")
	msgBytes, err := json.Marshal(discoveryMsg)
	if err != nil {
		log.Printf("[WARN] Failed to marshal discovery message: %v", err)
		// Fallback to simple ping
		msgBytes = []byte("ping")
	}

	log.Printf("[DEBUG] Broadcasting enhanced discovery for UDP peer discovery")
	conn.Write(msgBytes)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) // Longer timeout for JSON
	buf := make([]byte, 2048) // Larger buffer for JSON

	newPeers := []Peer{}
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		response := string(buf[:n])
		if !isLocalIP(addr.IP.String()) {
			if response == "pong" {
				// Backward compatibility: simple pong response
				peer := Peer{
					Addr: addr.IP.String(),
					TTL: time.Now().Add(config.PeerTTL/2),
					Version: "1.x", // Assume older version
				}
				newPeers = append(newPeers, peer)
				log.Printf("[INFO] Discovered legacy peer via UDP: %s", addr.IP.String())
			} else if strings.HasPrefix(response, "{") {
				// Enhanced discovery: JSON response
				var discoveryResp DiscoveryMessage
				if err := json.Unmarshal([]byte(response), &discoveryResp); err == nil {
					peer := Peer{
						Addr:       addr.IP.String(),
							TTL:        time.Now().Add(config.PeerTTL),
							Version:    discoveryResp.PeernixVersion,
							NixVersion: discoveryResp.NixVersion,
							Platform:   discoveryResp.Platform,
							Features:   discoveryResp.Features,
							PublicKey:  discoveryResp.PublicKey,
						}
					newPeers = append(newPeers, peer)
					log.Printf("[INFO] Discovered enhanced peer via UDP: %s v%s (%s)",
						addr.IP.String(), discoveryResp.PeernixVersion,
						strings.Join(discoveryResp.Features, ","))
				}
			}
		} else {
			log.Printf("[DEBUG] Ignoring response from self (%s)", addr.IP.String())
		}
	}

	// Merge UDP discovered peers with existing ones
	peersMux.Lock()
	oldCount := len(peers)
	for _, newPeer := range newPeers {
		found := false
		for i, peer := range peers {
			if peer.Addr == newPeer.Addr {
				peers[i].TTL = newPeer.TTL
				found = true
				break
			}
		}
		if !found {
			peers = append(peers, newPeer)
		}
	}

	// Remove expired peers and cleanup their HTTP clients
	now := time.Now()
	activePeers := []Peer{}
	expiredPeers := []string{}
	for _, peer := range peers {
		if peer.TTL.After(now) {
			activePeers = append(activePeers, peer)
		} else {
			expiredPeers = append(expiredPeers, peer.Addr)
		}
	}
	peers = activePeers
	peersMux.Unlock()

	// Cleanup HTTP clients for expired peers
	if len(expiredPeers) > 0 {
		clientsMux.Lock()
		for _, peerAddr := range expiredPeers {
			if client, exists := peerClients[peerAddr]; exists {
				// Close idle connections
				if transport, ok := client.Transport.(*http.Transport); ok {
					transport.CloseIdleConnections()
				}
				delete(peerClients, peerAddr)
				log.Printf("[DEBUG] Cleaned up HTTP client for expired peer %s", peerAddr)
			}
		}
		clientsMux.Unlock()
	}

	if oldCount != len(peers) {
		log.Printf("[INFO] Active peer count: %d", len(peers))
	}
}

// startMDNSServer starts a single mDNS server instance for service advertising
func startMDNSServer() error {
	// Service info with our capabilities
	info := []string{
		fmt.Sprintf("version=%s", "2.0.0"),
		fmt.Sprintf("platform=%s", fmt.Sprintf("%s-%s", runtime.GOARCH, runtime.GOOS)),
		fmt.Sprintf("features=%s", strings.Join(getSupportedFeatures(), ",")),
	}
	if signingEnabled {
		publicKeyEncoded := base64.StdEncoding.EncodeToString(publicKey)
		info = append(info, fmt.Sprintf("pubkey=%s:%s", keyName, publicKeyEncoded))
	}

	service, err := mdns.NewMDNSService("peernix", "_peernix._tcp", "", "", mustParseInt(config.HTTPPort), nil, info)
	if err != nil {
		return fmt.Errorf("failed to create mDNS service: %v", err)
	}

	mdnsServer, err = mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return fmt.Errorf("failed to start mDNS server: %v", err)
	}

	log.Printf("[INFO] mDNS service advertising started")
	return nil
}

// updatePeersMDNS discovers peers using mDNS
func updatePeersMDNS() {
	// Create entries channel to receive discovered services
	entriesCh := make(chan *mdns.ServiceEntry, 10)

	// Start browsing for peernix services
	go func() {
		defer close(entriesCh)
		if err := mdns.Lookup("_peernix._tcp", entriesCh); err != nil {
			log.Printf("[WARN] mDNS lookup failed: %v", err)
		}
	}()

	// Note: mDNS advertising is now handled by global server started at startup

	// Process discovered entries with shorter timeout for reduced idle load
	timeout := time.After(3 * time.Second)
	newPeers := []Peer{}

	for {
		select {
		case entry := <-entriesCh:
			if entry == nil {
				continue
			}

			// Skip our own service
			if isLocalIP(entry.Addr.String()) {
				log.Printf("[DEBUG] Ignoring own mDNS service at %s", entry.Addr)
				continue
			}

			// Parse service info
			peer := Peer{
				Addr: entry.Addr.String(),
				TTL:  time.Now().Add(config.PeerTTL),
			}

			// Extract metadata from TXT records
			for _, txt := range entry.InfoFields {
				if strings.HasPrefix(txt, "version=") {
					peer.Version = strings.TrimPrefix(txt, "version=")
				} else if strings.HasPrefix(txt, "platform=") {
					peer.Platform = strings.TrimPrefix(txt, "platform=")
				} else if strings.HasPrefix(txt, "features=") {
					featuresStr := strings.TrimPrefix(txt, "features=")
					peer.Features = strings.Split(featuresStr, ",")
				} else if strings.HasPrefix(txt, "pubkey=") {
					peer.PublicKey = strings.TrimPrefix(txt, "pubkey=")
				}
			}

			newPeers = append(newPeers, peer)
			log.Printf("[INFO] Discovered peer via mDNS: %s v%s (%s)",
				entry.Addr, peer.Version, strings.Join(peer.Features, ","))

		case <-timeout:
			goto merge_peers
		}
	}

merge_peers:
	// Merge mDNS discovered peers with existing ones
	peersMux.Lock()
	oldCount := len(peers)
	for _, newPeer := range newPeers {
		found := false
		for i, peer := range peers {
			if peer.Addr == newPeer.Addr {
				peers[i].TTL = newPeer.TTL
				peers[i].Version = newPeer.Version
				peers[i].Platform = newPeer.Platform
				peers[i].Features = newPeer.Features
				peers[i].PublicKey = newPeer.PublicKey
				found = true
				break
			}
		}
		if !found {
			peers = append(peers, newPeer)
		}
	}
	peersMux.Unlock()

	if oldCount != len(peers) {
		log.Printf("[INFO] mDNS discovery updated peer count: %d", len(peers))
	}
}

// Health checks removed - peers are considered healthy if they respond to discovery pings
// and are automatically removed based on TTL expiry

// findStorePath finds the full store path for a given hash with caching
func findStorePath(hash string) (string, bool) {
	cacheKey := "path:" + hash

	// Check cache first for resource conservation
	storeCacheMux.RLock()
	if cached, exists := storeCache[cacheKey]; exists {
		if time.Since(cached.timestamp) < 5*time.Minute {
			storeCacheMux.RUnlock()
			if cached.err != nil {
				return "", false
			}
			return cached.result.(string), true
		}
	}
	storeCacheMux.RUnlock()

	// Not in cache or expired, run command
	cmd := exec.Command("nix", "store", "path-from-hash-part", hash)
	out, err := cmd.Output()

	// Cache the result
	storeCacheMux.Lock()
	if err != nil {
		storeCache[cacheKey] = storeResult{"", time.Now(), err}
	} else {
		path := strings.TrimSpace(string(out))
		storeCache[cacheKey] = storeResult{path, time.Now(), nil}
	}
	storeCacheMux.Unlock()

	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func hasPath(hash string) bool {
	fullPath, found := findStorePath(hash)
	if !found {
		return false
	}

	// Quick file existence check first to avoid expensive nix-store command
	if _, err := os.Stat(fullPath); err != nil {
		return false
	}

	// Also check for lock file
	if _, err := os.Stat(fullPath + ".lock"); err == nil {
		// lock file exists
		return false
	}

	// Only run nix-store check for UDP responses (when we need to be certain)
	// For HTTP requests, file existence is sufficient since we're serving directly
	return true
}

func generateNarInfo(hash string, w io.Writer, compress bool) error {
	fullPath, found := findStorePath(hash)
	if !found {
		return fmt.Errorf("store path not found for hash: %s", hash)
	}

	// Get all required info from nix-store
	cmd := exec.Command("nix-store", "--query", "--references", fullPath)
	refs, err := cmd.Output()
	if err != nil {
		return err
	}

	cmd = exec.Command("nix-store", "--query", "--deriver", fullPath)
	deriver, err := cmd.Output()
	if err != nil {
		return err
	}

	cmd = exec.Command("nix-store", "--query", "--size", fullPath)
	size, err := cmd.Output()
	if err != nil {
		return err
	}

	// Get NAR hash from nix-store
	cmd = exec.Command("nix-store", "--query", "--hash", fullPath)
	narHashOutput, err := cmd.Output()
	if err != nil {
		return err
	}
	narHash := strings.TrimSpace(string(narHashOutput))

	// For uncompressed NAR, FileHash = NarHash and FileSize = NarSize
	fileHash := narHash
	fileSize := strings.TrimSpace(string(size))

	// Complete narinfo format with all required fields
	_, err = w.Write([]byte("StorePath: " + fullPath + "\n"))
	if err != nil {
		return err
	}
	url := hash + ".nar"
	compression := "none"
	if compress {
		url += ".gz"
		compression = "gzip"
	}

	_, err = w.Write([]byte("URL: " + url + "\n"))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("Compression: " + compression + "\n"))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("FileHash: " + fileHash + "\n"))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("FileSize: " + fileSize + "\n"))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("NarHash: " + narHash + "\n"))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("NarSize: " + strings.TrimSpace(string(size)) + "\n"))
	if err != nil {
		return err
	}
	// Process references to remove /nix/store/ prefix
	refPaths := strings.Fields(strings.TrimSpace(string(refs)))
	// Exclude references that point to the store path itself
	filteredRefPaths := make([]string, 0, len(refPaths))
	for _, refPath := range refPaths {
		if refPath != fullPath {
			filteredRefPaths = append(filteredRefPaths, refPath)
		}
	}
	refPaths = filteredRefPaths
	// Just in case the output of `nix-store --query --references` is not sorted.
	sort.Strings(refPaths)
	refNames := make([]string, len(refPaths))
	for i, refPath := range refPaths {
		refNames[i] = strings.TrimPrefix(refPath, "/nix/store/")
	}
	_, err = w.Write([]byte("References: " + strings.Join(refNames, " ") + "\n"))
	if err != nil {
		return err
	}
	// Process deriver to remove /nix/store/ prefix
	deriverPath := strings.TrimSpace(string(deriver))
	deriverName := strings.TrimPrefix(deriverPath, "/nix/store/")
	if deriverName == "" || deriverName == "unknown-deriver" {
		deriverName = "unknown-deriver"
	}
	_, err = w.Write([]byte("Deriver: " + deriverName + "\n"))
	if err != nil {
		return err
	}

	// Add signature if signing is enabled
	if signingEnabled {
		// See ValidPathInfo::fingerprint in nix source file src/libstore/path-info.cc

		// References must be comma-separated
		references := strings.Join(refPaths, ",")

		// Build fingerprint-style content to sign:
		// "1;{storePath};{narHash};{narSize};{refs}"
		// NOTE: narHash should be formatted the same way Nix does.
		content := fmt.Sprintf("1;%s;%s;%s;%s", fullPath, narHash, strings.TrimSpace(string(size)), references)

		signature := signNarInfo(content)
		_, err = w.Write([]byte("Sig: " + signature + "\n"))
		if err != nil {
			return err
		}
	}

	return nil
}

// queryPeersParallel queries all known peers in parallel for a hash
func queryPeersParallel(hash string) *net.UDPAddr {
	peersMux.RLock()
	if len(peers) == 0 {
		peersMux.RUnlock()
		return nil
	}

	// Create a copy of peers to avoid holding lock during network operations
	currentPeers := make([]Peer, len(peers))
	copy(currentPeers, peers)
	peersMux.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

type result struct {
		addr *net.UDPAddr
		err  error
	}

	results := make(chan result, len(currentPeers))

	// Query each peer concurrently with retry logic
	for _, peer := range currentPeers {
		go func(p Peer) {
			defer func() {
				if r := recover(); r != nil {
					results <- result{nil, fmt.Errorf("panic in peer query: %v", r)}
				}
			}()

			// Retry logic with exponential backoff: immediate, 100ms, 500ms, 2s
			retryDelays := []time.Duration{0, 100*time.Millisecond, 500*time.Millisecond, 2*time.Second}

			for attempt := 0; attempt < len(retryDelays); attempt++ {
				// Check context before each retry
				select {
				case <-ctx.Done():
					results <- result{nil, ctx.Err()}
					return
				default:
				}

				// Wait for retry delay (except first attempt)
				if attempt > 0 {
					select {
					case <-ctx.Done():
						results <- result{nil, ctx.Err()}
						return
					case <-time.After(retryDelays[attempt]):
						// Continue with retry
					}
				}

				addr, err := net.ResolveUDPAddr("udp", p.Addr+":"+config.UDPPort)
				if err != nil {
					if attempt == len(retryDelays)-1 {
						// Update failure count on final failure
						peersMux.Lock()
						for i := range peers {
							if peers[i].Addr == p.Addr {
								peers[i].FailureCount++
								break
							}
						}
						peersMux.Unlock()
						results <- result{nil, err}
						return
					}
					continue
				}

				conn, err := net.DialUDP("udp", nil, addr)
				if err != nil {
					if attempt == len(retryDelays)-1 {
						// Update failure count on final failure
						peersMux.Lock()
						for i := range peers {
							if peers[i].Addr == p.Addr {
								peers[i].FailureCount++
								break
							}
						}
						peersMux.Unlock()
						results <- result{nil, err}
						return
					}
					continue
				}

				conn.SetDeadline(time.Now().Add(1 * time.Second))
				metrics.PeerQueriesAttempted.Add(1)
				_, err = conn.Write([]byte("has_path?" + hash))
				if err != nil {
					conn.Close()
					if attempt == len(retryDelays)-1 {
						// Update failure count on final failure
						peersMux.Lock()
						for i := range peers {
							if peers[i].Addr == p.Addr {
								peers[i].FailureCount++
								break
							}
						}
						peersMux.Unlock()
						results <- result{nil, err}
						return
					}
					continue
				}

				buf := make([]byte, 1024)
				n, _, err := conn.ReadFromUDP(buf)
				conn.Close()

				if err != nil {
					if attempt == len(retryDelays)-1 {
						// Update failure count on final failure
						peersMux.Lock()
						for i := range peers {
							if peers[i].Addr == p.Addr {
								peers[i].FailureCount++
								break
							}
						}
						peersMux.Unlock()
						results <- result{nil, err}
						return
					}
					continue
				}

				if string(buf[:n]) == "yes" {
					metrics.PeerQueriesSuccessful.Add(1)
					// Update peer health on successful response
					peersMux.Lock()
					for i := range peers {
						if peers[i].Addr == p.Addr {
							peers[i].LastSeen = time.Now()
							peers[i].FailureCount = 0
							break
						}
					}
					peersMux.Unlock()

					results <- result{addr, nil}
					return
				} else if attempt == len(retryDelays)-1 {
					// Path not found, but peer is healthy
					peersMux.Lock()
					for i := range peers {
						if peers[i].Addr == p.Addr {
							peers[i].LastSeen = time.Now()
							peers[i].FailureCount = 0
							break
						}
					}
					peersMux.Unlock()

					results <- result{nil, fmt.Errorf("peer doesn't have path")}
					return
				}
				// Path not found, but try again in case of transient issues
			}
		}(peer)
	}

	// Wait for first success or all failures
	for i := 0; i < len(currentPeers); i++ {
		select {
		case res := <-results:
			if res.err == nil {
				log.Printf("[INFO] Found %s at peer %s via parallel query", hash, res.addr.IP.String())
				return res.addr
			}
		case <-ctx.Done():
			log.Printf("[DEBUG] Peer query timeout for hash %s", hash)
			return nil
		}
	}

	return nil
}

func generateNar(hash string, w io.Writer, compress bool) error {
	fullPath, found := findStorePath(hash)
	if !found {
		return fmt.Errorf("store path not found for hash: %s", hash)
	}

	// Use streaming approach with proper pipe management for resource conservation
	cmd := exec.Command("nix-store", "--dump", fullPath)

	// Create a pipe for streaming output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start nix-store command: %v", err)
	}

	// Handle compression and streaming in a goroutine to avoid blocking
	var copyErr error
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer stdout.Close()

		if compress {
			// Stream through gzip compressor
			gw := gzip.NewWriter(w)
			defer gw.Close()

			// Use io.Copy for efficient streaming with 32KB buffer
			_, copyErr = io.Copy(gw, stdout)
		} else {
			// Stream directly without compression
			_, copyErr = io.Copy(w, stdout)
		}
	}()

	// Wait for both streaming and command completion
	<-done
	cmdErr := cmd.Wait()

	// Return the first error encountered
	if copyErr != nil {
		return fmt.Errorf("failed to stream NAR: %v", copyErr)
	}
	if cmdErr != nil {
		return fmt.Errorf("nix-store command failed: %v", cmdErr)
	}

	return nil
}

// countingWriter wraps ResponseWriter to count bytes written
type countingWriter struct {
	http.ResponseWriter
	bytes int64
}

func (cw *countingWriter) Write(b []byte) (int, error) {
	n, err := cw.ResponseWriter.Write(b)
	cw.bytes += int64(n)
	return n, err
}

// findPeerForHash handles request deduplication and querying peers.
// This new function abstracts the logic that was previously inside handleNixCache.
func findPeerForHash(hash string) *net.UDPAddr {
	requestsMux.Lock()
	if pendingCh, exists := pendingRequests[hash]; exists {
		// Another request is already in progress, wait for its result
		requestsMux.Unlock()
		log.Printf("[DEBUG] Joining existing request for hash %s", hash)

		select {
		case peerAddr := <-pendingCh:
			if peerAddr == nil {
				log.Printf("[INFO] Deduplicated request failed for hash %s", hash)
				return nil
			}
			log.Printf("[INFO] Using result from deduplicated request for hash %s", hash)
			return peerAddr
		case <-time.After(5 * time.Second):
			log.Printf("[WARN] Timeout waiting for deduplicated request for hash %s", hash)
			return nil
		}
	}

	// Create new pending request channel
	pendingCh := make(chan *net.UDPAddr, 10) // Buffered to handle multiple waiters

	pendingRequests[hash] = pendingCh
	requestsMux.Unlock()

	// Query peers in parallel
	log.Printf("[INFO] Querying peers for hash %s", hash)
	peerAddr := queryPeersParallel(hash)

	// Notify all waiting requests of the result
	requestsMux.Lock()
	delete(pendingRequests, hash)
	requestsMux.Unlock()

	// Send result to all waiters
	go func() {
		defer close(pendingCh)
		// Non-blocking send to all potential waiters
		for i := 0; i < cap(pendingCh); i++ {
			select {
			case pendingCh <- peerAddr:
			default:
				return
			}
		}
	}()

	return peerAddr
}

func handleNixCache(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	path := strings.TrimPrefix(r.URL.Path, "/nix-cache/")
	log.Printf("[INFO] HTTP %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// Wrap response writer to count bytes
	cw := &countingWriter{ResponseWriter: w}

	var hash string
	isNarInfo := strings.HasSuffix(path, ".narinfo")
	isNar := strings.HasSuffix(path, ".nar")

	if isNarInfo {
		hash = strings.TrimSuffix(path, ".narinfo")
	} else if isNar {
		hash = strings.TrimSuffix(path, ".nar")
	} else {
		log.Printf("[DEBUG] Invalid path format: %s", path)
		http.Error(w, "Not found", 404)
		return
	}

	// Track request completion
	defer func() {
		duration := time.Since(startTime)
		metrics.RequestMux.Lock()
		metrics.RequestTimes = append(metrics.RequestTimes, duration)
		metrics.RequestMux.Unlock()
	}()

	// Check if client supports compression and compression is enabled
	compress := config.CompressionEnabled && supportsCompression(r.Header.Get("Accept-Encoding")) && isNar

	// Check local store first
	if hasPath(hash) {
		metrics.Hits.Add(1)
		log.Printf("[INFO] Serving %s from local store", path)
		if isNarInfo {
			cw.Header().Set("Content-Type", "text/x-nix-narinfo")
			if err := generateNarInfo(hash, cw, compress); err != nil {
				log.Printf("[ERROR] Failed to generate narinfo for %s: %v", hash, err)
				http.Error(cw, err.Error(), 500)
			} else {
				metrics.FilesSent.Add(1)
				metrics.BytesSent.Add(uint64(cw.bytes))
				
				// Cache "localhost" marker so .nar requests know this was served locally
				// This allows fallback to peers if path is deleted later (e.g., by GC)
				narInfoPeerCacheMux.Lock()
				narInfoPeerCache[hash] = "localhost"
				narInfoPeerCacheMux.Unlock()
			}
		} else {
			cw.Header().Set("Content-Type", "application/x-nix-nar")
			if compress {
				cw.Header().Set("Content-Encoding", "gzip")
				log.Printf("[DEBUG] Compressing NAR for %s", hash)
			}
			if err := generateNar(hash, cw, compress); err != nil {
				log.Printf("[ERROR] Failed to generate nar for %s: %v", hash, err)
				http.Error(cw, err.Error(), 500)
			} else {
				metrics.FilesSent.Add(1)
				metrics.BytesSent.Add(uint64(cw.bytes))
				if compress {
					log.Printf("[INFO] Served compressed NAR for %s (%d bytes)", hash, cw.bytes)
				}
			}
		}
		return
	}

	// If not in local store, find a peer
	var peerIP string
	var exists bool

	// For .nar requests, check the cache for a sticky peer first
	if isNar {
		narInfoPeerCacheMux.RLock()
		peerIP, exists = narInfoPeerCache[hash]
		narInfoPeerCacheMux.RUnlock()
		if exists {
			// If cached peer is "localhost" but we're here, path was deleted (likely by GC)
			// Fall back to querying peers
			if peerIP == "localhost" {
				log.Printf("[INFO] Path was served locally but no longer in store, querying peers for hash %s", hash)
				peerAddr := findPeerForHash(hash)
				if peerAddr == nil {
					metrics.Misses.Add(1)
					log.Printf("[INFO] No peers found for %s after local deletion", path)
					http.Error(cw, "Not found in local store or peers", 404)
					return
				}
				peerIP = peerAddr.IP.String()
				// Update cache with actual peer
				narInfoPeerCacheMux.Lock()
				narInfoPeerCache[hash] = peerIP
				narInfoPeerCacheMux.Unlock()
				log.Printf("[INFO] Found peer %s for .nar request of hash %s (fallback after local deletion)", peerIP, hash)
			} else {
				log.Printf("[INFO] Found cached peer %s for .nar request of hash %s", peerIP, hash)
			}
		} else {
			log.Printf("[WARN] No cached peer for .nar hash %s. Refusing to query network to avoid hash mismatch.", hash)
			http.Error(cw, "Not found, peer for .nar not cached", 404)
			return
		}
	}

	// If no peer is cached (which is now only possible for .narinfo requests), query the network
	if isNarInfo {
		// Use request deduplication to query peers
		peerAddr := findPeerForHash(hash)
		if peerAddr == nil {
			metrics.Misses.Add(1)
			log.Printf("[INFO] No peers found for %s", path)
			http.Error(cw, "Not found in local store or peers", 404)
			return
		}
		peerIP = peerAddr.IP.String()

		// cache the peer that had it
		log.Printf("[INFO] Caching peer %s for .narinfo of hash %s", peerIP, hash)
		narInfoPeerCacheMux.Lock()
		narInfoPeerCache[hash] = peerIP
		narInfoPeerCacheMux.Unlock()
	}

	// Fetch from the determined peer
	peerURL := "http://" + peerIP + ":" + config.HTTPPort + r.URL.Path
	log.Printf("[INFO] Fetching %s from peer %s (%s)", path, peerIP, peerURL)

	client := getPeerClient(peerIP)
	resp, err := client.Get(peerURL)
	if err != nil {
		metrics.Misses.Add(1)
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			log.Printf("[DEBUG] Peer %s timeout for %s", peerIP, path)
		} else {
			log.Printf("[WARN] Failed to fetch from peer %s: %v", peerIP, err)
		}
		http.Error(cw, "Failed to fetch from peer", 502)
		return
	}
	defer resp.Body.Close()

	// Copy headers from peer response
	for key, values := range resp.Header {
		for _, value := range values {
			cw.Header().Add(key, value)
		}
	}
	cw.WriteHeader(resp.StatusCode)
	n, err := io.Copy(cw, resp.Body)
	if err != nil {
		log.Printf("[ERROR] Error copying from peer: %v", err)
	} else {
		metrics.Hits.Add(1)
		metrics.FilesReceived.Add(1)
		metrics.BytesReceived.Add(uint64(n))
		log.Printf("[INFO] Successfully served %s from peer %s (%d bytes)", path, peerIP, n)
	}
}
