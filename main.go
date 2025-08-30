package main

import (
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	udpPort  = "9999"
	httpPort = "9999"
)

type Peer struct {
	Addr string
	TTL  time.Time
}

// Metrics holds all the metrics for Prometheus
type Metrics struct {
	Hits          atomic.Uint64
	Misses        atomic.Uint64
	FilesSent     atomic.Uint64
	BytesSent     atomic.Uint64
	FilesReceived atomic.Uint64
	BytesReceived atomic.Uint64
	RequestTimes  []time.Duration
	RequestMux    sync.RWMutex
}

var (
	peers    []Peer
	peersMux sync.RWMutex
	logger   *syslog.Writer
	localIPs []string
	metrics  = &Metrics{}
)

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

// checkNixConfig checks if peernix is configured as a substituter
func checkNixConfig() {
	substituterURL := fmt.Sprintf("http://localhost:%s/nix-cache/", httpPort)
	
	cmd := exec.Command("nix", "config", "show", "substituters")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("[WARN] Failed to check nix config: %v", err)
		return
	}
	
	if !strings.Contains(string(output), substituterURL) {
		log.Printf("[WARN] ========================================")
		log.Printf("[WARN] peernix is not configured as a substituter!")
		log.Printf("[WARN] To enable peernix, add the following to your nix configuration:")
		log.Printf("[WARN] ")
		
		// Check which config file to use
		configFile := "/etc/nix/nix.conf"
		if _, err := os.Stat("/etc/nix/nix.custom.conf"); err == nil {
			configFile = "/etc/nix/nix.custom.conf"
		}
		
		log.Printf("[WARN] In %s add:", configFile)
		log.Printf("[WARN]   extra-substituters = %s", substituterURL)
		log.Printf("[WARN]   extra-trusted-substituters = %s", substituterURL)
		log.Printf("[WARN] ")
		log.Printf("[WARN] Then restart the nix daemon:")
		log.Printf("[WARN]   sudo launchctl kickstart -k system/org.nixos.nix-daemon")
		log.Printf("[WARN] ========================================")
	} else {
		log.Printf("[INFO] peernix is configured as a substituter ✓")
	}
}

func main() {
	var err error
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

	logInfo("Starting peernix server on ports UDP:" + udpPort + " HTTP:" + httpPort)
	
	// Check nix configuration
	checkNixConfig()

	go udpServer()
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/nix-cache/", handleNixCache)
	
	log.Printf("[INFO] " + "HTTP server starting on :" + httpPort)
	if err := http.ListenAndServe(":"+httpPort, nil); err != nil {
		log.Printf("[ERROR] " + fmt.Sprintf("HTTP server failed: %v", err))
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

func handleHealth(w http.ResponseWriter, r *http.Request) {
	// Calculate average latency
	metrics.RequestMux.RLock()
	var avgLatency time.Duration
	if len(metrics.RequestTimes) > 0 {
		var total time.Duration
		for _, t := range metrics.RequestTimes {
			total += t
		}
		avgLatency = total / time.Duration(len(metrics.RequestTimes))
	}
	// Keep only last 1000 request times
	if len(metrics.RequestTimes) > 1000 {
		metrics.RequestTimes = metrics.RequestTimes[len(metrics.RequestTimes)-1000:]
	}
	metrics.RequestMux.RUnlock()
	
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
	
	fmt.Fprintf(w, "# HELP peernix_peers_current Current number of known peers\n")
	fmt.Fprintf(w, "# TYPE peernix_peers_current gauge\n")
	fmt.Fprintf(w, "peernix_peers_current %d\n", peerCount)
	
	fmt.Fprintf(w, "# HELP peernix_request_latency_ms Average request latency in milliseconds\n")
	fmt.Fprintf(w, "# TYPE peernix_request_latency_ms gauge\n")
	fmt.Fprintf(w, "peernix_request_latency_ms %d\n", avgLatency.Milliseconds())
}

func udpServer() {
	port, _ := strconv.Atoi(udpPort)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		log.Printf("[ERROR] " + fmt.Sprintf("Failed to start UDP server: %v", err))
		return
	}
	defer conn.Close()
	conn.SetWriteBuffer(1024)
	log.Printf("[INFO] " + "UDP server started on :" + udpPort)

	go func() {
		for range time.Tick(5 * time.Minute) {
			log.Printf("[DEBUG] " + "Running periodic peer discovery")
			updatePeers()
		}
	}()

	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[WARN] " + fmt.Sprintf("UDP read error: %v", err))
			continue
		}
		msg := string(buf[:n])
		
		if strings.HasPrefix(msg, "has_path?") {
			hash := strings.TrimPrefix(msg, "has_path?")
			log.Printf("[DEBUG] " + fmt.Sprintf("Received path query from %s for hash: %s", addr, hash))
			if hasPath(hash) {
				log.Printf("[INFO] " + fmt.Sprintf("Responding YES to %s for hash: %s", addr, hash))
				conn.WriteToUDP([]byte("yes"), addr)
			} else {
				log.Printf("[DEBUG] " + fmt.Sprintf("Path not found locally: %s", hash))
			}
		} else if msg == "ping" {
			// Don't respond to our own pings
			if isLocalIP(addr.IP.String()) {
				log.Printf("[DEBUG] " + fmt.Sprintf("Ignoring ping from self (%s)", addr))
			} else {
				log.Printf("[DEBUG] " + fmt.Sprintf("Received ping from %s, sending pong", addr))
				conn.WriteToUDP([]byte("pong"), addr)
			}
		} else {
			log.Printf("[DEBUG] " + fmt.Sprintf("Unknown UDP message from %s: %s", addr, msg))
		}
	}
}

func updatePeers() {
	addr, err := net.ResolveUDPAddr("udp", "255.255.255.255:"+udpPort)
	if err != nil {
		log.Printf("[WARN] " + fmt.Sprintf("Failed to resolve broadcast address: %v", err))
		return
	}
	
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("[WARN] " + fmt.Sprintf("Failed to dial UDP broadcast: %v", err))
		return
	}
	defer conn.Close()

	log.Printf("[DEBUG] " + "Broadcasting ping for peer discovery")
	conn.Write([]byte("ping"))
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)

	newPeers := []Peer{}
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if string(buf[:n]) == "pong" {
			// Don't add ourselves as a peer
			if !isLocalIP(addr.IP.String()) {
				peer := Peer{Addr: addr.IP.String(), TTL: time.Now().Add(5 * time.Minute)}
				newPeers = append(newPeers, peer)
				log.Printf("[INFO] " + fmt.Sprintf("Discovered peer: %s", addr.IP.String()))
			} else {
				log.Printf("[DEBUG] " + fmt.Sprintf("Ignoring pong from self (%s)", addr.IP.String()))
			}
		}
	}
	
	peersMux.Lock()
	oldCount := len(peers)
	peers = newPeers
	peersMux.Unlock()
	
	if oldCount != len(newPeers) {
		log.Printf("[INFO] " + fmt.Sprintf("Peer count changed: %d -> %d", oldCount, len(newPeers)))
	}
}

// findStorePath finds the full store path for a given hash
func findStorePath(hash string) (string, bool) {
	cmd := exec.Command("nix", "store", "path-from-hash-part", hash)
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func hasPath(hash string) bool {
	fullPath, found := findStorePath(hash)
	if !found {
		log.Printf("[DEBUG] " + fmt.Sprintf("No store path found for hash: %s", hash))
		return false
	}
	
	cmd := exec.Command("nix-store", "--check-validity", fullPath)
	err := cmd.Run()
	if err == nil {
		log.Printf("[DEBUG] " + fmt.Sprintf("Path exists locally: %s", fullPath))
		return true
	}
	log.Printf("[DEBUG] " + fmt.Sprintf("Path not valid: %s", fullPath))
	return false
}

func generateNarInfo(hash string, w io.Writer) error {
	fullPath, found := findStorePath(hash)
	if !found {
		return fmt.Errorf("store path not found for hash: %s", hash)
	}
	
	cmd := exec.Command("nix-store", "--query", "--requisites", fullPath)
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

	_, err = w.Write([]byte("StorePath: " + fullPath + "\n"))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("References: " + strings.ReplaceAll(string(refs), "\n", " ") + "\n"))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("Deriver: " + string(deriver) + "\n"))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("NarSize: " + string(size) + "\n"))
	return err
}

func generateNar(hash string, w io.Writer) error {
	fullPath, found := findStorePath(hash)
	if !found {
		return fmt.Errorf("store path not found for hash: %s", hash)
	}
	cmd := exec.Command("nix-store", "--dump", fullPath)
	cmd.Stdout = w
	return cmd.Run()
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

func handleNixCache(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	path := strings.TrimPrefix(r.URL.Path, "/nix-cache/")
	log.Printf("[INFO] " + fmt.Sprintf("HTTP %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr))
	
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
		log.Printf("[DEBUG] " + fmt.Sprintf("Invalid path format: %s", path))
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

	// Check local store first
	if hasPath(hash) {
		metrics.Hits.Add(1)
		log.Printf("[INFO] " + fmt.Sprintf("Serving %s from local store", path))
		if isNarInfo {
			cw.Header().Set("Content-Type", "text/x-nix-narinfo")
			err := generateNarInfo(hash, cw)
			if err != nil {
				log.Printf("[ERROR] " + fmt.Sprintf("Failed to generate narinfo for %s: %v", hash, err))
				http.Error(cw, err.Error(), 500)
			} else {
				metrics.FilesSent.Add(1)
				metrics.BytesSent.Add(uint64(cw.bytes))
			}
		} else {
			cw.Header().Set("Content-Type", "application/x-nix-nar")
			err := generateNar(hash, cw)
			if err != nil {
				log.Printf("[ERROR] " + fmt.Sprintf("Failed to generate nar for %s: %v", hash, err))
				http.Error(cw, err.Error(), 500)
			} else {
				metrics.FilesSent.Add(1)
				metrics.BytesSent.Add(uint64(cw.bytes))
			}
		}
		return
	}

	// Query peers
	log.Printf("[INFO] " + fmt.Sprintf("Querying peers for %s", path))
	addr, err := net.ResolveUDPAddr("udp", "255.255.255.255:"+udpPort)
	if err != nil {
		log.Printf("[ERROR] " + fmt.Sprintf("Failed to resolve UDP address: %v", err))
		http.Error(w, "Internal error", 500)
		return
	}
	
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("[ERROR] " + fmt.Sprintf("Failed to dial UDP: %v", err))
		http.Error(w, "Internal error", 500)
		return
	}
	defer conn.Close()

	conn.Write([]byte("has_path?" + hash))
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)

	for {
		n, peerAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			metrics.Misses.Add(1)
			log.Printf("[INFO] " + fmt.Sprintf("No peers responded for %s", path))
			http.Error(cw, "Not found in local store or peers", 404)
			return
		}
		if string(buf[:n]) == "yes" {
			peerURL := "http://" + peerAddr.IP.String() + ":" + httpPort + r.URL.Path
			log.Printf("[INFO] " + fmt.Sprintf("Found %s at peer %s, fetching from %s", path, peerAddr.IP, peerURL))
			
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Get(peerURL)
			if err != nil {
				log.Printf("[WARN] " + fmt.Sprintf("Failed to fetch from peer %s: %v", peerAddr.IP, err))
				continue
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
				log.Printf("[ERROR] " + fmt.Sprintf("Error copying from peer: %v", err))
				http.Error(cw, err.Error(), 500)
			} else {
				metrics.Hits.Add(1)
				metrics.FilesReceived.Add(1)
				metrics.BytesReceived.Add(uint64(n))
				log.Printf("[INFO] " + fmt.Sprintf("Successfully served %s from peer %s (%d bytes)", path, peerAddr.IP, n))
			}
			return
		}
	}
}
