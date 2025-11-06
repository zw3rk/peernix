package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// This test simulates peers responding with "not_found" to verify fail-fast behavior

const testHash = "test-hash-for-fail-fast-verification"

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test-fail-fast.go <num_peers>")
		fmt.Println("This will start <num_peers> mock peers that respond with 'not_found'")
		os.Exit(1)
	}

	var numPeers int
	fmt.Sscanf(os.Args[1], "%d", &numPeers)

	if numPeers <= 0 {
		fmt.Println("Number of peers must be > 0")
		os.Exit(1)
	}

	fmt.Printf("Starting %d mock peers that will respond with 'not_found'\n", numPeers)

	var wg sync.WaitGroup
	for i := 0; i < numPeers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			startMockPeer(id)
		}(i)
	}

	// Wait a bit for peers to start
	time.Sleep(1 * time.Second)
	fmt.Println("All mock peers started. Press Ctrl+C to exit.")
	
	wg.Wait()
}

func startMockPeer(id int) {
	// Listen on a random high port for UDP
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		fmt.Printf("Peer %d: Failed to start: %v\n", id, err)
		return
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	fmt.Printf("Peer %d: Listening on port %d\n", id, localAddr.Port)

	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("Peer %d: Read error: %v\n", id, err)
			continue
		}

		msg := string(buf[:n])
		fmt.Printf("Peer %d: Received '%s' from %s\n", id, msg, addr)

		// Respond with "not_found" for has_path queries with our test hash
		if msg == "has_path?"+testHash {
			fmt.Printf("Peer %d: Responding with 'not_found'\n", id)
			conn.WriteToUDP([]byte("not_found"), addr)
		} else if msg == "ping" {
			fmt.Printf("Peer %d: Responding with 'pong'\n", id)
			conn.WriteToUDP([]byte("pong"), addr)
		}
	}
}
