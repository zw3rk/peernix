package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run test-udp-direct.go <peer_ip> <hash>")
		os.Exit(1)
	}

	peerIP := os.Args[1]
	hash := os.Args[2]

	// Connect directly to the peer
	addr, err := net.ResolveUDPAddr("udp", peerIP+":9999")
	if err != nil {
		fmt.Printf("Failed to resolve address: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Printf("Failed to dial UDP: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send the has_path query
	message := "has_path?" + hash
	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Printf("Failed to send message: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Sent: %s to %s\n", message, peerIP)

	// Wait for response
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	
	fmt.Println("Waiting for response...")
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("No response (timeout)")
		} else {
			fmt.Printf("Read error: %v\n", err)
		}
		os.Exit(1)
	}
	
	response := string(buf[:n])
	fmt.Printf("Response from %s: '%s'\n", addr, response)
	
	// Check if response is what we expect
	if response == "not_found" {
		fmt.Println("✅ SUCCESS: Received 'not_found' response as expected!")
		os.Exit(0)
	} else if response == "yes" {
		fmt.Println("⚠️  Received 'yes' - the hash exists on this peer")
		os.Exit(0)
	} else {
		fmt.Printf("⚠️  Unexpected response: '%s'\n", response)
		os.Exit(1)
	}
}
