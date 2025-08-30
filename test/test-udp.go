package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test-udp.go <command>")
		fmt.Println("Commands:")
		fmt.Println("  ping                - Send broadcast ping")
		fmt.Println("  has_path <hash>     - Query for a path")
		os.Exit(1)
	}

	// Set up UDP connection for broadcast
	addr, err := net.ResolveUDPAddr("udp", "255.255.255.255:9999")
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

	// Send the message
	var message string
	switch os.Args[1] {
	case "ping":
		message = "ping"
	case "has_path":
		if len(os.Args) < 3 {
			fmt.Println("Usage: go run test-udp.go has_path <hash>")
			os.Exit(1)
		}
		message = "has_path?" + os.Args[2]
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}

	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Printf("Failed to send message: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Sent: %s\n", message)

	// Wait for responses
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	
	fmt.Println("Waiting for responses...")
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Println("No more responses (timeout)")
				break
			}
			fmt.Printf("Read error: %v\n", err)
			break
		}
		fmt.Printf("Response from %s: %s\n", addr, string(buf[:n]))
	}
}