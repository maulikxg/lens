package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

func main() {
	// Open output file
	outputFile, err := os.Create("winrm_test_results.log")
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer outputFile.Close()

	// WinRM configuration
	ip := "172.16.8.128"
	port := 5985
	username := "Administrator"
	password := "Mind@123"

	// Configure multi-output
	multiWriter := io.MultiWriter(os.Stdout, outputFile)
	log.SetOutput(multiWriter)

	// Create WinRM endpoint
	endpoint := winrm.NewEndpoint(
		ip,
		port,
		false,
		true,
		nil, nil, nil,
		60*time.Second,
	)

	log.Println("\n=== WINRM CONNECTION TEST ===")
	log.Printf("Connecting to %s:%d as %s\n", ip, port, username)

	// Create WinRM client
	params := winrm.DefaultParameters
	params.Timeout = "PT60S"
	client, err := winrm.NewClientWithParameters(endpoint, username, password, params)
	if err != nil {
		log.Fatalf("Failed to create WinRM client: %v", err)
	}

	// Test connection
	connectedUser, err := runCommand(client, "whoami", "Connection test")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("\n✓ Successfully connected as: %s\n", connectedUser)

	// System information commands
	commands := []struct {
		title   string
		command string
	}{
		{"HOSTNAME", "hostname"},
		{"IP CONFIGURATION", "ipconfig /all"},
		{"OS INFORMATION", "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\""},
		{"WINDOWS VERSION", "ver"},
		{"LOGGED-IN USER", "echo %USERNAME%"},
		{"SYSTEM UPTIME", "systeminfo | find \"System Boot Time\""},
		{"CPU INFORMATION", "wmic cpu get name,numberofcores,numberoflogicalprocessors"},
		{"MEMORY INFORMATION", "wmic memorychip get capacity,partnumber,speed"},
		{"DISK INFORMATION", "wmic diskdrive get model,size,mediatype"},
		{"BIOS INFORMATION", "wmic bios get serialnumber,version,manufacturer"},
		{"SYSTEM MODEL", "wmic csproduct get name,identifyingnumber"},
		{"TIME ZONE", "systeminfo | find \"Time Zone\""},
		{"LAST BOOT TIME", "wmic os get lastbootuptime"},
		{"DOMAIN INFORMATION", "systeminfo | find \"Domain\""},
		{"NETWORK CONNECTIONS", "netstat -ano"},
	}

	// Run all commands
	log.Println("\n=== SYSTEM INFORMATION ===")
	for _, cmd := range commands {
		result, err := runCommand(client, cmd.command, cmd.title)
		if err != nil {
			log.Printf("⚠ %s failed: %v\n", cmd.title, err)
			continue
		}
		printSection(cmd.title, result)
	}

	// Summary
	log.Println("\n=== TEST SUMMARY ===")
	log.Printf("Target:       %s:%d", ip, port)
	log.Printf("Connected as: %s", connectedUser)
	log.Printf("Commands run: %d", len(commands))
	log.Println("Results saved to winrm_test_results.log")
}

func runCommand(client *winrm.Client, cmd string, description string) (string, error) {
	stdout, stderr, code, err := client.RunWithString(cmd, "")
	if err != nil {
		return "", fmt.Errorf("%s (exit code %d): %s", stderr, code, err)
	}
	return strings.TrimSpace(stdout), nil
}

func printSection(title string, content string) {
	divider := strings.Repeat("=", 50)
	log.Printf("\n%s\n%s\n%s\n%s\n", divider, title, divider, content)
}
