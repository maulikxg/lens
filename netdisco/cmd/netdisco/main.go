package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/netdisco/netdisco/internal/discovery"
	"github.com/netdisco/netdisco/internal/models"
	"github.com/netdisco/netdisco/internal/output"
)

func main() {
	// Command line arguments
	targetArg := flag.String("target", "", "Target IP, IP range, or CIDR notation (required)")
	outputDir := flag.String("output", "./output", "Directory to store results")
	concurrency := flag.Int("concurrency", 10, "Maximum number of concurrent operations")
	timeout := flag.Int("timeout", 5, "Timeout in seconds for network operations")
	sshUser := flag.String("ssh-user", "", "SSH username for Linux systems")
	sshPass := flag.String("ssh-pass", "", "SSH password for Linux systems")
	sshPort := flag.Int("ssh-port", 22, "SSH port for Linux systems")
	sshAltUsers := flag.String("ssh-alt-users", "", "Comma-separated list of alternative SSH usernames to try")
	winUser := flag.String("win-user", "", "WinRM username for Windows systems")
	winPass := flag.String("win-pass", "", "WinRM password for Windows systems")
	winPort := flag.Int("win-port", 5985, "WinRM port for Windows systems")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	debugMode := flag.Bool("debug", false, "Enable debug mode with additional error information")

	flag.Parse()

	// Validate required arguments
	if *targetArg == "" {
		fmt.Println("Error: target is required")
		flag.Usage()
		os.Exit(1)
	}

	// Process alternative SSH users
	var altUsers []string
	if *sshAltUsers != "" {
		altUsers = strings.Split(*sshAltUsers, ",")
		for i, user := range altUsers {
			altUsers[i] = strings.TrimSpace(user)
		}
	}

	// Create configuration from command line arguments
	config := &models.Config{
		Target:      *targetArg,
		OutputDir:   *outputDir,
		Concurrency: *concurrency,
		Timeout:     *timeout,
		SSHConfig: models.SSHConfig{
			Username:         *sshUser,
			Password:         *sshPass,
			Port:             *sshPort,
			AlternativeUsers: altUsers,
		},
		WinRMConfig: models.WinRMConfig{
			Username: *winUser,
			Password: *winPass,
			Port:     *winPort,
		},
		Verbose:   *verbose,
		DebugMode: *debugMode,
	}

	// Ensure output directory exists
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Initialize logger
	logFile, err := os.Create(fmt.Sprintf("%s/netdisco.log", config.OutputDir))
	if err != nil {
		log.Fatalf("Failed to create log file: %v", err)
	}
	defer logFile.Close()

	// Configure logger
	var logOutput io.Writer
	if config.Verbose {
		// Log to both file and stdout in verbose mode
		logOutput = io.MultiWriter(logFile, os.Stdout)
	} else {
		logOutput = logFile
	}
	logger := log.New(logOutput, "", log.LstdFlags)

	// Log startup information
	logger.Printf("NetDisco starting with target: %s", config.Target)
	if config.SSHConfig.Username != "" {
		logger.Printf("SSH credentials provided for Linux systems (username: %s)", config.SSHConfig.Username)
		if len(config.SSHConfig.AlternativeUsers) > 0 {
			logger.Printf("Alternative SSH usernames: %s", strings.Join(config.SSHConfig.AlternativeUsers, ", "))
		}
	}
	if config.WinRMConfig.Username != "" {
		logger.Printf("WinRM credentials provided for Windows systems (username: %s)", config.WinRMConfig.Username)
	}

	// Start discovery process
	fmt.Println("Starting network discovery...")
	devices, err := discovery.Discover(config, logger)
	if err != nil {
		logger.Fatalf("Discovery failed: %v", err)
	}

	// Output results
	fmt.Printf("Discovery complete. Found %d devices.\n", len(devices))
	if err := output.SaveToJSON(devices, config.OutputDir); err != nil {
		logger.Fatalf("Failed to save results: %v", err)
	}

	// Print summary
	reachable := 0
	linux := 0
	windows := 0
	unknown := 0
	errors := 0
	for _, device := range devices {
		if device.Reachable {
			reachable++
			switch device.DeviceType {
			case models.DeviceTypeLinux:
				linux++
			case models.DeviceTypeWindows:
				windows++
			default:
				unknown++
			}
			if len(device.ScanErrors) > 0 {
				errors++
			}
		}
	}

	fmt.Println("\nSummary:")
	fmt.Printf("- Total devices scanned: %d\n", len(devices))
	fmt.Printf("- Reachable devices: %d\n", reachable)
	fmt.Printf("- Linux systems: %d\n", linux)
	fmt.Printf("- Windows systems: %d\n", windows)
	fmt.Printf("- Unknown systems: %d\n", unknown)
	fmt.Printf("- Devices with collection errors: %d\n", errors)
	
	// Show error summary if there are any errors and debug mode is enabled
	if errors > 0 && config.DebugMode {
		fmt.Println("\nError Summary:")
		for _, device := range devices {
			if len(device.ScanErrors) > 0 {
				fmt.Printf("- %s: %s\n", device.IP, device.ScanErrors[0])
			}
		}
	}
	
	fmt.Printf("\nResults saved to %s\n", config.OutputDir)
}
