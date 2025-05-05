package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/netdisco/netdisco/internal/api"
	"github.com/netdisco/netdisco/internal/discovery"
	"github.com/netdisco/netdisco/internal/models"
	"github.com/netdisco/netdisco/internal/output"
)

func main() {
	// Define command line modes
	cliMode := flag.NewFlagSet("cli", flag.ExitOnError)
	apiMode := flag.NewFlagSet("api", flag.ExitOnError)

	// Command line arguments for CLI mode
	targetArg := cliMode.String("target", "", "Target IP, IP range, or CIDR notation (required)")
	outputDir := cliMode.String("output", "./output", "Directory to store results")
	concurrency := cliMode.Int("concurrency", 10, "Maximum number of concurrent operations")
	timeout := cliMode.Int("timeout", 5, "Timeout in seconds for network operations")
	sshUser := cliMode.String("ssh-user", "", "SSH username for Linux systems")
	sshPass := cliMode.String("ssh-pass", "", "SSH password for Linux systems")
	sshPort := cliMode.Int("ssh-port", 22, "SSH port for Linux systems")
	sshAltUsers := cliMode.String("ssh-alt-users", "", "Comma-separated list of alternative SSH usernames to try")
	winUser := cliMode.String("win-user", "", "WinRM username for Windows systems")
	winPass := cliMode.String("win-pass", "", "WinRM password for Windows systems")
	winPort := cliMode.Int("win-port", 5985, "WinRM port for Windows systems")
	verbose := cliMode.Bool("verbose", false, "Enable verbose logging")
	debugMode := cliMode.Bool("debug", false, "Enable debug mode with additional error information")

	// Command line arguments for API mode
	apiPort := apiMode.Int("port", 8080, "Port for the API server")
	apiHost := apiMode.String("host", "localhost", "Host for the API server")
	apiDataDir := apiMode.String("data-dir", "./data", "Directory to store API data")
	apiVerbose := apiMode.Bool("verbose", false, "Enable verbose logging")

	// If no arguments provided, show usage
	if len(os.Args) < 2 {
		fmt.Println("Please specify a mode: 'cli' or 'api'")
		fmt.Println("\nCLI mode usage:")
		cliMode.PrintDefaults()
		fmt.Println("\nAPI mode usage:")
		apiMode.PrintDefaults()
		os.Exit(1)
	}

	// Parse mode
	switch os.Args[1] {
	case "cli":
		cliMode.Parse(os.Args[2:])
		runCLIMode(cliMode, targetArg, outputDir, concurrency, timeout, sshUser, sshPass, sshPort, sshAltUsers, winUser, winPass, winPort, verbose, debugMode)
	case "api":
		apiMode.Parse(os.Args[2:])
		runAPIMode(apiMode, apiPort, apiHost, apiDataDir, apiVerbose)
	default:
		fmt.Printf("Unknown mode: %s\n", os.Args[1])
		fmt.Println("Please specify a mode: 'cli' or 'api'")
		os.Exit(1)
	}
}

func runCLIMode(flagSet *flag.FlagSet, targetArg, outputDir *string, concurrency, timeout *int, sshUser, sshPass *string, sshPort *int, sshAltUsers *string, winUser, winPass *string, winPort *int, verbose, debugMode *bool) {
	// Validate required arguments
	if *targetArg == "" {
		fmt.Println("Error: target is required")
		flagSet.Usage()
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

func runAPIMode(flagSet *flag.FlagSet, port *int, host, dataDir *string, verbose *bool) {
	// Ensure data directory exists
	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Initialize logger
	logFile, err := os.Create(fmt.Sprintf("%s/api.log", *dataDir))
	if err != nil {
		log.Fatalf("Failed to create log file: %v", err)
	}
	defer logFile.Close()

	// Configure logger
	var logOutput io.Writer
	if *verbose {
		// Log to both file and stdout in verbose mode
		logOutput = io.MultiWriter(logFile, os.Stdout)
	} else {
		logOutput = logFile
	}
	logger := log.New(logOutput, "", log.LstdFlags)

	// Create API server
	apiServer, err := api.NewAPI(*dataDir, logger)
	if err != nil {
		logger.Fatalf("Failed to create API server: %v", err)
	}

	// Get router
	router := apiServer.GetRouter()

	// Configure server
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", *host, *port),
		Handler: router,
	}

	// Handle graceful shutdown
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		fmt.Printf("API server starting on http://%s:%d\n", *host, *port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-stopChan
	fmt.Println("\nReceived shutdown signal. Shutting down API server...")
	if err := server.Close(); err != nil {
		logger.Fatalf("Error during server shutdown: %v", err)
	}
	fmt.Println("API server shut down successfully.")
}
