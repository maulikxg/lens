package models

// Config represents the application configuration
type Config struct {
	Target      string     // Target IP, IP range, or CIDR notation
	OutputDir   string     // Directory to store results
	Concurrency int        // Maximum number of concurrent operations
	Timeout     int        // Timeout in seconds for network operations
	SSHConfig   SSHConfig  // SSH configuration for Linux systems
	WinRMConfig WinRMConfig // WinRM configuration for Windows systems
	Verbose     bool       // Enable verbose logging
	DebugMode   bool       // Enable debug mode with additional information
}

// SSHConfig represents SSH connection configuration
type SSHConfig struct {
	Username         string
	Password         string
	Port             int
	AlternativeUsers []string // Alternative usernames to try if main username fails
}

// WinRMConfig represents WinRM connection configuration
type WinRMConfig struct {
	Username string
	Password string
	Port     int
} 