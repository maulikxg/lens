package models

import (
	"time"
)

// TargetType represents the type of target specification in a discovery profile
type TargetType string

const (
	TargetTypeSingle TargetType = "single"    // Single IP address
	TargetTypeRange  TargetType = "range"     // IP range (e.g., 192.168.1.1-192.168.1.254)
	TargetTypeCIDR   TargetType = "cidr"      // CIDR notation (e.g., 192.168.1.0/24)
)

// DiscoveryStatus represents the status of a discovery job
type DiscoveryStatus string

const (
	DiscoveryStatusPending   DiscoveryStatus = "pending"
	DiscoveryStatusRunning   DiscoveryStatus = "running"
	DiscoveryStatusCompleted DiscoveryStatus = "completed"
	DiscoveryStatusFailed    DiscoveryStatus = "failed"
)

// DiscoveryProfile represents a network discovery configuration
type DiscoveryProfile struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	TargetType       TargetType      `json:"target_type"`
	Target           string          `json:"target"`             // IP, IP range, or CIDR
	CredentialIDs    []string        `json:"credential_ids"`     // IDs of credential profiles to use
	Concurrency      int             `json:"concurrency"`        // Max concurrent operations
	Timeout          int             `json:"timeout"`            // Timeout in seconds
	LastRunAt        *time.Time      `json:"last_run_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// DiscoveryJob represents a running or completed discovery operation
type DiscoveryJob struct {
	ID                string           `json:"id"`
	ProfileID         string           `json:"profile_id"`
	Status            DiscoveryStatus  `json:"status"`
	TargetsTotal      int              `json:"targets_total"`
	TargetsCompleted  int              `json:"targets_completed"`
	TargetsSuccessful int              `json:"targets_successful"`
	TargetsFailed     int              `json:"targets_failed"`
	StartedAt         time.Time        `json:"started_at"`
	CompletedAt       *time.Time       `json:"completed_at,omitempty"`
	ErrorMessage      string           `json:"error_message,omitempty"`
	Results           []Device         `json:"results,omitempty"`
}

// CreateConfig creates a Config object from the discovery profile and credential profile
func (d *DiscoveryProfile) CreateConfig(credentials []*CredentialProfile, outputDir string) *Config {
	// Initialize Config with defaults
	config := &Config{
		Target:      d.Target,
		OutputDir:   outputDir,
		Concurrency: d.Concurrency,
		Timeout:     d.Timeout,
		Verbose:     true, // Set to true for better debug info
		DebugMode:   true, // Set to true for better debug info
	}
	
	// Apply credential profiles
	for _, cred := range credentials {
		switch cred.Type {
		case CredentialTypeLinux:
			config.SSHConfig = cred.CreateSSHConfig()
		case CredentialTypeWindows:
			config.WinRMConfig = cred.CreateWinRMConfig()
		}
	}
	
	return config
} 