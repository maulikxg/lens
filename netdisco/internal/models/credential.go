package models

import (
	"time"
)

// CredentialType represents the type of credential profile
type CredentialType string

const (
	CredentialTypeLinux   CredentialType = "linux"
	CredentialTypeWindows CredentialType = "windows"
)

// CredentialProfile represents a set of credentials for authenticating to systems
type CredentialProfile struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Type        CredentialType `json:"type"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	
	// Linux specific fields
	SSHUsername string `json:"ssh_username,omitempty"`
	SSHPassword string `json:"ssh_password,omitempty"`
	SSHPort     int    `json:"ssh_port,omitempty"`
	SSHKeyFile  string `json:"ssh_key_file,omitempty"`
	
	// Windows specific fields
	WinRMUsername string `json:"winrm_username,omitempty"`
	WinRMPassword string `json:"winrm_password,omitempty"`
	WinRMPort     int    `json:"winrm_port,omitempty"`
	WinRMUseHTTPS bool   `json:"winrm_use_https,omitempty"`
}

// CreateSSHConfig converts the credential profile to an SSHConfig
func (c *CredentialProfile) CreateSSHConfig() SSHConfig {
	return SSHConfig{
		Username:         c.SSHUsername,
		Password:         c.SSHPassword,
		Port:             c.SSHPort,
		AlternativeUsers: []string{},
	}
}

// CreateWinRMConfig converts the credential profile to a WinRMConfig
func (c *CredentialProfile) CreateWinRMConfig() WinRMConfig {
	return WinRMConfig{
		Username: c.WinRMUsername,
		Password: c.WinRMPassword,
		Port:     c.WinRMPort,
	}
} 