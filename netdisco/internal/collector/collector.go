package collector

import (
	"fmt"
	"log"

	"github.com/netdisco/netdisco/internal/models"
)

// DeviceCollector is the interface for all device information collectors
type DeviceCollector interface {
	Collect(device *models.Device) error
}

// NewCollector creates the appropriate collector for the device type
func NewCollector(config *models.Config, logger *log.Logger, deviceType models.DeviceType) (DeviceCollector, error) {
	switch deviceType {
	case models.DeviceTypeLinux:
		if config.SSHConfig.Username == "" || config.SSHConfig.Password == "" {
			return nil, fmt.Errorf("SSH credentials are required for Linux devices")
		}
		return NewSSHCollector(config, logger), nil
	case models.DeviceTypeWindows:
		if config.WinRMConfig.Username == "" || config.WinRMConfig.Password == "" {
			return nil, fmt.Errorf("WinRM credentials are required for Windows devices")
		}
		return NewWinRMCollector(config, logger), nil
	default:
		return nil, fmt.Errorf("unsupported device type: %s", deviceType)
	}
} 