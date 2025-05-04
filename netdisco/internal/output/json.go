package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netdisco/netdisco/internal/models"
)

// SaveToJSON saves the discovered devices to JSON files
func SaveToJSON(devices []models.Device, outputDir string) error {
	// Create summary file
	if err := saveSummary(devices, outputDir); err != nil {
		return fmt.Errorf("failed to save summary: %v", err)
	}

	// Create individual device files
	for _, device := range devices {
		if err := saveDevice(device, outputDir); err != nil {
			return fmt.Errorf("failed to save device %s: %v", device.IP, err)
		}
	}

	return nil
}

// saveSummary saves a summary of all devices to a JSON file
func saveSummary(devices []models.Device, outputDir string) error {
	// Create a summary structure
	summary := struct {
		TotalDevices     int             `json:"total_devices"`
		ReachableDevices int             `json:"reachable_devices"`
		LinuxDevices     int             `json:"linux_devices"`
		WindowsDevices   int             `json:"windows_devices"`
		UnknownDevices   int             `json:"unknown_devices"`
		Devices          []models.Device `json:"devices"`
		Timestamp        string          `json:"timestamp"`
	}{
		TotalDevices: len(devices),
		Devices:      devices,
		Timestamp:    time.Now().Format(time.RFC3339),
	}

	// Count device types
	for _, device := range devices {
		if device.Reachable {
			summary.ReachableDevices++
		}
		switch device.DeviceType {
		case models.DeviceTypeLinux:
			summary.LinuxDevices++
		case models.DeviceTypeWindows:
			summary.WindowsDevices++
		default:
			summary.UnknownDevices++
		}
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal summary: %v", err)
	}

	// Save to file
	summaryFile := filepath.Join(outputDir, "summary.json")
	if err := os.WriteFile(summaryFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write summary file: %v", err)
	}

	return nil
}

// saveDevice saves a single device to a JSON file
func saveDevice(device models.Device, outputDir string) error {
	// Skip unreachable devices
	if !device.Reachable {
		return nil
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(device, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal device: %v", err)
	}

	// Create a valid filename
	filename := sanitizeFilename(device.IP)
	if device.Hostname != "" {
		filename = sanitizeFilename(device.Hostname) + "_" + filename
	}

	// Save to file
	deviceFile := filepath.Join(outputDir, filename+".json")
	if err := os.WriteFile(deviceFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write device file: %v", err)
	}

	return nil
}

// sanitizeFilename sanitizes a string to use as a filename
func sanitizeFilename(s string) string {
	// Replace invalid characters with underscores
	invalid := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", " "}
	result := s
	for _, char := range invalid {
		result = strings.ReplaceAll(result, char, "_")
	}
	return result
} 