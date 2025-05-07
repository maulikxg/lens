package utils

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/netdisco/netdisco/internal/models"
)

// DetectOSType returns the current OS type
func DetectOSType() models.DeviceType {
	switch runtime.GOOS {
	case "windows":
		return models.DeviceTypeWindows
	case "linux":
		return models.DeviceTypeLinux
	default:
		return models.DeviceTypeUnknown
	}
}

// DetectRemoteOSType attempts to determine the OS type of a remote host
// using multiple detection methods for increased reliability
func DetectRemoteOSType(ip string, timeout int) models.DeviceType {
	// First try port scanning for common OS-specific ports
	osType := detectOSByPorts(ip, timeout)
	if osType != models.DeviceTypeUnknown {
		return osType
	}

	// Try TTL-based detection as a fallback
	return detectOSByTTL(ip)
}

// detectOSByPorts attempts to identify OS by checking common ports
func detectOSByPorts(ip string, timeout int) models.DeviceType {
	timeout = timeout * 1000 // Convert to milliseconds
	
	// Check for Windows-specific ports
	windowsPorts := []int{3389, 5985, 5986, 445, 139}
	for _, port := range windowsPorts {
		if isPortOpen(ip, port, timeout) {
			return models.DeviceTypeWindows
		}
	}
	
	// Check for Linux/Unix-specific ports
	linuxPorts := []int{22}
	for _, port := range linuxPorts {
		if isPortOpen(ip, port, timeout) {
			return models.DeviceTypeLinux
		}
	}
	
	return models.DeviceTypeUnknown
}

// detectOSByTTL uses TTL values from ICMP to guess the OS
// Windows typically uses TTL=128, Linux uses TTL=64
func detectOSByTTL(ip string) models.DeviceType {
	var cmd *exec.Cmd
	
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return models.DeviceTypeUnknown
	}
	
	outputStr := string(output)
	
	// Check for TTL values in the output
	if strings.Contains(outputStr, "TTL=128") || strings.Contains(outputStr, "ttl=128") {
		return models.DeviceTypeWindows
	} else if strings.Contains(outputStr, "TTL=64") || strings.Contains(outputStr, "ttl=64") {
		return models.DeviceTypeLinux
	}
	
	return models.DeviceTypeUnknown
}

// isPortOpen checks if a specific port is open on a remote host
func isPortOpen(ip string, port, timeout int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Millisecond)
	
	if err != nil {
		return false
	}
	
	defer conn.Close()
	return true
} 