package discovery

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/netdisco/netdisco/internal/models"
)

// Discover scans the network for devices and collects information about them
func Discover(config *models.Config, logger *log.Logger) ([]models.Device, error) {
	logger.Printf("Starting discovery with target: %s", config.Target)
	
	// Parse target into IP addresses
	ips, err := parseTarget(config.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target: %v", err)
	}
	
	logger.Printf("Parsed %d IP addresses to scan", len(ips))
	
	// Create a channel to receive results
	results := make(chan models.Device, len(ips))
	
	// Create a wait group to track goroutines
	var wg sync.WaitGroup
	
	// Create a semaphore to limit concurrency
	semaphore := make(chan struct{}, config.Concurrency)
	
	// Start discovery for each IP
	for _, ip := range ips {
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Create a new device
			device := models.Device{
				IP:         ipAddr,
				DeviceType: models.DeviceTypeUnknown,
				LastScan:   time.Now(),
				Reachable:  false,
			}
			
			// Check if the device is reachable
			if isReachable(ipAddr, config.Timeout) {
				device.Reachable = true
				logger.Printf("Device %s is reachable", ipAddr)
				
				// Scan open ports
				ports := scanPorts(ipAddr, []int{22, 80, 443, 3389, 5985}, config.Timeout)
				device.OpenPorts = ports
				
				// Try to identify OS type
				deviceType := identifyOS(ipAddr, ports)
				device.DeviceType = deviceType
				
				// Resolve hostname
				hostname, _ := resolveHostname(ipAddr)
				device.Hostname = hostname
			} else {
				logger.Printf("Device %s is not reachable", ipAddr)
			}
			
			// Send the result
			results <- device
		}(ip)
	}
	
	// Wait for all goroutines to complete
	wg.Wait()
	close(results)
	
	// Collect results
	var devices []models.Device
	for device := range results {
		devices = append(devices, device)
	}
	
	logger.Printf("Discovery completed. Found %d devices, %d reachable", len(devices), countReachable(devices))
	
	// Collect detailed information from reachable devices
	collectedDevices, err := CollectDeviceInfo(devices, config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to collect device information: %v", err)
	}
	
	// Final processing to copy data to proper fields
	for i := range collectedDevices {
		// Copy MAC address from network interface to the main device data if available
		if len(collectedDevices[i].NetworkInfo.Interfaces) > 0 {
			for _, iface := range collectedDevices[i].NetworkInfo.Interfaces {
				if iface.IP == collectedDevices[i].IP && iface.MAC != "" {
					collectedDevices[i].MAC = iface.MAC
					break
				}
			}
		}
		
		// If no MAC found for IP, try using any MAC
		if collectedDevices[i].MAC == "" && len(collectedDevices[i].NetworkInfo.Interfaces) > 0 {
			for _, iface := range collectedDevices[i].NetworkInfo.Interfaces {
				if iface.MAC != "" {
					collectedDevices[i].MAC = iface.MAC
					break
				}
			}
		}
		
		// If hostname is missing but network hostname exists, use it
		if collectedDevices[i].Hostname == "" && collectedDevices[i].NetworkInfo.Hostname != "" {
			collectedDevices[i].Hostname = collectedDevices[i].NetworkInfo.Hostname
		}
	}
	
	return collectedDevices, nil
}

// countReachable counts the number of reachable devices
func countReachable(devices []models.Device) int {
	count := 0
	for _, device := range devices {
		if device.Reachable {
			count++
		}
	}
	return count
}

// parseTarget parses a target string (IP, range, or CIDR) into a list of IP addresses
func parseTarget(target string) ([]string, error) {
	// Check if target is a CIDR notation
	if strings.Contains(target, "/") {
		return parseCIDR(target)
	}
	
	// Check if target is an IP range
	if strings.Contains(target, "-") {
		return parseIPRange(target)
	}
	
	// Single IP address
	return []string{target}, nil
}

// parseCIDR parses a CIDR notation into a list of IP addresses
func parseCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	
	// Remove network and broadcast addresses
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	
	return ips, nil
}

// parseIPRange parses an IP range (e.g., 192.168.1.1-192.168.1.10) into a list of IP addresses
func parseIPRange(ipRange string) ([]string, error) {
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format: %s", ipRange)
	}
	
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))
	
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP address in range: %s", ipRange)
	}
	
	var ips []string
	for ip := startIP; !ip.Equal(endIP); inc(ip) {
		ips = append(ips, ip.String())
	}
	ips = append(ips, endIP.String())
	
	return ips, nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// isReachable checks if a device is reachable
func isReachable(ip string, timeout int) bool {
	// Check common ports: SSH (22), HTTP (80), HTTPS (443)
	portsToCheck := []int{22, 80, 443}
	
	for _, port := range portsToCheck {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Duration(timeout)*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	
	// Not reachable on any common port
	return false
}

// scanPorts checks which ports are open on a device
func scanPorts(ip string, ports []int, timeout int) []int {
	var openPorts []int
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Duration(timeout)*time.Second)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	return openPorts
}

// identifyOS tries to identify the OS type based on open ports
func identifyOS(ip string, ports []int) models.DeviceType {
	// Check if port 22 is open (possible Linux)
	for _, port := range ports {
		if port == 22 {
			return models.DeviceTypeLinux
		}
		if port == 5985 || port == 3389 {
			return models.DeviceTypeWindows
		}
	}
	return models.DeviceTypeUnknown
}

// resolveHostname tries to resolve the hostname of an IP
func resolveHostname(ip string) (string, error) {
	hosts, err := net.LookupAddr(ip)
	if err != nil {
		return "", err
	}
	if len(hosts) > 0 {
		return hosts[0], nil
	}
	return "", fmt.Errorf("no hostname found")
} 