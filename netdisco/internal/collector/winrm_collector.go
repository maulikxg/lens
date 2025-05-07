package collector

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/masterzen/winrm"
	"github.com/netdisco/netdisco/internal/models"
)

// WinRMCollector collects information from Windows systems using WinRM
type WinRMCollector struct {
	Config *models.Config
	Logger *log.Logger
}

// NewWinRMCollector creates a new WinRM collector
func NewWinRMCollector(config *models.Config, logger *log.Logger) *WinRMCollector {
	return &WinRMCollector{
		Config: config,
		Logger: logger,
	}
}

// Collect gathers information from a Windows system
func (c *WinRMCollector) Collect(device *models.Device) error {
	if device.DeviceType != models.DeviceTypeWindows {
		return fmt.Errorf("device is not a Windows system")
	}

	c.Logger.Printf("Collecting information from Windows device %s", device.IP)

	// Create WinRM client with improved configuration
	endpoint := winrm.NewEndpoint(
		device.IP,
		c.Config.WinRMConfig.Port,
		c.Config.WinRMConfig.UseHTTPS, // Use HTTPS if configured
		true,                          // skip SSL verification
		nil,                           // CA certificate
		nil,                           // client certificate
		nil,                           // client key
		time.Duration(c.Config.Timeout) * time.Second, // timeout in seconds
	)

	params := winrm.DefaultParameters
	params.Timeout = fmt.Sprintf("PT%dS", c.Config.Timeout)
	
	client, err := winrm.NewClientWithParameters(
		endpoint, 
		c.Config.WinRMConfig.Username, 
		c.Config.WinRMConfig.Password,
		params,
	)
	
	if err != nil {
		return fmt.Errorf("failed to create WinRM client: %v", err)
	}

	// Verify connection
	if err := c.verifyConnection(client); err != nil {
		return fmt.Errorf("WinRM connection verification failed: %v", err)
	}

	// Check if this is really a Windows system with a simple command
	output, err := c.runCommand(client, "ver")
	if err != nil {
		return fmt.Errorf("failed to run Windows version command: %v", err)
	}
	c.Logger.Printf("Windows version check: %s", output)

	// Collect OS information
	if err := c.collectOSInfo(client, device); err != nil {
		device.ScanErrors = append(device.ScanErrors, fmt.Sprintf("OS info: %v", err))
	}

	// Collect hardware information
	if err := c.collectHardwareInfo(client, device); err != nil {
		device.ScanErrors = append(device.ScanErrors, fmt.Sprintf("Hardware info: %v", err))
	}

	// Collect network information
	if err := c.collectNetworkInfo(client, device); err != nil {
		device.ScanErrors = append(device.ScanErrors, fmt.Sprintf("Network info: %v", err))
	}

	// Collect memory information
	if err := c.collectMemoryInfo(client, device); err != nil {
		device.ScanErrors = append(device.ScanErrors, fmt.Sprintf("Memory info: %v", err))
	}
	
	return nil
}

// verifyConnection checks if the WinRM connection is working properly
func (c *WinRMCollector) verifyConnection(client *winrm.Client) error {
	_, err := c.runCommand(client, "hostname")
	if err != nil {
		return fmt.Errorf("connection test failed: %v", err)
	}
	return nil
}

// verifyOSType confirms that the device is running Windows
func (c *WinRMCollector) verifyOSType(client *winrm.Client, device *models.Device) error {
	// Try to run a Windows-specific command
	output, err := c.runPowerShell(client, "Get-WmiObject Win32_OperatingSystem | Select-Object Caption")
	if err != nil {
		return fmt.Errorf("failed to verify OS type: %v", err)
	}

	// Check if the output contains Windows
	if !strings.Contains(strings.ToLower(output), "windows") {
		// If the verification fails, update the device type
		device.DeviceType = models.DeviceTypeUnknown
		return fmt.Errorf("device does not appear to be running Windows")
	}
	
	return nil
}

// collectOSInfo collects operating system information
func (c *WinRMCollector) collectOSInfo(client *winrm.Client, device *models.Device) error {
	// Get OS information using simple PowerShell commands
	osInfo := models.OSInfo{}

	// Get OS name
	command := "systeminfo | findstr /B /C:\"OS Name\""
	output, err := c.runCommand(client, command)
	if err != nil {
		return fmt.Errorf("failed to get OS name: %v", err)
	}
	if strings.Contains(output, ":") {
		parts := strings.SplitN(output, ":", 2)
		if len(parts) == 2 {
			osInfo.Name = strings.TrimSpace(parts[1])
			osInfo.Distribution = "windows"
		}
	}
	
	// Get OS version
	command = "systeminfo | findstr /B /C:\"OS Version\""
	output, err = c.runCommand(client, command)
	if err != nil {
		return fmt.Errorf("failed to get OS version: %v", err)
	}
	if strings.Contains(output, ":") {
		parts := strings.SplitN(output, ":", 2)
		if len(parts) == 2 {
			osInfo.Version = strings.TrimSpace(parts[1])
		}
	}
	
	// Get system architecture
	command = "systeminfo | findstr /B /C:\"System Type\""
	output, err = c.runCommand(client, command)
	if err != nil {
		return fmt.Errorf("failed to get system type: %v", err)
	}
	if strings.Contains(output, ":") {
		parts := strings.SplitN(output, ":", 2)
		if len(parts) == 2 {
			osInfo.Architecture = strings.TrimSpace(parts[1])
		}
	}

	device.OSInfo = osInfo
	return nil
}

// collectHardwareInfo collects hardware information
func (c *WinRMCollector) collectHardwareInfo(client *winrm.Client, device *models.Device) error {
	hardwareInfo := models.HardwareInfo{}

	// Get CPU information using system info
	command := "systeminfo | findstr /B /C:\"Processor(s)\""
	output, err := c.runCommand(client, command)
	if err != nil {
		return fmt.Errorf("failed to get CPU information: %v", err)
	}
	if strings.Contains(output, ":") {
		parts := strings.SplitN(output, ":", 2)
		if len(parts) == 2 {
			hardwareInfo.CPUModel = strings.TrimSpace(parts[1])
			// Try to extract CPU cores from the description
			re := regexp.MustCompile(`(\d+) Processor\(s\) Installed`)
			matches := re.FindStringSubmatch(output)
			if len(matches) > 1 {
				cores, err := strconv.Atoi(matches[1])
		if err == nil {
			hardwareInfo.CPUCores = cores
		}
	}
		}
	}

	// Get RAM information
	command = "systeminfo | findstr /B /C:\"Total Physical Memory\""
	output, err = c.runCommand(client, command)
	if err != nil {
		return fmt.Errorf("failed to get RAM information: %v", err)
	}
	if strings.Contains(output, ":") {
		parts := strings.SplitN(output, ":", 2)
		if len(parts) == 2 {
			memStr := strings.TrimSpace(parts[1])
			// Extract the numeric portion (typically in MB)
			re := regexp.MustCompile(`([\d,]+)\s*MB`)
			matches := re.FindStringSubmatch(memStr)
			if len(matches) > 1 {
				// Remove commas from the number
				numStr := strings.Replace(matches[1], ",", "", -1)
				ram, err := strconv.ParseInt(numStr, 10, 64)
		if err == nil {
					hardwareInfo.TotalRAM = ram
				}
			}
		}
	}

	// Get disk space information
	command = "wmic logicaldisk where DeviceID='C:' get Size,FreeSpace"
	output, err = c.runCommand(client, command)
	if err == nil {
		lines := strings.Split(output, "\n")
		if len(lines) > 1 {
			parts := strings.Fields(lines[1])
			if len(parts) >= 2 {
				freeSpace, err := strconv.ParseInt(parts[0], 10, 64)
				if err == nil {
					hardwareInfo.FreeDiskSpace = freeSpace / (1024 * 1024 * 1024) // Convert bytes to GB
				}
				totalSize, err := strconv.ParseInt(parts[1], 10, 64)
		if err == nil {
					hardwareInfo.TotalDiskSpace = totalSize / (1024 * 1024 * 1024) // Convert bytes to GB
				}
			}
		}
	}

	device.HardwareInfo = hardwareInfo
	return nil
}

// collectNetworkInfo collects network configuration information
func (c *WinRMCollector) collectNetworkInfo(client *winrm.Client, device *models.Device) error {
	networkInfo := models.NetworkInfo{}

	// Get hostname
	command := "hostname"
	output, err := c.runCommand(client, command)
	if err != nil {
		return fmt.Errorf("failed to get hostname: %v", err)
	}
	networkInfo.Hostname = strings.TrimSpace(output)

	// Get IP addresses using ipconfig
	command = "ipconfig /all"
	output, err = c.runCommand(client, command)
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %v", err)
	}

	// Parse ipconfig output
	var interfaces []models.NetworkInterface
	var currentInterface *models.NetworkInterface
	
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Start of a new interface
		if strings.Contains(line, "adapter") && strings.HasSuffix(line, ":") {
			if currentInterface != nil && currentInterface.Name != "" {
				interfaces = append(interfaces, *currentInterface)
			}
			
			name := strings.TrimSuffix(strings.TrimPrefix(line, "Ethernet adapter "), ":")
			name = strings.TrimSuffix(strings.TrimPrefix(name, "Wireless LAN adapter "), ":")
			currentInterface = &models.NetworkInterface{
				Name: name,
			}
		}
		
		if currentInterface == nil {
			continue
		}
		
		// Extract MAC address
		if strings.Contains(line, "Physical Address") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentInterface.MAC = strings.TrimSpace(parts[1])
			}
		}
		
		// Extract IP address
		if strings.Contains(line, "IPv4 Address") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				// Remove (Preferred) suffix if present
				ip := strings.TrimSpace(parts[1])
				ip = strings.Replace(ip, "(Preferred)", "", -1)
				currentInterface.IP = strings.TrimSpace(ip)
			}
		}
		
		// Extract subnet mask
		if strings.Contains(line, "Subnet Mask") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentInterface.Netmask = strings.TrimSpace(parts[1])
			}
		}
	}
	
	// Add the last interface if it exists
	if currentInterface != nil && currentInterface.Name != "" {
		interfaces = append(interfaces, *currentInterface)
	}
	
	networkInfo.Interfaces = interfaces
	device.NetworkInfo = networkInfo
	return nil
}

// collectMemoryInfo collects memory information
func (c *WinRMCollector) collectMemoryInfo(client *winrm.Client, device *models.Device) error {
	// Use the RAM info already collected in hardware info
	memoryInfo := models.MemoryInfo{
		TotalRAMSize: device.HardwareInfo.TotalRAM,
	}
	
	device.MemoryInfo = memoryInfo
	return nil
}

// runCommand executes a command on the remote system
func (c *WinRMCollector) runCommand(client *winrm.Client, cmd string) (string, error) {
	stdout, stderr, _, err := client.RunWithString(cmd, "")
	if err != nil {
		return "", fmt.Errorf("failed to run command: %v, stderr: %s", err, stderr)
	}
	return stdout, nil
}

// runPowerShell executes a PowerShell command on the remote system
func (c *WinRMCollector) runPowerShell(client *winrm.Client, cmd string) (string, error) {
	// Use a simpler approach that works more reliably
	wrappedCmd := fmt.Sprintf("powershell -Command \"%s\"", strings.Replace(cmd, "\"", "`\"", -1))
	c.Logger.Printf("Running PowerShell command: %s", wrappedCmd)
	return c.runCommand(client, wrappedCmd)
}

// encodeCommand base64 encodes a PowerShell command
func encodeCommand(cmd string) string {
	return winrm.Powershell(cmd)
} 
