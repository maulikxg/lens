package collector

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

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

	// Create WinRM client
	endpoint := winrm.NewEndpoint(
		device.IP,
		c.Config.WinRMConfig.Port,
		false, // use HTTPS
		true,  // skip SSL verification
		nil,   // CA certificate
		nil,   // client certificate
		nil,   // client key
		0,     // timeout
	)

	client, err := winrm.NewClient(endpoint, c.Config.WinRMConfig.Username, c.Config.WinRMConfig.Password)
	if err != nil {
		return fmt.Errorf("failed to create WinRM client: %v", err)
	}

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

// collectOSInfo collects operating system information
func (c *WinRMCollector) collectOSInfo(client *winrm.Client, device *models.Device) error {
	// Get OS information using PowerShell
	command := "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture"
	output, err := c.runPowerShell(client, command)
	if err != nil {
		return fmt.Errorf("failed to get OS information: %v", err)
	}

	osInfo := models.OSInfo{}

	// Parse OS information
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Caption") {
			continue // Skip header line
		}
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch key {
			case "Caption":
				osInfo.Name = value
				osInfo.Distribution = "windows"
			case "Version":
				osInfo.Version = value
			case "OSArchitecture":
				osInfo.Architecture = value
			}
		}
	}

	// Get kernel information (Windows doesn't really have a "kernel version" like Linux)
	// Using BuildNumber as a substitute
	command = "Get-CimInstance Win32_OperatingSystem | Select-Object BuildNumber"
	output, err = c.runPowerShell(client, command)
	if err == nil {
		re := regexp.MustCompile(`BuildNumber\s*:\s*(.+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) > 1 {
			osInfo.Kernel = strings.TrimSpace(matches[1])
		}
	}

	device.OSInfo = osInfo
	return nil
}

// collectHardwareInfo collects hardware information
func (c *WinRMCollector) collectHardwareInfo(client *winrm.Client, device *models.Device) error {
	hardwareInfo := models.HardwareInfo{}

	// Get CPU model and cores
	command := "Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores"
	output, err := c.runPowerShell(client, command)
	if err != nil {
		return fmt.Errorf("failed to get CPU information: %v", err)
	}

	// Parse CPU information
	cpuNameRe := regexp.MustCompile(`Name\s*:\s*(.+)`)
	cpuCoresRe := regexp.MustCompile(`NumberOfCores\s*:\s*(\d+)`)

	cpuNameMatches := cpuNameRe.FindStringSubmatch(output)
	if len(cpuNameMatches) > 1 {
		hardwareInfo.CPUModel = strings.TrimSpace(cpuNameMatches[1])
	}

	cpuCoresMatches := cpuCoresRe.FindStringSubmatch(output)
	if len(cpuCoresMatches) > 1 {
		cores, err := strconv.Atoi(strings.TrimSpace(cpuCoresMatches[1]))
		if err == nil {
			hardwareInfo.CPUCores = cores
		}
	}

	// Get total RAM
	command = "Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory"
	output, err = c.runPowerShell(client, command)
	if err != nil {
		return fmt.Errorf("failed to get total RAM: %v", err)
	}

	// Parse RAM information
	ramRe := regexp.MustCompile(`TotalPhysicalMemory\s*:\s*(\d+)`)
	ramMatches := ramRe.FindStringSubmatch(output)
	if len(ramMatches) > 1 {
		ram, err := strconv.ParseInt(strings.TrimSpace(ramMatches[1]), 10, 64)
		if err == nil {
			hardwareInfo.TotalRAM = ram / (1024 * 1024) // Convert bytes to MB
		}
	}

	// Get disk space
	command = "Get-CimInstance Win32_LogicalDisk -Filter 'DeviceID=\"C:\"' | Select-Object Size, FreeSpace"
	output, err = c.runPowerShell(client, command)
	if err != nil {
		return fmt.Errorf("failed to get disk space: %v", err)
	}

	// Parse disk information
	sizeRe := regexp.MustCompile(`Size\s*:\s*(\d+)`)
	freeRe := regexp.MustCompile(`FreeSpace\s*:\s*(\d+)`)

	sizeMatches := sizeRe.FindStringSubmatch(output)
	if len(sizeMatches) > 1 {
		size, err := strconv.ParseInt(strings.TrimSpace(sizeMatches[1]), 10, 64)
		if err == nil {
			hardwareInfo.TotalDiskSpace = size / (1024 * 1024 * 1024) // Convert bytes to GB
		}
	}

	freeMatches := freeRe.FindStringSubmatch(output)
	if len(freeMatches) > 1 {
		free, err := strconv.ParseInt(strings.TrimSpace(freeMatches[1]), 10, 64)
		if err == nil {
			hardwareInfo.FreeDiskSpace = free / (1024 * 1024 * 1024) // Convert bytes to GB
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

	// Get domain name
	command = "Get-CimInstance Win32_ComputerSystem | Select-Object Domain"
	output, err = c.runPowerShell(client, command)
	if err == nil {
		re := regexp.MustCompile(`Domain\s*:\s*(.+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) > 1 {
			networkInfo.Domain = strings.TrimSpace(matches[1])
		}
	}

	// Get network interfaces
	command = `Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $true } | ForEach-Object {
		$adapter = $_
		$config = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.Index -eq $adapter.Index }
		[PSCustomObject]@{
			Name = $adapter.Name
			MAC = $adapter.MACAddress
			IP = $config.IPAddress -join ','
			Netmask = $config.IPSubnet -join ','
			Status = $adapter.NetConnectionStatus
		}
	} | Format-List`
	output, err = c.runPowerShell(client, command)
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %v", err)
	}

	// Parse network interfaces
	interfacesRe := regexp.MustCompile(`(?s)Name\s*:\s*(.+?)\nMAC\s*:\s*(.+?)\nIP\s*:\s*(.+?)\nNetmask\s*:\s*(.+?)\nStatus\s*:\s*(\d+)`)
	matches := interfacesRe.FindAllStringSubmatch(output, -1)
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}

		name := strings.TrimSpace(match[1])
		mac := strings.TrimSpace(match[2])
		ips := strings.Split(strings.TrimSpace(match[3]), ",")
		netmasks := strings.Split(strings.TrimSpace(match[4]), ",")
		status := "down"
		if statusVal, err := strconv.Atoi(strings.TrimSpace(match[5])); err == nil && statusVal == 2 {
			status = "up"
		}

		// Use the first IP address and netmask
		ip := ""
		netmask := ""
		if len(ips) > 0 {
			ip = ips[0]
		}
		if len(netmasks) > 0 {
			netmask = netmasks[0]
		}

		if ip != "" && netmask != "" {
			networkInterface := models.NetworkInterface{
				Name:    name,
				MAC:     mac,
				IP:      ip,
				Netmask: netmask,
				Status:  status,
			}
			networkInfo.Interfaces = append(networkInfo.Interfaces, networkInterface)
		}
	}

	device.NetworkInfo = networkInfo
	return nil
}

// collectMemoryInfo collects detailed memory information
func (c *WinRMCollector) collectMemoryInfo(client *winrm.Client, device *models.Device) error {
	memoryInfo := models.MemoryInfo{}

	// Get detailed memory slots information
	command := `Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
		[PSCustomObject]@{
			SlotID = $_.DeviceLocator
			Manufacturer = $_.Manufacturer
			SerialNumber = $_.SerialNumber
			Size = [math]::Round($_.Capacity / 1MB)
			Type = $_.MemoryType
			ClockSpeed = "$($_.Speed) MHz"
			Width = "$($_.DataWidth) bits"
			Occupied = $true
		}
	} | Format-List`
	output, err := c.runPowerShell(client, command)
	if err != nil {
		return fmt.Errorf("failed to get memory slots: %v", err)
	}

	// Parse memory slots
	slotRe := regexp.MustCompile(`(?s)SlotID\s*:\s*(.+?)\nManufacturer\s*:\s*(.+?)\nSerialNumber\s*:\s*(.+?)\nSize\s*:\s*(\d+)\nType\s*:\s*(\d+)\nClockSpeed\s*:\s*(.+?)\nWidth\s*:\s*(.+?)\nOccupied\s*:\s*(.+?)(?:\n|$)`)
	matches := slotRe.FindAllStringSubmatch(output, -1)
	for _, match := range matches {
		if len(match) < 9 {
			continue
		}

		slotID := strings.TrimSpace(match[1])
		manufacturer := strings.TrimSpace(match[2])
		serialNumber := strings.TrimSpace(match[3])
		sizeStr := strings.TrimSpace(match[4])
		typeStr := strings.TrimSpace(match[5])
		clockSpeed := strings.TrimSpace(match[6])
		width := strings.TrimSpace(match[7])
		occupiedStr := strings.TrimSpace(match[8])

		size, _ := strconv.ParseInt(sizeStr, 10, 64)
		memType := ""
		switch typeStr {
		case "0":
			memType = "Unknown"
		case "21":
			memType = "DDR2"
		case "24":
			memType = "DDR3"
		case "26":
			memType = "DDR4"
		default:
			memType = fmt.Sprintf("Type-%s", typeStr)
		}

		occupied := true
		if occupiedStr == "False" {
			occupied = false
		}

		slot := models.MemorySlot{
			SlotID:       slotID,
			Manufacturer: manufacturer,
			SerialNumber: serialNumber,
			Size:         size,
			Type:         memType,
			ClockSpeed:   clockSpeed,
			Width:        width,
			Occupied:     occupied,
		}

		memoryInfo.Slots = append(memoryInfo.Slots, slot)
	}

	// Get total slots info (including empty slots)
	command = `Get-CimInstance Win32_PhysicalMemoryArray | Select-Object MemoryDevices`
	output, err = c.runPowerShell(client, command)
	if err == nil {
		re := regexp.MustCompile(`MemoryDevices\s*:\s*(\d+)`)
		matches := re.FindStringSubmatch(output)
		if len(matches) > 1 {
			totalSlots, err := strconv.Atoi(strings.TrimSpace(matches[1]))
			if err == nil {
				memoryInfo.TotalSlots = totalSlots
			}
		}
	} else {
		// Fallback: just count the slots we found
		memoryInfo.TotalSlots = len(memoryInfo.Slots)
	}

	// Calculate summary information
	memoryInfo.OccupiedSlots = 0
	memoryInfo.TotalRAMSize = 0

	for _, slot := range memoryInfo.Slots {
		if slot.Occupied {
			memoryInfo.OccupiedSlots++
			memoryInfo.TotalRAMSize += slot.Size
		}
	}
	memoryInfo.FreeSlots = memoryInfo.TotalSlots - memoryInfo.OccupiedSlots

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
	encodedCmd := fmt.Sprintf("powershell -NonInteractive -EncodedCommand %s", encodeCommand(cmd))
	return c.runCommand(client, encodedCmd)
}

// encodeCommand base64 encodes a PowerShell command
func encodeCommand(cmd string) string {
	return winrm.Powershell(cmd)
} 