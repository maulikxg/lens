package collector

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/netdisco/netdisco/internal/models"
	"golang.org/x/crypto/ssh"
)

// SSHCollector collects information from Linux systems using SSH
type SSHCollector struct {
	Config *models.Config
	Logger *log.Logger
}

// NewSSHCollector creates a new SSH collector
func NewSSHCollector(config *models.Config, logger *log.Logger) *SSHCollector {
	return &SSHCollector{
		Config: config,
		Logger: logger,
	}
}

// Collect gathers information from a Linux system
func (c *SSHCollector) Collect(device *models.Device) error {
	if device.DeviceType != models.DeviceTypeLinux {
		return fmt.Errorf("device is not a Linux system")
	}

	c.Logger.Printf("Collecting information from Linux device %s", device.IP)

	// Try to connect with provided credentials first
	err := c.tryConnection(device, c.Config.SSHConfig.Username, c.Config.SSHConfig.Password)
	if err != nil {
		// If authentication fails, try common usernames
		c.Logger.Printf("Authentication failed with username '%s', trying common alternatives", c.Config.SSHConfig.Username)
		
		// List of common usernames to try
		commonUsers := []string{"admin", "root", "administrator", "ubuntu", "ec2-user", "centos", "debian", "pi"}
		
		// Check if the provided username is already in the list
		found := false
		for _, u := range commonUsers {
			if u == c.Config.SSHConfig.Username {
				found = true
				break
			}
		}
		if !found {
			commonUsers = append([]string{c.Config.SSHConfig.Username}, commonUsers...)
		}
		
		// Try each username
		var lastErr error
		for _, username := range commonUsers {
			c.Logger.Printf("Trying username: %s", username)
			if err := c.tryConnection(device, username, c.Config.SSHConfig.Password); err == nil {
				return nil // Successfully authenticated
			} else {
				lastErr = err
			}
		}
		
		return fmt.Errorf("failed with all usernames: %v", lastErr)
	}
	
	return nil
}

// tryConnection attempts to connect with given credentials and collect information
func (c *SSHCollector) tryConnection(device *models.Device, username, password string) error {
	// Create SSH client configuration
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(c.Config.Timeout) * time.Second,
	}

	// Connect to the SSH server
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", device.IP, c.Config.SSHConfig.Port), config)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %v", err)
	}
	defer client.Close()

	// Test connection with a simple command
	_, err = c.runCommand(client, "echo 'Connection test'")
	if err != nil {
		return fmt.Errorf("connection test failed: %v", err)
	}
	
	c.Logger.Printf("Successfully connected to %s with username: %s", device.IP, username)

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
func (c *SSHCollector) collectOSInfo(client *ssh.Client, device *models.Device) error {
	// Get OS release information
	output, err := c.runCommand(client, "cat /etc/os-release")
	if err != nil {
		return fmt.Errorf("failed to get OS release: %v", err)
	}

	osInfo := models.OSInfo{}

	// Parse OS release information
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "NAME=") {
			osInfo.Name = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
		} else if strings.HasPrefix(line, "VERSION=") {
			osInfo.Version = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
		} else if strings.HasPrefix(line, "ID=") {
			osInfo.Distribution = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
	}

	// Get kernel information
	output, err = c.runCommand(client, "uname -r")
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %v", err)
	}
	osInfo.Kernel = strings.TrimSpace(output)

	// Get architecture
	output, err = c.runCommand(client, "uname -m")
	if err != nil {
		return fmt.Errorf("failed to get architecture: %v", err)
	}
	osInfo.Architecture = strings.TrimSpace(output)

	device.OSInfo = osInfo
	return nil
}

// collectHardwareInfo collects hardware information
func (c *SSHCollector) collectHardwareInfo(client *ssh.Client, device *models.Device) error {
	hardwareInfo := models.HardwareInfo{}

	// Get CPU model
	output, err := c.runCommand(client, "grep 'model name' /proc/cpuinfo | head -1")
	if err != nil {
		return fmt.Errorf("failed to get CPU model: %v", err)
	}
	if strings.Contains(output, ":") {
		hardwareInfo.CPUModel = strings.TrimSpace(strings.Split(output, ":")[1])
	}

	// Get CPU cores
	output, err = c.runCommand(client, "grep -c processor /proc/cpuinfo")
	if err != nil {
		return fmt.Errorf("failed to get CPU cores: %v", err)
	}
	cores, err := strconv.Atoi(strings.TrimSpace(output))
	if err == nil {
		hardwareInfo.CPUCores = cores
	}

	// Get total RAM
	output, err = c.runCommand(client, "grep MemTotal /proc/meminfo")
	if err != nil {
		return fmt.Errorf("failed to get total RAM: %v", err)
	}
	re := regexp.MustCompile(`MemTotal:\s+(\d+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		ram, err := strconv.ParseInt(matches[1], 10, 64)
		if err == nil {
			hardwareInfo.TotalRAM = ram / 1024 // Convert KB to MB
		}
	}

	// Get disk space
	output, err = c.runCommand(client, "df -BG / | tail -1")
	if err != nil {
		return fmt.Errorf("failed to get disk space: %v", err)
	}
	fields := strings.Fields(output)
	if len(fields) >= 4 {
		totalStr := strings.TrimSuffix(fields[1], "G")
		freeStr := strings.TrimSuffix(fields[3], "G")
		total, err := strconv.ParseInt(totalStr, 10, 64)
		if err == nil {
			hardwareInfo.TotalDiskSpace = total
		}
		free, err := strconv.ParseInt(freeStr, 10, 64)
		if err == nil {
			hardwareInfo.FreeDiskSpace = free
		}
	}

	device.HardwareInfo = hardwareInfo
	return nil
}

// collectNetworkInfo collects network configuration information
func (c *SSHCollector) collectNetworkInfo(client *ssh.Client, device *models.Device) error {
	networkInfo := models.NetworkInfo{}

	// Get hostname
	output, err := c.runCommand(client, "hostname")
	if err != nil {
		return fmt.Errorf("failed to get hostname: %v", err)
	}
	networkInfo.Hostname = strings.TrimSpace(output)

	// Get domain name
	output, err = c.runCommand(client, "hostname -d")
	if err == nil && output != "" {
		networkInfo.Domain = strings.TrimSpace(output)
	}

	// Get network interfaces
	output, err = c.runCommand(client, "ip -o addr show")
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %v", err)
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			ifName := strings.TrimSuffix(fields[1], ":")
			ifStatus := "down"
			if strings.Contains(line, "state UP") {
				ifStatus = "up"
			}

			// Get IP address and netmask
			ipRegex := regexp.MustCompile(`inet\s+([0-9.]+)/(\d+)`)
			matches := ipRegex.FindStringSubmatch(line)
			if len(matches) < 3 {
				continue
			}

			ifIP := matches[1]
			ifNetmask := matches[2]

			// Get MAC address
			macOutput, err := c.runCommand(client, fmt.Sprintf("ip link show %s | grep link/ether", ifName))
			if err != nil {
				continue
			}
			macRegex := regexp.MustCompile(`link/ether\s+([0-9a-f:]+)`)
			macMatches := macRegex.FindStringSubmatch(macOutput)
			ifMAC := ""
			if len(macMatches) > 1 {
				ifMAC = macMatches[1]
			}

			networkInterface := models.NetworkInterface{
				Name:    ifName,
				IP:      ifIP,
				Netmask: ifNetmask,
				MAC:     ifMAC,
				Status:  ifStatus,
			}

			networkInfo.Interfaces = append(networkInfo.Interfaces, networkInterface)
		}
	}

	device.NetworkInfo = networkInfo
	return nil
}

// collectMemoryInfo collects detailed memory information
func (c *SSHCollector) collectMemoryInfo(client *ssh.Client, device *models.Device) error {
	memoryInfo := models.MemoryInfo{}

	// First try using dmidecode (requires sudo)
	output, err := c.runCommand(client, "sudo -n dmidecode -t memory 2>/dev/null | grep -A20 'Memory Device'")
	if err == nil && !strings.Contains(output, "sudo") {
		c.Logger.Printf("Using dmidecode for detailed memory information on %s", device.IP)
		if err := c.parseMemoryDmidecode(output, &memoryInfo); err != nil {
			c.Logger.Printf("Error parsing dmidecode output: %v", err)
		}
	} else {
		// Use alternative commands for memory information
		c.Logger.Printf("Dmidecode not available or requires password on %s, using fallback methods", device.IP)
		if err := c.collectMemoryInfoFallback(client, device, &memoryInfo); err != nil {
			return err
		}
	}

	// Update device with collected memory info
	device.MemoryInfo = memoryInfo
	return nil
}

// parseMemoryDmidecode parses the output of dmidecode
func (c *SSHCollector) parseMemoryDmidecode(output string, memoryInfo *models.MemoryInfo) error {
	// Parse memory slots
	sections := strings.Split(output, "Memory Device")
	for i, section := range sections {
		if i == 0 || strings.TrimSpace(section) == "" {
			continue
		}

		slot := models.MemorySlot{
			SlotID: fmt.Sprintf("DIMM%d", i),
		}

		lines := strings.Split(section, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Size:") {
				if strings.Contains(line, "No Module Installed") {
					slot.Occupied = false
					slot.Size = 0
				} else {
					slot.Occupied = true
					sizeStr := strings.TrimSpace(strings.TrimPrefix(line, "Size:"))
					if strings.Contains(sizeStr, "MB") {
						sizeVal := strings.TrimSuffix(sizeStr, " MB")
						size, err := strconv.ParseInt(sizeVal, 10, 64)
						if err == nil {
							slot.Size = size
						}
					} else if strings.Contains(sizeStr, "GB") {
						sizeVal := strings.TrimSuffix(sizeStr, " GB")
						size, err := strconv.ParseInt(sizeVal, 10, 64)
						if err == nil {
							slot.Size = size * 1024 // Convert GB to MB
						}
					}
				}
			} else if strings.HasPrefix(line, "Manufacturer:") {
				slot.Manufacturer = strings.TrimSpace(strings.TrimPrefix(line, "Manufacturer:"))
			} else if strings.HasPrefix(line, "Serial Number:") {
				slot.SerialNumber = strings.TrimSpace(strings.TrimPrefix(line, "Serial Number:"))
			} else if strings.HasPrefix(line, "Type:") {
				slot.Type = strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
			} else if strings.HasPrefix(line, "Speed:") {
				slot.ClockSpeed = strings.TrimSpace(strings.TrimPrefix(line, "Speed:"))
			} else if strings.HasPrefix(line, "Data Width:") {
				slot.Width = strings.TrimSpace(strings.TrimPrefix(line, "Data Width:"))
			}
		}

		memoryInfo.Slots = append(memoryInfo.Slots, slot)
	}

	// Calculate summary information
	memoryInfo.TotalSlots = len(memoryInfo.Slots)
	memoryInfo.OccupiedSlots = 0
	memoryInfo.TotalRAMSize = 0

	for _, slot := range memoryInfo.Slots {
		if slot.Occupied {
			memoryInfo.OccupiedSlots++
			memoryInfo.TotalRAMSize += slot.Size
		}
	}
	memoryInfo.FreeSlots = memoryInfo.TotalSlots - memoryInfo.OccupiedSlots

	return nil
}

// collectMemoryInfoFallback collects memory information using fallback methods
func (c *SSHCollector) collectMemoryInfoFallback(client *ssh.Client, device *models.Device, memoryInfo *models.MemoryInfo) error {
	// Try /proc/meminfo for basic info
	output, err := c.runCommand(client, "cat /proc/meminfo")
	if err != nil {
		return fmt.Errorf("failed to get memory info: %v", err)
	}

	// Parse total RAM
	re := regexp.MustCompile(`MemTotal:\s+(\d+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		ram, err := strconv.ParseInt(matches[1], 10, 64)
		if err == nil {
			memoryInfo.TotalRAMSize = ram / 1024 // Convert KB to MB
		}
	}

	// Try to get basic memory type info using inxi (available on many systems)
	output, err = c.runCommand(client, "inxi -m 2>/dev/null")
	if err == nil && !strings.Contains(output, "command not found") {
		c.Logger.Printf("Using inxi for memory information on %s", device.IP)
		
		// Parse inxi output
		// Try to find memory slots
		slotRe := regexp.MustCompile(`(?i)Device-\d+:.*?(?:\n|$)`)
		slotMatches := slotRe.FindAllString(output, -1)
		
		if len(slotMatches) > 0 {
			for i, slotInfo := range slotMatches {
				slot := models.MemorySlot{
					SlotID:   fmt.Sprintf("DIMM%d", i),
					Occupied: true,
				}
				
				// Try to extract size
				sizeRe := regexp.MustCompile(`(?i)size:\s*(\d+(?:\.\d+)?)\s*(GB|MB|KB)`)
				sizeMatch := sizeRe.FindStringSubmatch(slotInfo)
				if len(sizeMatch) > 2 {
					sizeVal, err := strconv.ParseFloat(sizeMatch[1], 64)
					if err == nil {
						switch strings.ToUpper(sizeMatch[2]) {
						case "GB":
							slot.Size = int64(sizeVal * 1024) // Convert GB to MB
						case "KB":
							slot.Size = int64(sizeVal / 1024) // Convert KB to MB
						case "MB":
							slot.Size = int64(sizeVal)
						}
					}
				}
				
				// Try to extract manufacturer
				mfgRe := regexp.MustCompile(`(?i)vendor:\s*(.+?)(?:\s|$)`)
				mfgMatch := mfgRe.FindStringSubmatch(slotInfo)
				if len(mfgMatch) > 1 {
					slot.Manufacturer = strings.TrimSpace(mfgMatch[1])
				}
				
				// Try to get type
				typeRe := regexp.MustCompile(`(?i)type:\s*(.+?)(?:\s|$)`)
				typeMatch := typeRe.FindStringSubmatch(slotInfo)
				if len(typeMatch) > 1 {
					slot.Type = strings.TrimSpace(typeMatch[1])
				}
				
				// Try to get speed
				speedRe := regexp.MustCompile(`(?i)speed:\s*(.+?)(?:\s|$)`)
				speedMatch := speedRe.FindStringSubmatch(slotInfo)
				if len(speedMatch) > 1 {
					slot.ClockSpeed = strings.TrimSpace(speedMatch[1])
				}
				
				memoryInfo.Slots = append(memoryInfo.Slots, slot)
			}
			
			memoryInfo.TotalSlots = len(slotMatches)
			memoryInfo.OccupiedSlots = len(slotMatches)
			memoryInfo.FreeSlots = 0
		}
	}

	// Try lshw for memory slot info (doesn't require root on some systems)
	if len(memoryInfo.Slots) == 0 {
		output, err = c.runCommand(client, "lshw -class memory 2>/dev/null")
		if err == nil && !strings.Contains(output, "not found") {
			c.Logger.Printf("Using lshw for memory slot information on %s", device.IP)
			
			// Parse memory banks info
			bankSections := regexp.MustCompile(`(?s)\*-memory(?:.+?)(?:\*-|\z)`).FindString(output)
			if bankSections != "" {
				// Try to get memory type
				memTypeRe := regexp.MustCompile(`(?i)description:\s*(.+)`)
				memTypeMatch := memTypeRe.FindStringSubmatch(bankSections)
				generalMemType := ""
				if len(memTypeMatch) > 1 {
					generalMemType = strings.TrimSpace(memTypeMatch[1])
				}
				
				// Try to find banks
				bankRe := regexp.MustCompile(`(?s)\*-bank(?:.+?)(?:\*-|\z)`)
				bankMatches := bankRe.FindAllString(output, -1)
				
				slotCount := 0
				occupiedCount := 0
				
				for i, bank := range bankMatches {
					slotCount++
					slot := models.MemorySlot{
						SlotID: fmt.Sprintf("BANK%d", i),
					}
					
					// Check if occupied
					if strings.Contains(bank, "empty") {
						slot.Occupied = false
					} else {
						slot.Occupied = true
						occupiedCount++
						
						// Try to get size
						sizeRe := regexp.MustCompile(`size:\s*(\d+)([GMK]?)B`)
						sizeMatch := sizeRe.FindStringSubmatch(bank)
						if len(sizeMatch) > 2 {
							sizeVal, err := strconv.ParseInt(sizeMatch[1], 10, 64)
							if err == nil {
								switch sizeMatch[2] {
								case "G":
									slot.Size = sizeVal * 1024 // GB to MB
								case "K":
									slot.Size = sizeVal / 1024 // KB to MB
								default:
									slot.Size = sizeVal // Already MB
								}
							}
						}
						
						// Try to get manufacturer
						mfgRe := regexp.MustCompile(`vendor:\s*(.+)`)
						mfgMatch := mfgRe.FindStringSubmatch(bank)
						if len(mfgMatch) > 1 {
							slot.Manufacturer = strings.TrimSpace(mfgMatch[1])
						}
						
						// Try to get product/serial
						serialRe := regexp.MustCompile(`(?:product|serial):\s*(.+)`)
						serialMatch := serialRe.FindStringSubmatch(bank)
						if len(serialMatch) > 1 {
							slot.SerialNumber = strings.TrimSpace(serialMatch[1])
						}
						
						// Try to get clock speed
						clockRe := regexp.MustCompile(`clock:\s*(\d+)([GMK]?)Hz`)
						clockMatch := clockRe.FindStringSubmatch(bank)
						if len(clockMatch) > 2 {
							clockVal := clockMatch[1]
							switch clockMatch[2] {
							case "G":
								slot.ClockSpeed = clockVal + " GHz"
							case "M":
								slot.ClockSpeed = clockVal + " MHz"
							case "K":
								slot.ClockSpeed = clockVal + " KHz"
							default:
								slot.ClockSpeed = clockVal + " Hz"
							}
						}
						
						// Try to get width
						widthRe := regexp.MustCompile(`width:\s*(\d+)\s*bits`)
						widthMatch := widthRe.FindStringSubmatch(bank)
						if len(widthMatch) > 1 {
							slot.Width = widthMatch[1] + " bits"
						}
						
						// Try to get memory type from description
						typeRe := regexp.MustCompile(`description:\s*(.+)`)
						typeMatch := typeRe.FindStringSubmatch(bank)
						if len(typeMatch) > 1 {
							bankDesc := strings.TrimSpace(typeMatch[1])
							if strings.Contains(bankDesc, "DDR") {
								slot.Type = bankDesc
							} else if generalMemType != "" {
								slot.Type = generalMemType
							}
						} else if generalMemType != "" {
							slot.Type = generalMemType
						}
					}
					
					memoryInfo.Slots = append(memoryInfo.Slots, slot)
				}
				
				if slotCount > 0 {
					memoryInfo.TotalSlots = slotCount
					memoryInfo.OccupiedSlots = occupiedCount
					memoryInfo.FreeSlots = slotCount - occupiedCount
				}
			}
		}
	}

	// If still no slots, try free command as absolute fallback
	if len(memoryInfo.Slots) == 0 {
		output, err = c.runCommand(client, "free -m")
		if err == nil {
			// Parse free output to get basic memory info
			memRe := regexp.MustCompile(`Mem:\s+(\d+)`)
			memMatch := memRe.FindStringSubmatch(output)
			if len(memMatch) > 1 {
				totalMem, err := strconv.ParseInt(memMatch[1], 10, 64)
				if err == nil {
					// Update total RAM size if not already set
					if memoryInfo.TotalRAMSize == 0 {
						memoryInfo.TotalRAMSize = totalMem
					}
					
					// Create a generic slot with the total RAM
					slot := models.MemorySlot{
						SlotID:   "TOTAL",
						Size:     totalMem,
						Occupied: true,
						Type:     "Unknown",
					}
					
					// Try to guess more information
					cpuOutput, err := c.runCommand(client, "cat /proc/cpuinfo")
					if err == nil {
						// Try to determine memory type based on CPU generation
						if strings.Contains(cpuOutput, "AMD") {
							slot.Type = "DDR4" // Most modern AMD CPUs use DDR4
						} else if strings.Contains(cpuOutput, "12th Gen") || strings.Contains(cpuOutput, "13th Gen") {
							slot.Type = "DDR5" // 12th/13th gen Intel likely uses DDR5
						} else if strings.Contains(cpuOutput, "11th Gen") || strings.Contains(cpuOutput, "10th Gen") {
							slot.Type = "DDR4" // 10th/11th gen Intel uses DDR4
						}
					}
					
					memoryInfo.Slots = append(memoryInfo.Slots, slot)
					memoryInfo.TotalSlots = 1
					memoryInfo.OccupiedSlots = 1
					memoryInfo.FreeSlots = 0
				}
			}
		}
	}
	
	// If we couldn't get slot counts any other way, make some estimates
	if memoryInfo.TotalSlots == 0 && len(memoryInfo.Slots) > 0 {
		memoryInfo.TotalSlots = len(memoryInfo.Slots)
		memoryInfo.OccupiedSlots = len(memoryInfo.Slots)
		memoryInfo.FreeSlots = 0
	}
	
	// Ensure memory total size is set if we have slot information
	if memoryInfo.TotalRAMSize == 0 && len(memoryInfo.Slots) > 0 {
		var total int64
		for _, slot := range memoryInfo.Slots {
			total += slot.Size
		}
		memoryInfo.TotalRAMSize = total
	}

	return nil
}

// runCommand executes a command on the remote system
func (c *SSHCollector) runCommand(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to run command: %v", err)
	}

	return string(output), nil
} 