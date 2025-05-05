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
	c.Logger.Printf("Starting memory info fallback collection for %s", device.IP)
	
	// Try /proc/meminfo for basic info
	output, err := c.runCommand(client, "cat /proc/meminfo")
	if err != nil {
		c.Logger.Printf("Failed to get /proc/meminfo: %v", err)
		return fmt.Errorf("failed to get memory info: %v", err)
	}

	// Parse total RAM
	re := regexp.MustCompile(`MemTotal:\s+(\d+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		ram, err := strconv.ParseInt(matches[1], 10, 64)
		if err == nil {
			memoryInfo.TotalRAMSize = ram / 1024 // Convert KB to MB
			c.Logger.Printf("Found total RAM: %d MB", memoryInfo.TotalRAMSize)
		}
	}

	// Try dmidecode without sudo (might work in some containers or systems)
	c.Logger.Printf("Trying dmidecode without sudo...")
	output, err = c.runCommand(client, "dmidecode -t memory 2>/dev/null | grep -A30 'Memory Device' | grep -v 'dmidecode'")
	if err == nil && !strings.Contains(output, "command not found") && !strings.Contains(output, "Permission denied") {
		c.Logger.Printf("Using dmidecode without sudo for memory information on %s", device.IP)
		
		if err := c.parseMemoryDmidecode(output, memoryInfo); err != nil {
			c.Logger.Printf("Error parsing dmidecode output: %v", err)
		} else if len(memoryInfo.Slots) > 0 {
			c.Logger.Printf("Successfully parsed dmidecode output, found %d memory slots", len(memoryInfo.Slots))
			return nil
		}
	} else {
		c.Logger.Printf("dmidecode failed or not available: %v", err)
	}

	// Try to get detailed memory info using sysfs
	c.Logger.Printf("Trying sysfs memory info...")
	output, err = c.runCommand(client, "find /sys/devices/system/memory/memory*/block_size_bytes -type f 2>/dev/null | head -1")
	if err == nil && strings.TrimSpace(output) != "" {
		c.Logger.Printf("Found sysfs memory information on %s", device.IP)
		
		// Try to count memory blocks
		blockCount, err := c.runCommand(client, "ls -1 /sys/devices/system/memory/ | grep -c 'memory[0-9]'")
		if err == nil {
			count, err := strconv.Atoi(strings.TrimSpace(blockCount))
			if err == nil && count > 0 {
				c.Logger.Printf("Found %d memory blocks", count)
				// Try to get block size
				blockSizeHex, err := c.runCommand(client, "cat "+strings.TrimSpace(output))
				if err == nil {
					// Convert hex block size to decimal
					blockSizeHex = strings.TrimSpace(blockSizeHex)
					c.Logger.Printf("Found block size (hex): %s", blockSizeHex)
					blockSizeInt, err := strconv.ParseInt(blockSizeHex, 0, 64)
					if err == nil {
						blockSizeMB := blockSizeInt / (1024 * 1024)
						c.Logger.Printf("Block size: %d MB", blockSizeMB)
						
						// Create memory slots based on memory blocks
						for i := 0; i < count; i++ {
							slotID := fmt.Sprintf("BLOCK%d", i)
							
							// Check if this memory block is online
							onlineStatus, err := c.runCommand(client, fmt.Sprintf("cat /sys/devices/system/memory/memory%d/online 2>/dev/null || echo 1", i))
							if err != nil || strings.TrimSpace(onlineStatus) == "1" {
								slot := models.MemorySlot{
									SlotID:   slotID,
									Size:     blockSizeMB,
									Occupied: true,
									Type:     "System RAM",
								}
								memoryInfo.Slots = append(memoryInfo.Slots, slot)
							}
						}
						
						if len(memoryInfo.Slots) > 0 {
							c.Logger.Printf("Created %d memory slots from sysfs", len(memoryInfo.Slots))
							memoryInfo.TotalSlots = count
							memoryInfo.OccupiedSlots = len(memoryInfo.Slots)
							memoryInfo.FreeSlots = count - len(memoryInfo.Slots)
							return nil
						}
					} else {
						c.Logger.Printf("Failed to parse block size: %v", err)
					}
				} else {
					c.Logger.Printf("Failed to read block size: %v", err)
				}
			} else {
				c.Logger.Printf("Failed to parse block count: %v", err)
			}
		} else {
			c.Logger.Printf("Failed to get block count: %v", err)
		}
	} else {
		c.Logger.Printf("Sysfs memory info not available: %v", err)
	}

	// Try lscpu for detailed CPU information which can help determine memory type
	c.Logger.Printf("Trying lscpu...")
	cpuInfo, err := c.runCommand(client, "lscpu")
	cpuModel := ""
	if err == nil {
		modelNameRe := regexp.MustCompile(`Model name:\s*(.+)`)
		modelMatch := modelNameRe.FindStringSubmatch(cpuInfo)
		if len(modelMatch) > 1 {
			cpuModel = strings.TrimSpace(modelMatch[1])
			c.Logger.Printf("Found CPU model: %s", cpuModel)
		}
	} else {
		c.Logger.Printf("lscpu failed: %v", err)
	}

	// Try to get basic memory type info using inxi (available on many systems)
	c.Logger.Printf("Trying inxi...")
	output, err = c.runCommand(client, "inxi -m 2>/dev/null")
	if err == nil && !strings.Contains(output, "command not found") {
		c.Logger.Printf("Using inxi for memory information on %s", device.IP)
		
		// Parse inxi output
		// Try to find memory slots
		slotRe := regexp.MustCompile(`(?i)Device-\d+:.*?(?:\n|$)`)
		slotMatches := slotRe.FindAllString(output, -1)
		
		if len(slotMatches) > 0 {
			c.Logger.Printf("Found %d memory slots with inxi", len(slotMatches))
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
						c.Logger.Printf("Slot %d size: %d MB", i, slot.Size)
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
					c.Logger.Printf("Slot %d type: %s", i, slot.Type)
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
	} else {
		c.Logger.Printf("inxi not available: %v", err)
	}

	// Try lshw for memory slot info (doesn't require root on some systems)
	if len(memoryInfo.Slots) == 0 {
		c.Logger.Printf("Trying lshw...")
		output, err = c.runCommand(client, "lshw -class memory 2>/dev/null")
		if err == nil && !strings.Contains(output, "not found") {
			c.Logger.Printf("Using lshw for memory slot information on %s", device.IP)
			
			// Parse memory banks info
			bankSections := regexp.MustCompile(`(?s)\*-memory(?:.+?)(?:\*-|\z)`).FindString(output)
			if bankSections != "" {
				c.Logger.Printf("Found memory banks section in lshw output")
				// Try to get memory type
				memTypeRe := regexp.MustCompile(`(?i)description:\s*(.+)`)
				memTypeMatch := memTypeRe.FindStringSubmatch(bankSections)
				generalMemType := ""
				if len(memTypeMatch) > 1 {
					generalMemType = strings.TrimSpace(memTypeMatch[1])
					c.Logger.Printf("Found general memory type: %s", generalMemType)
				}
				
				// Try to find banks
				bankRe := regexp.MustCompile(`(?s)\*-bank(?:.+?)(?:\*-|\z)`)
				bankMatches := bankRe.FindAllString(output, -1)
				
				if len(bankMatches) > 0 {
					c.Logger.Printf("Found %d banks in lshw output", len(bankMatches))
				}
				
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
						c.Logger.Printf("Bank %d is empty", i)
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
								c.Logger.Printf("Bank %d size: %d MB", i, slot.Size)
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
								c.Logger.Printf("Bank %d type from description: %s", i, slot.Type)
							} else if generalMemType != "" {
								slot.Type = generalMemType
								c.Logger.Printf("Bank %d using general memory type: %s", i, slot.Type)
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
					c.Logger.Printf("Created %d slots from lshw (%d occupied, %d free)", 
						memoryInfo.TotalSlots, memoryInfo.OccupiedSlots, memoryInfo.FreeSlots)
				}
			} else {
				c.Logger.Printf("No memory banks section found in lshw output")
			}
		} else {
			c.Logger.Printf("lshw not available: %v", err)
		}
	}

	// Try to guess memory slots using memory size and common configurations
	if len(memoryInfo.Slots) == 0 && memoryInfo.TotalRAMSize > 0 {
		c.Logger.Printf("Using memory size heuristics for %s with total RAM: %d MB", 
			device.IP, memoryInfo.TotalRAMSize)
		
		memoryType := "Unknown"
		
		// Try to guess memory type from CPU model
		if cpuModel != "" {
			if strings.Contains(cpuModel, "12th Gen") || strings.Contains(cpuModel, "13th Gen") {
				memoryType = "DDR5"
			} else if strings.Contains(cpuModel, "11th Gen") || strings.Contains(cpuModel, "10th Gen") || 
					strings.Contains(cpuModel, "9th Gen") || strings.Contains(cpuModel, "8th Gen") {
				memoryType = "DDR4"
			} else if strings.Contains(cpuModel, "7th Gen") || strings.Contains(cpuModel, "6th Gen") || 
					strings.Contains(cpuModel, "5th Gen") {
				memoryType = "DDR3"
			}
			c.Logger.Printf("Guessed memory type from CPU: %s", memoryType)
		}
		
		// Guess likely slot configuration based on total RAM
		totalRAM := memoryInfo.TotalRAMSize
		var slotSizes []int64
		
		// Common configurations: 2 slots, 4 slots or 8 slots with equal distribution
		if totalRAM % 2 == 0 {
			if totalRAM <= 4096 { // <= 4GB - likely 1 or 2 slots
				if totalRAM <= 2048 {
					slotSizes = []int64{totalRAM} // Single slot
					c.Logger.Printf("Guessing single slot for %d MB RAM", totalRAM)
				} else {
					slotSizes = []int64{totalRAM / 2, totalRAM / 2} // 2 equal slots
					c.Logger.Printf("Guessing 2 equal slots of %d MB each", totalRAM/2)
				}
			} else if totalRAM <= 32768 { // <= 32GB - likely 2 or 4 slots
				if totalRAM % 4 == 0 {
					slotSize := totalRAM / 4
					slotSizes = []int64{slotSize, slotSize, slotSize, slotSize} // 4 equal slots
					c.Logger.Printf("Guessing 4 equal slots of %d MB each", slotSize)
				} else {
					slotSize := totalRAM / 2
					slotSizes = []int64{slotSize, slotSize} // 2 equal slots
					c.Logger.Printf("Guessing 2 equal slots of %d MB each", slotSize)
				}
			} else { // > 32GB - likely 4 or 8 slots
				if totalRAM % 8 == 0 {
					slotSize := totalRAM / 8
					slotSizes = make([]int64, 8)
					for i := 0; i < 8; i++ {
						slotSizes[i] = slotSize
					}
					c.Logger.Printf("Guessing 8 equal slots of %d MB each", slotSize)
				} else if totalRAM % 4 == 0 {
					slotSize := totalRAM / 4
					slotSizes = []int64{slotSize, slotSize, slotSize, slotSize} // 4 equal slots
					c.Logger.Printf("Guessing 4 equal slots of %d MB each", slotSize)
				} else {
					slotSize := totalRAM / 2
					slotSizes = []int64{slotSize, slotSize} // 2 equal slots
					c.Logger.Printf("Guessing 2 equal slots of %d MB each", slotSize)
				}
			}
		} else {
			// Odd total RAM - likely mixed slot sizes, make a reasonable guess
			if totalRAM <= 3072 { // <= 3GB
				slotSizes = []int64{totalRAM} // Single slot
				c.Logger.Printf("Guessing single slot for %d MB RAM", totalRAM)
			} else if totalRAM <= 6144 { // <= 6GB
				// Like 3GB and 1GB or something similar
				slotSizes = []int64{totalRAM * 2 / 3, totalRAM / 3}
				c.Logger.Printf("Guessing 2 mixed slots of %d MB and %d MB", 
					totalRAM * 2 / 3, totalRAM / 3)
			} else if totalRAM <= 24576 { // <= 24GB
				// Likely 3 slots or potentially 2 slots with mixed sizes
				if totalRAM % 3 == 0 {
					slotSize := totalRAM / 3
					slotSizes = []int64{slotSize, slotSize, slotSize} // 3 equal slots
					c.Logger.Printf("Guessing 3 equal slots of %d MB each", slotSize)
				} else {
					// Assume 4 slots with 1 empty
					slotSize := totalRAM / 3
					slotSizes = []int64{slotSize, slotSize, slotSize}
					c.Logger.Printf("Guessing 3 equal slots of %d MB each", slotSize)
				}
			} else {
				// For very large odd RAM amounts, assume multiple slots
				slotSize := totalRAM / 3
				slotSizes = []int64{slotSize, slotSize, slotSize} // 3 equal slots as fallback
				c.Logger.Printf("Guessing 3 equal slots of %d MB each for large RAM", slotSize)
			}
		}
		
		// Create memory slots based on our calculated distribution
		for i, size := range slotSizes {
			slot := models.MemorySlot{
				SlotID:     fmt.Sprintf("DIMM%d", i),
				Size:       size,
				Occupied:   true,
				Type:       memoryType,
				ClockSpeed: "Unknown",
			}
			memoryInfo.Slots = append(memoryInfo.Slots, slot)
		}
		
		memoryInfo.TotalSlots = len(slotSizes)
		memoryInfo.OccupiedSlots = len(slotSizes)
		memoryInfo.FreeSlots = 0
		c.Logger.Printf("Created %d memory slots based on heuristics", len(memoryInfo.Slots))
	}

	// If all else fails, create a generic TOTAL slot
	if len(memoryInfo.Slots) == 0 {
		c.Logger.Printf("All previous methods failed, trying free command...")
		output, err = c.runCommand(client, "free -m")
		if err == nil {
			// Parse free output to get basic memory info
			memRe := regexp.MustCompile(`Mem:\s+(\d+)`)
			memMatch := memRe.FindStringSubmatch(output)
			if len(memMatch) > 1 {
				totalMem, err := strconv.ParseInt(memMatch[1], 10, 64)
				if err == nil {
					c.Logger.Printf("Found memory size from free: %d MB", totalMem)
					// Update total RAM size if not already set
					if memoryInfo.TotalRAMSize == 0 {
						memoryInfo.TotalRAMSize = totalMem
					}
					
					// Create memory type based on CPU
					memoryType := "Unknown"
					if cpuModel != "" {
						if strings.Contains(cpuModel, "AMD") {
							memoryType = "DDR4" // Most modern AMD CPUs use DDR4
						} else if strings.Contains(cpuModel, "12th Gen") || strings.Contains(cpuModel, "13th Gen") {
							memoryType = "DDR5" // 12th/13th gen Intel likely uses DDR5
						} else if strings.Contains(cpuModel, "11th Gen") || strings.Contains(cpuModel, "10th Gen") {
							memoryType = "DDR4" // 10th/11th gen Intel uses DDR4
						}
						c.Logger.Printf("Inferred memory type from CPU: %s", memoryType)
					}
					
					// Split memory into reasonable slots based on size
					if totalMem <= 4096 { // <= 4GB
						// Create a single slot
						slot := models.MemorySlot{
							SlotID:   "DIMM0",
							Size:     totalMem,
							Occupied: true,
							Type:     memoryType,
						}
						memoryInfo.Slots = append(memoryInfo.Slots, slot)
						memoryInfo.TotalSlots = 1
						memoryInfo.OccupiedSlots = 1
						memoryInfo.FreeSlots = 0
						c.Logger.Printf("Created single memory slot of %d MB", totalMem)
					} else if totalMem <= 16384 { // <= 16GB
						// Create two equal slots for better visualization
						slotSize := totalMem / 2
						slot1 := models.MemorySlot{
							SlotID:   "DIMM0",
							Size:     slotSize,
							Occupied: true,
							Type:     memoryType,
						}
						slot2 := models.MemorySlot{
							SlotID:   "DIMM1",
							Size:     slotSize,
							Occupied: true,
							Type:     memoryType,
						}
						memoryInfo.Slots = append(memoryInfo.Slots, slot1, slot2)
						memoryInfo.TotalSlots = 2
						memoryInfo.OccupiedSlots = 2
						memoryInfo.FreeSlots = 0
						c.Logger.Printf("Created 2 memory slots of %d MB each", slotSize)
					} else { // > 16GB
						// Create four equal slots for better visualization
						slotSize := totalMem / 4
						for i := 0; i < 4; i++ {
							slot := models.MemorySlot{
								SlotID:   fmt.Sprintf("DIMM%d", i),
								Size:     slotSize,
								Occupied: true,
								Type:     memoryType,
							}
							memoryInfo.Slots = append(memoryInfo.Slots, slot)
						}
						memoryInfo.TotalSlots = 4
						memoryInfo.OccupiedSlots = 4
						memoryInfo.FreeSlots = 0
						c.Logger.Printf("Created 4 memory slots of %d MB each", slotSize)
					}
				} else {
					c.Logger.Printf("Failed to parse memory total: %v", err)
				}
			} else {
				c.Logger.Printf("Failed to match memory total in free output")
			}
		} else {
			c.Logger.Printf("Free command failed: %v", err)
		}
	}
	
	// If we couldn't get slot counts any other way, make some estimates
	if memoryInfo.TotalSlots == 0 && len(memoryInfo.Slots) > 0 {
		memoryInfo.TotalSlots = len(memoryInfo.Slots)
		memoryInfo.OccupiedSlots = len(memoryInfo.Slots)
		memoryInfo.FreeSlots = 0
		c.Logger.Printf("Set slot counts based on number of slots: %d", memoryInfo.TotalSlots)
	}
	
	// Ensure memory total size is set if we have slot information
	if memoryInfo.TotalRAMSize == 0 && len(memoryInfo.Slots) > 0 {
		var total int64
		for _, slot := range memoryInfo.Slots {
			total += slot.Size
		}
		memoryInfo.TotalRAMSize = total
		c.Logger.Printf("Updated total RAM size from slots: %d MB", memoryInfo.TotalRAMSize)
	}

	c.Logger.Printf("Memory info collection complete. Found %d slots with total %d MB RAM", 
		len(memoryInfo.Slots), memoryInfo.TotalRAMSize)
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