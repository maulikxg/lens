package discovery

import (
	"fmt"
	"log"
	"sync"

	"github.com/netdisco/netdisco/internal/collector"
	"github.com/netdisco/netdisco/internal/models"
	"github.com/netdisco/netdisco/internal/utils"
)

// CollectDeviceInfo collects detailed information from discovered devices
func CollectDeviceInfo(devices []models.Device, config *models.Config, logger *log.Logger) ([]models.Device, error) {
	logger.Printf("Starting to collect detailed information from %d devices", len(devices))
	
	// Create a channel to receive results
	results := make(chan models.Device, len(devices))
	
	// Create a wait group to track goroutines
	var wg sync.WaitGroup
	
	// Create a semaphore to limit concurrency
	semaphore := make(chan struct{}, config.Concurrency)
	
	// Start collection for each reachable device
	for _, device := range devices {
		if !device.Reachable {
			// Skip unreachable devices
			results <- device
			continue
		}
		
		// For unknown device types, try more advanced OS detection
		if device.DeviceType == models.DeviceTypeUnknown && len(device.OpenPorts) > 0 {
			device.DeviceType = utils.DetectRemoteOSType(device.IP, config.Timeout)
			logger.Printf("Advanced OS detection for %s: %s", device.IP, device.DeviceType)
		}
		
		// Skip devices that still have unknown type
		if device.DeviceType == models.DeviceTypeUnknown {
			logger.Printf("Skipping device %s: unknown device type", device.IP)
			device.ScanErrors = append(device.ScanErrors, "Unable to determine device type")
			results <- device
			continue
		}
		
		wg.Add(1)
		go func(d models.Device) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Create collector for the device type
			c, err := collector.NewCollector(config, logger, d.DeviceType)
			if err != nil {
				logger.Printf("Failed to create collector for device %s: %v", d.IP, err)
				d.ScanErrors = append(d.ScanErrors, fmt.Sprintf("Collector error: %v", err))
				results <- d
				return
			}
			
			// Collect information
			logger.Printf("Collecting information from %s (%s)", d.IP, d.DeviceType)
			if err := c.Collect(&d); err != nil {
				logger.Printf("Failed to collect information from device %s: %v", d.IP, err)
				d.ScanErrors = append(d.ScanErrors, fmt.Sprintf("Collection error: %v", err))
			}
			
			// Send the result
			results <- d
		}(device)
	}
	
	// Wait for all goroutines to complete
	wg.Wait()
	close(results)
	
	// Collect results
	var collectedDevices []models.Device
	for device := range results {
		collectedDevices = append(collectedDevices, device)
	}
	
	logger.Printf("Information collection completed for %d devices", len(collectedDevices))
	return collectedDevices, nil
} 