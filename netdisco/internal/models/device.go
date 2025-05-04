package models

import "time"

// DeviceType represents the type of discovered device
type DeviceType string

const (
	DeviceTypeLinux   DeviceType = "linux"
	DeviceTypeWindows DeviceType = "windows"
	DeviceTypeUnknown DeviceType = "unknown"
)

// Device represents a discovered network device
type Device struct {
	IP          string    `json:"ip"`
	Hostname    string    `json:"hostname"`
	MAC         string    `json:"mac"`
	DeviceType  DeviceType `json:"device_type"`
	Reachable   bool      `json:"reachable"`
	OpenPorts   []int     `json:"open_ports"`
	LastScan    time.Time `json:"last_scan"`
	OSInfo      OSInfo    `json:"os_info,omitempty"`
	HardwareInfo HardwareInfo `json:"hardware_info,omitempty"`
	NetworkInfo  NetworkInfo  `json:"network_info,omitempty"`
	MemoryInfo   MemoryInfo   `json:"memory_info,omitempty"`
	ScanErrors   []string  `json:"scan_errors,omitempty"`
}

// OSInfo contains operating system information
type OSInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Distribution string `json:"distribution,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	Architecture string `json:"architecture"`
}

// HardwareInfo contains hardware specifications
type HardwareInfo struct {
	CPUModel     string `json:"cpu_model"`
	CPUCores     int    `json:"cpu_cores"`
	TotalRAM     int64  `json:"total_ram_mb"` // In MB
	TotalDiskSpace int64 `json:"total_disk_space_gb"` // In GB
	FreeDiskSpace int64 `json:"free_disk_space_gb"` // In GB
}

// NetworkInterface represents a network interface on the device
type NetworkInterface struct {
	Name   string `json:"name"`
	MAC    string `json:"mac"`
	IP     string `json:"ip"`
	Netmask string `json:"netmask"`
	Status string `json:"status"` // up/down
}

// NetworkInfo contains network configuration information
type NetworkInfo struct {
	Interfaces []NetworkInterface `json:"interfaces"`
	Hostname   string             `json:"hostname"`
	Domain     string             `json:"domain,omitempty"`
}

// MemorySlot represents a physical memory slot
type MemorySlot struct {
	SlotID       string `json:"slot_id"`
	Manufacturer string `json:"manufacturer,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	Size         int64  `json:"size_mb,omitempty"` // In MB
	Type         string `json:"type,omitempty"`
	ClockSpeed   string `json:"clock_speed,omitempty"`
	Width        string `json:"width,omitempty"`
	Occupied     bool   `json:"occupied"`
}

// MemoryInfo contains detailed memory information
type MemoryInfo struct {
	TotalSlots     int         `json:"total_slots"`
	OccupiedSlots  int         `json:"occupied_slots"`
	FreeSlots      int         `json:"free_slots"`
	TotalRAMSize   int64       `json:"total_ram_size_mb"` // In MB
	Slots          []MemorySlot `json:"slots,omitempty"`
} 