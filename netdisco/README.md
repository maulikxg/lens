# NetDisco: Network Discovery and Inventory Tool

NetDisco is a production-grade network discovery and inventory tool written in Go. It discovers devices on a network, identifies operating systems, authenticates to these devices, collects detailed system information, and outputs structured data.

## Features

- **Device Discovery**: Scans networks by IP address, IP range, or CIDR notation
- **OS Identification**: Detects Linux (SSH) and Windows (WinRM) systems
- **Authentication**: Supports SSH for Linux and WinRM for Windows
- **Information Collection**: Gathers detailed OS, hardware, network, and memory information
- **Concurrency Control**: Configurable concurrency and timeouts
- **Output Options**: Structured JSON output with summary and detailed device files

## Installation

### Using Go

```bash
go install github.com/netdisco/netdisco/cmd/netdisco@latest
```

### Building from Source

```bash
git clone https://github.com/netdisco/netdisco.git
cd netdisco
go build -o netdisco ./cmd/netdisco
```

## Usage

```bash
# Basic usage with minimum parameters
./netdisco --target 192.168.1.0/24 --ssh-user admin --ssh-pass password --win-user administrator --win-pass password

# Scan a single IP
./netdisco --target 192.168.1.10 --ssh-user admin --ssh-pass password

# Scan an IP range
./netdisco --target 192.168.1.10-192.168.1.20 --ssh-user admin --ssh-pass password

# Customize concurrency and timeout
./netdisco --target 192.168.1.0/24 --concurrency 20 --timeout 10 --ssh-user admin --ssh-pass password

# Specify custom output directory
./netdisco --target 192.168.1.0/24 --output /path/to/output --ssh-user admin --ssh-pass password
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target` | Target IP, IP range, or CIDR notation (required) | |
| `--output` | Directory to store results | `./output` |
| `--concurrency` | Maximum number of concurrent operations | 10 |
| `--timeout` | Timeout in seconds for network operations | 5 |
| `--ssh-user` | SSH username for Linux systems | |
| `--ssh-pass` | SSH password for Linux systems | |
| `--ssh-port` | SSH port for Linux systems | 22 |
| `--win-user` | WinRM username for Windows systems | |
| `--win-pass` | WinRM password for Windows systems | |
| `--win-port` | WinRM port for Windows systems | 5985 |
| `--verbose` | Enable verbose logging | false |

## Output Format

NetDisco produces a summary file and individual device files in JSON format:

### Summary File (summary.json)

Contains an overview of all discovered devices and counts by type.

### Device Files

Each reachable device gets its own JSON file with detailed information:

- Basic device information (IP, hostname, MAC)
- OS details (name, version, distribution, kernel)
- Hardware specifications (CPU, RAM, disk space)
- Network configuration (interfaces, IPs, MACs)
- Memory details (slots, size, type, speed)

## Security Considerations

- Credentials are specified on the command line, which may be visible in process listings
- No support for SSH key authentication yet (only username/password)
- WinRM connections do not verify SSL certificates

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 