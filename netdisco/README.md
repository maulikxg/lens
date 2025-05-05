# NetDisco: Network Discovery and Inventory Tool

NetDisco is a production-grade network discovery and inventory tool written in Go. It discovers devices on a network, identifies operating systems, authenticates to these devices, collects detailed system information, and outputs structured data.

## Features

- **Device Discovery**: Scans networks by IP address, IP range, or CIDR notation
- **OS Identification**: Detects Linux (SSH) and Windows (WinRM) systems
- **Authentication**: Supports SSH for Linux and WinRM for Windows
- **Information Collection**: Gathers detailed OS, hardware, network, and memory information
- **Concurrency Control**: Configurable concurrency and timeouts
- **Output Options**: Structured JSON output with summary and detailed device files
- **API Mode**: RESTful API for credential management, discovery profiles, and job management
- **Profile Management**: Create and store credential and discovery profiles

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

NetDisco can be run in two modes:

- **CLI Mode**: Command-line interface for one-off scans
- **API Mode**: HTTP API server for creating credentials, discovery profiles, and running jobs

### CLI Mode

```bash
# Basic usage with minimum parameters
./netdisco cli --target 192.168.1.0/24 --ssh-user admin --ssh-pass password --win-user administrator --win-pass password

# Scan a single IP
./netdisco cli --target 192.168.1.10 --ssh-user admin --ssh-pass password

# Scan an IP range
./netdisco cli --target 192.168.1.10-192.168.1.20 --ssh-user admin --ssh-pass password

# Customize concurrency and timeout
./netdisco cli --target 192.168.1.0/24 --concurrency 20 --timeout 10 --ssh-user admin --ssh-pass password

# Specify custom output directory
./netdisco cli --target 192.168.1.0/24 --output /path/to/output --ssh-user admin --ssh-pass password
```

### API Mode

```bash
# Start API server with default settings (localhost:8080)
./netdisco api

# Start API server on specific host and port
./netdisco api --host 0.0.0.0 --port 8000

# Specify custom data directory
./netdisco api --data-dir /path/to/data

# Enable verbose logging
./netdisco api --verbose
```

## Command Line Options

### CLI Mode Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target` | Target IP, IP range, or CIDR notation (required) | |
| `--output` | Directory to store results | `./output` |
| `--concurrency` | Maximum number of concurrent operations | 10 |
| `--timeout` | Timeout in seconds for network operations | 5 |
| `--ssh-user` | SSH username for Linux systems | |
| `--ssh-pass` | SSH password for Linux systems | |
| `--ssh-port` | SSH port for Linux systems | 22 |
| `--ssh-alt-users` | Comma-separated list of alternative SSH usernames to try | |
| `--win-user` | WinRM username for Windows systems | |
| `--win-pass` | WinRM password for Windows systems | |
| `--win-port` | WinRM port for Windows systems | 5985 |
| `--verbose` | Enable verbose logging | false |
| `--debug` | Enable debug mode with additional error information | false |

### API Mode Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | Host for the API server | localhost |
| `--port` | Port for the API server | 8080 |
| `--data-dir` | Directory to store API data | ./data |
| `--verbose` | Enable verbose logging | false |

## API Documentation

The API mode provides a RESTful API for managing credential profiles, discovery profiles, and discovery jobs.

### Credential Profiles

#### List all credential profiles
```
GET /api/credentials
```

#### Create a credential profile
```
POST /api/credentials
```

Request body example:
```json
{
  "name": "Linux Server",
  "description": "Credentials for Linux servers",
  "type": "linux",
  "ssh_username": "admin",
  "ssh_password": "password",
  "ssh_port": 22
}
```

#### Get a credential profile
```
GET /api/credentials/{id}
```

#### Update a credential profile
```
PUT /api/credentials/{id}
```

#### Delete a credential profile
```
DELETE /api/credentials/{id}
```

### Discovery Profiles

#### List all discovery profiles
```
GET /api/discovery
```

#### Create a discovery profile
```
POST /api/discovery
```

Request body example:
```json
{
  "name": "Network Scan",
  "description": "Scan the network",
  "target_type": "cidr",
  "target": "192.168.1.0/24",
  "credential_ids": ["credential-id-1", "credential-id-2"],
  "concurrency": 10,
  "timeout": 5
}
```

#### Get a discovery profile
```
GET /api/discovery/{id}
```

#### Update a discovery profile
```
PUT /api/discovery/{id}
```

#### Delete a discovery profile
```
DELETE /api/discovery/{id}
```

#### Run a discovery profile
```
POST /api/discovery/{id}/run
```

### Discovery Jobs

#### List all discovery jobs
```
GET /api/jobs
```

#### Get a discovery job
```
GET /api/jobs/{id}
```

#### Cancel a discovery job
```
POST /api/jobs/{id}/cancel
```

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

- In CLI mode, credentials are specified on the command line, which may be visible in process listings
- API server credentials are stored in files on disk (consider using encryption for production)
- No support for SSH key authentication yet (only username/password)
- WinRM connections do not verify SSL certificates
- API server has no authentication (consider adding authentication for production)

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 