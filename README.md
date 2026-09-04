# NetScope — TCP Port Scanner

NetScope is a lightweight TCP port scanner built with Python.

The project was created as a cybersecurity learning project to understand TCP connections, network ports, sockets, DNS resolution, timeouts, and concurrent network scanning.

## Features

* Scan an IP address or domain name
* Resolve domain names to IP addresses
* Scan a custom TCP port range
* Configurable connection timeout
* Concurrent port scanning
* Display detected open ports
* Simple command-line interface
* No external Python packages required

## How It Works

The scanner uses Python's built-in `socket` module to attempt TCP connections to the specified ports.

For a domain:

```text
Domain
   ↓
DNS Resolution
   ↓
IP Address
   ↓
TCP Connection Attempts
   ↓
Open Ports
```

For each port, the scanner attempts to establish a TCP connection.

If the connection succeeds, the port is reported as open.

## Requirements

* Python 3
* Git (only required for development/version control)
* Linux, macOS, or Windows

No external Python dependencies are required.

## Installation

Clone the repository:

```bash
git clone https://github.com/iammaneshkumar/netscope.git
cd netscope
```

Run the scanner:

```bash
python3 scanner.py
```

## Usage

The program asks for:

1. Target IP address or domain
2. Starting port
3. Ending port
4. Connection timeout

Example:

```text
Enter IP address or domain: scanme.nmap.org
Enter starting port: 1
Enter ending port: 100
Enter timeout in seconds (e.g. 0.5): 0.5

Target: scanme.nmap.org
IP Address: <resolved-ip>
Scanning ports 1-100...

[+] Port 22 is OPEN
[+] Port 80 is OPEN

Scan completed.

Open ports:
  22
  80
```

Results can vary depending on the target and network conditions.

## Project Status

### Version 1.0

* [x] IP address support
* [x] Domain name support
* [x] DNS resolution
* [x] TCP port scanning
* [x] Custom port ranges
* [x] Configurable timeout
* [x] Concurrent scanning
* [x] Open-port reporting

### Planned Features

* [ ] Improved scan result handling
* [ ] Service identification
* [ ] Banner grabbing
* [ ] Version detection
* [ ] JSON/CSV reports
* [ ] Scan history
* [ ] Tkinter GUI
* [ ] Unit tests
* [ ] Optional Nmap integration

## Learning Objectives

This project is designed to provide practical experience with:

* TCP/IP networking
* TCP ports
* Python sockets
* DNS resolution
* Network timeouts
* Concurrent programming
* Basic network security concepts
* Git and GitHub

## Responsible Use

This tool should only be used against systems that you own or have explicit permission to test.

Do not scan systems or networks without authorization.

## License

MIT License
