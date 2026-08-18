# NetPulse

NetPulse is an advanced local network scanner that discovers devices, identifies their manufacturer and friendly names (mDNS/SSDP), detects ARP spoofing, and optionally scans for open ports — all with color-coded output and SQLite storage.

## Features

- ARP scanning of local subnets
- Device identification: vendor, hostname, friendly name (mDNS/SSDP)
- Whitelist/blacklist with wildcard support
- ARP spoofing detection
- Optional TCP port scanning
- Colour-coded console output
- SQLite database for history
- Saves discovered IPs to a text file

## Installation

```bash
pip install -r requirements.txt
