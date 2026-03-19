# G-scan

Intranet scanning tool — host discovery, port scanning, service brute-force, vulnerability detection, web fingerprinting. IPv4/IPv6 support.

## Features

- **Discovery** — ICMP/ping alive detection with bloom filter dedup & rate limiting
- **Port scan** — adaptive thread pool, port spraying, retry on resource exhaustion, ~150 default ports
- **Brute-force** — SSH, SMB, RDP, MySQL, MSSQL, PostgreSQL, Redis, Oracle, FTP, LDAP, VNC, etc.
- **Vulnerabilities** — MS17-010, SMBGhost, Redis unauthorized, web POCs (xray-compatible)
- **Web** — title grabbing, CMS fingerprinting, favicon hash (mmh3/MD5, Shodan-compatible)
- **Exploitation** — Redis public key write, cron shell, SSH command exec, WMI exec
- **SMB/FTP** — anonymous access detection with share/file listing

## Quick Start

```bash
# Basic scan
./fscan -h 192.168.1.0/24

# Scan with web POC
./fscan -h 192.168.1.0/24 -poc

# Skip alive detection, enable POC
./fscan -h 10.0.0.0/8 -np -poc

# SSH command execution
./fscan -h 192.168.1.0/24 -c "whoami"

# SMB hash pass-the-hash
./fscan -h 192.168.1.0/24 -m smb2 -user admin -hash xxxxx

# Import targets from file
./fscan -hf targets.txt

# Through SOCKS5 proxy
./fscan -h 192.168.1.0/24 -socks5 127.0.0.1:1080
```

## Build

```bash
go build -ldflags="-s -w" -trimpath .
```

## Disclaimer

For **authorized security testing only**. You are solely responsible for compliance with applicable laws. No warranties provided.
