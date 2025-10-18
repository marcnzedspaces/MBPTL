# MBPTL Kali Linux Attack Container

This is a pre-configured Kali Linux container with all the tools needed for the Most Basic Penetration Testing Labs (MBPTL).

## Credentials
- **Username:** `kali`
- **Password:** `kali`
- **Sudo:** Enabled with no password required

## Pre-installed Tools

### Core System Tools
- **sudo** - Execute commands with elevated privileges
- **bash** - Shell environment
- **vim/nano** - Text editors
- **openssh-server** - SSH server for remote access

### Network & Reconnaissance Tools
- **nmap** - Port scanning and service enumeration
- **curl** - HTTP request testing and API interaction
- **wget** - File downloads and HTTP requests
- **netcat (nc)** - Network connections and reverse shells
- **ping** - Network connectivity testing
- **ip** - Network interface management
- **ifconfig** - Network interface configuration

### File Analysis Tools
- **file** - Determine file types
- **strings** - Extract readable strings from binaries
- **objdump** - Disassemble and analyze binaries

### Programming & Scripting
- **python3** - Python interpreter
- **pip3** - Python package manager
- **git** - Version control and tool downloads

### Python Libraries
- **pwntools** - Binary exploitation framework

### Penetration Testing Tools (in ~/tools/)

#### Directory/File Enumeration
- **dirsearch** - `~/tools/dirsearch/`
  - Usage: `python3 ~/tools/dirsearch/dirsearch.py -u <URL>`
  - Alias: `dirsearch -u <URL>`

#### SQL Injection
- **sqlmap** - `~/tools/sqlmap/`
  - Usage: `python3 ~/tools/sqlmap/sqlmap.py -u <URL>`
  - Alias: `sqlmap -u <URL>`

#### Privilege Escalation
- **LinPEAS** - Download script available
  - Run: `~/tools/get-linpeas.sh` to download
  - Will be saved to: `~/tools/linpeas.sh`

## Directory Structure

```
/home/kali/
├── tools/                    # Penetration testing tools
│   ├── dirsearch/           # Directory enumeration tool
│   ├── sqlmap/              # SQL injection tool
│   ├── get-linpeas.sh       # Script to download LinPEAS
│   └── linpeas.sh           # (after running get-linpeas.sh)
├── workspace/               # Working directory for your files
└── scripts/                 # Custom scripts
```

## Quick Start

### Access the Container
```bash
# Interactive shell as kali user
docker exec -it attacker-kali bash

# Or as root
docker exec -it -u root attacker-kali bash
```

### Run Common Tasks

#### Port Scanning
```bash
nmap mbptl-main
nmap -p- mbptl-main
```

#### Directory Enumeration
```bash
dirsearch -u http://mbptl-main/
```

#### SQL Injection Testing
```bash
sqlmap -u 'http://mbptl-main/detail.php?id=1' --dbs
```

#### Set Up Reverse Shell Listener
```bash
nc -lp 1337
```

#### Download LinPEAS
```bash
~/tools/get-linpeas.sh
```

## Target Containers

The Kali container is connected to the following targets:

- **mbptl-main** - Main web server (ports 80, 8080, 3306)
- **mbptl-internal** - Internal binary service (port 31337)
- **mbptl-app** - Internal Flask application (port 5000)

## Useful Aliases

The following aliases are pre-configured in `.bashrc`:

- `dirsearch` - Run dirsearch directly
- `sqlmap` - Run sqlmap directly
- `ll` - List files with details (`ls -lah`)
- `tools` - Navigate to ~/tools directory
- `workspace` - Navigate to ~/workspace directory

## Building the Container

From the `mbptl` directory:

```bash
# Build the container
docker-compose build attacker-kali

# Start the container
docker-compose up -d attacker-kali

# Access the container
docker exec -it attacker-kali bash
```

## Notes

- All tools are pre-installed and ready to use
- No need to install packages during the lab
- LinPEAS is downloaded on-demand to always get the latest version
- The container has full network access to all lab targets
- Persistent storage is maintained in the container's home directory
