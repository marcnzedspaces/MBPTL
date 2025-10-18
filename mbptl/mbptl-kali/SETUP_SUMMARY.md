# MBPTL Kali Container - Setup Summary

## What We've Accomplished

Successfully modified the MBPTL lab to include a fully-configured Kali Linux attack container with all the necessary penetration testing tools pre-installed.

## Files Created/Modified

### 1. **mbptl/mbptl-kali/Dockerfile** (NEW)
   - Custom Dockerfile based on `kalilinux/kali-rolling`
   - Pre-installs all required tools from the writeup
   - Creates kali user with sudo privileges
   - Sets up helpful aliases and welcome message
   - Configures SSH server

### 2. **mbptl/docker-compose.yml** (MODIFIED)
   - Added `attacker-kali` service
   - Configured to build from custom Dockerfile
   - Connected to all lab targets (main, internal, app)
   - Persistent container configuration

### 3. **mbptl/mbptl-kali/README.md** (NEW)
   - Complete documentation of the Kali container
   - List of all pre-installed tools
   - Quick start guide
   - Usage examples for common tasks

### 4. **mbptl/mbptl-kali/quickref.sh** (NEW)
   - Quick reference script with all common commands
   - Can be run inside the container for help

### 5. **README.md** (MODIFIED)
   - Added documentation about the Kali attack container
   - Updated deployment steps
   - Added Kali container to lab structure

## Pre-installed Tools

### Core System Tools
✅ sudo, bash, vim, nano, openssh-server

### Network & Reconnaissance
✅ nmap - Port scanning
✅ curl - HTTP requests
✅ wget - File downloads
✅ netcat (nc) - Network connections
✅ ping, ip, ifconfig - Network utilities

### File Analysis
✅ file - File type detection
✅ strings - Extract strings from binaries
✅ objdump - Binary disassembly

### Programming & Scripting
✅ python3 - Python interpreter
✅ pip3 - Package manager
✅ git - Version control

### Python Libraries
✅ pwntools - Binary exploitation framework

### Penetration Testing Tools
✅ dirsearch - Directory enumeration (~/tools/dirsearch/)
✅ sqlmap - SQL injection (~/tools/sqlmap/)
✅ LinPEAS - Privilege escalation (download script ready)

## How to Use

### 1. Build the Container
```bash
cd /Users/joaquinantonio/Code/MBPTL/mbptl
docker-compose build attacker-kali
```

### 2. Start the Container
```bash
docker-compose up -d attacker-kali
```

### 3. Access the Container
```bash
# As kali user (recommended)
docker exec -it attacker-kali bash

# As root
docker exec -it -u root attacker-kali bash
```

### 4. Log in as kali user (if accessing as root)
```bash
su - kali
```

## Features

### Welcome Message
When logging in as the kali user, a welcome message displays:
- List of installed tools
- Tool locations
- Target container information
- Workspace directories

### Helpful Aliases
Pre-configured in .bashrc:
- `dirsearch` - Run dirsearch directly
- `sqlmap` - Run sqlmap directly
- `ll` - Detailed file listing
- `tools` - Navigate to ~/tools
- `workspace` - Navigate to ~/workspace

### Directory Structure
```
/home/kali/
├── tools/           # All penetration testing tools
│   ├── dirsearch/   # Directory enumeration
│   ├── sqlmap/      # SQL injection
│   └── get-linpeas.sh  # LinPEAS download script
├── workspace/       # Your working directory
└── scripts/         # Custom scripts
```

### Network Access
The Kali container has full network access to:
- **mbptl-main** (ports 80, 8080, 3306)
- **mbptl-internal** (port 31337)
- **mbptl-app** (port 5000)

## Testing

### Test Port Scanning
```bash
docker exec -it attacker-kali bash
su - kali
nmap mbptl-main
```

### Test Web Tools
```bash
curl http://mbptl-main/
curl http://mbptl-main:8080/
```

### Test Penetration Testing Tools
```bash
dirsearch -u http://mbptl-main/
sqlmap -u 'http://mbptl-main/detail.php?id=1' --dbs
```

## Benefits

1. **No Manual Setup** - All tools pre-installed and ready to use
2. **Consistent Environment** - Same setup for all users
3. **Network Ready** - Pre-connected to all lab targets
4. **Beginner Friendly** - Welcome messages and helpful aliases
5. **Persistent** - Container state is maintained between restarts
6. **Isolated** - Dedicated attack platform separate from host system

## Next Steps for Users

1. Start the lab: `docker-compose up -d`
2. Access Kali container: `docker exec -it attacker-kali bash`
3. Switch to kali user: `su - kali`
4. Follow the writeup at: `writeup/README.md`
5. All tools are ready - no installation needed!

## Troubleshooting

### Container won't start
```bash
docker-compose down
docker-compose build attacker-kali
docker-compose up -d attacker-kali
```

### Tools not found
Make sure you're logged in as the kali user:
```bash
su - kali
```

### Permission issues
The kali user has passwordless sudo access:
```bash
sudo <command>
```

## Summary

The MBPTL lab now includes a fully-equipped Kali Linux attack container that matches all the tools mentioned in the writeup. Users can start penetration testing immediately without any manual tool installation, making the lab even more beginner-friendly and reducing setup friction.
