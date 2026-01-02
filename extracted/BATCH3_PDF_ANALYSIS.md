# Batch 3 PDF Analysis for SKILLS.md Documentation

This document contains structured summaries of 10 security-focused PDF files, extracted and analyzed for Claude AI SKILLS.md file creation.

---

## 1. Introduction to IDOR.pdf

### Main Topic/Focus Area
Insecure Direct Object References (IDOR) vulnerabilities - a critical web application security flaw that allows attackers to access unauthorized data by manipulating object references.

### Key Techniques, Tools, or Commands Covered
- **URL Tampering**: Modifying URL parameters (e.g., `?id=2023` to `?id=2022`)
- **Body Manipulation**: Altering request body parameters
- **Burp Suite**: Intercepting and modifying HTTP requests
- **Intruder Attacks**: Using Battering Ram attack type for enumeration
- **Parameter Enumeration**: Brute-forcing object IDs

### Target Audience
**Intermediate** - Requires understanding of HTTP requests, web application architecture, and basic security testing concepts.

### Practical Workflows or Procedures
1. **Reconnaissance**: Identify endpoints with object references (user IDs, file names)
2. **Interception**: Use Burp Suite to capture requests
3. **Manipulation**: Modify object references in URLs or request bodies
4. **Enumeration**: Use Intruder to test multiple ID values
5. **Exploitation**: Access or modify unauthorized resources

### Prerequisites or Dependencies
- Burp Suite (or similar proxy tool)
- Understanding of HTTP request/response cycle
- Knowledge of web application authentication mechanisms
- Basic Python/Django knowledge (for remediation examples)

### Common Use Cases
- Accessing other users' profile data
- Downloading unauthorized files (receipts, documents)
- Modifying billing/shipping addresses of other users
- Account takeover through data manipulation
- Bug bounty hunting for authorization flaws

---

## 2. JSON_Web_Token_Hacking.pdf

### Main Topic/Focus Area
JWT (JSON Web Token) security vulnerabilities and attack techniques for web application authentication bypass.

### Key Techniques, Tools, or Commands Covered
- **None Algorithm Attack**: Changing `"alg": "HS256"` to `"alg": "none"`
- **Brute-Force Secret Key**: Cracking weak HMAC secrets
- **JWT Signature Replay Attack**: Reusing captured tokens
- **JWT Claim Tampering**: Modifying payload claims
- **Key Confusion Attack**: Using public RSA key as HMAC secret
- **XSS Token Theft**: Stealing JWTs from localStorage

### Target Audience
**Intermediate to Advanced** - Requires understanding of authentication mechanisms, cryptography basics, and web security.

### Practical Workflows or Procedures
1. **Token Capture**: Intercept JWT from Authorization header or cookies
2. **Decode Token**: Use Base64 decoding to view header/payload
3. **Algorithm Analysis**: Identify signing algorithm (HS256, RS256, etc.)
4. **Attack Selection**: Choose appropriate attack based on configuration
5. **Token Modification**: Alter claims (role, user ID, expiration)
6. **Signature Bypass**: Use none algorithm or brute-force secret
7. **Replay/Submit**: Send modified token to server

### Prerequisites or Dependencies
- Understanding of Base64 encoding
- Knowledge of cryptographic algorithms (HMAC, RSA)
- Web proxy tool (Burp Suite)
- JWT decoder tools (jwt.io)
- Brute-force tools for secret cracking

### Common Use Cases
- Authentication bypass
- Privilege escalation (user to admin)
- Session hijacking
- SSO mechanism exploitation
- API security testing

---

## 3. John_the_Ripper.pdf

### Main Topic/Focus Area
Password hash cracking using John the Ripper - a comprehensive guide to cracking various hash types and encrypted files.

### Key Techniques, Tools, or Commands Covered
```bash
# Single Crack Mode
john --single --format=raw-sha1 crack.txt

# Wordlist Mode
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha1 crack.txt

# View supported formats
john --list=formats

# Restore interrupted session
john --restore

# Unshadow for Linux credentials
unshadow /etc/passwd /etc/shadow > crack.txt
```

**Supported Hash Types**:
- SHA1, SHA256, MD4, MD5, RIPEMD128, Whirlpool

**File Type Crackers**:
- ssh2john (SSH private keys)
- keepass2john (KeePass databases)
- rar2john (RAR archives)
- zip2john (ZIP archives)
- pdf2john (PDF files)

### Target Audience
**Beginner to Intermediate** - Well-documented with step-by-step instructions.

### Practical Workflows or Procedures
1. **Identify Hash Type**: Determine encryption algorithm
2. **Prepare Hash File**: Extract hash to text file with `username:hash` format
3. **Select Mode**: Choose single, wordlist, or incremental mode
4. **Choose Wordlist**: Use rockyou.txt or custom wordlist
5. **Run Attack**: Execute john with appropriate parameters
6. **Collect Results**: View cracked passwords

### Prerequisites or Dependencies
- Kali Linux (pre-installed) or manual installation
- Wordlists (rockyou.txt recommended)
- Hash extraction utilities (*2john scripts)
- Understanding of hash formats

### Common Use Cases
- Linux password auditing (/etc/shadow)
- SSH private key passphrase recovery
- Encrypted archive password recovery (ZIP, RAR, 7z)
- KeePass database password cracking
- PDF password removal
- Penetration testing credential attacks

---

## 4. LDAP_Injection.pdf

### Main Topic/Focus Area
LDAP Injection and Blind LDAP Injection attacks against web applications using LDAP directory services.

### Key Techniques, Tools, or Commands Covered
**LDAP Filter Syntax**:
```
(&(attribute=value)(second_filter))  # AND injection
(|(attribute=value)(second_filter))  # OR injection
```

**Injection Payloads**:
- Access bypass: `slisberger)(&))`
- Wildcard queries: `*` for matching any characters
- Absolute TRUE: `(&)`
- Absolute FALSE: `(|)`

**Blind LDAP Injection**:
- Booleanization techniques
- Charset reduction
- Attribute discovery

### Target Audience
**Advanced** - Requires deep understanding of LDAP, directory services, and web application security.

### Practical Workflows or Procedures
1. **Identify LDAP Backend**: Recognize LDAP-based authentication
2. **Test for Injection**: Send malformed input to trigger errors
3. **Determine Environment**: AND or OR injection context
4. **Craft Payload**: Construct syntactically correct LDAP filter
5. **Bypass Authentication**: Use injection to authenticate without credentials
6. **Privilege Escalation**: Modify queries to access unauthorized resources
7. **Data Extraction**: Use blind techniques for information gathering

### Prerequisites or Dependencies
- Understanding of LDAP protocol (RFC 4515)
- Knowledge of Active Directory/OpenLDAP
- Web proxy tools
- Understanding of filter syntax and operators

### Common Use Cases
- Authentication bypass in enterprise applications
- Access control circumvention
- Single Sign-On (SSO) exploitation
- Corporate directory data extraction
- Privilege escalation in LDAP-based systems

---

## 5. LINUX PRIVILEGE ESCALATION.pdf

### Main Topic/Focus Area
Comprehensive guide to escalating privileges on Linux systems from low-privileged user to root access.

### Key Techniques, Tools, or Commands Covered
**Enumeration Commands**:
```bash
hostname                    # System hostname
uname -a                    # Kernel version
cat /proc/version          # Kernel details
cat /etc/issue             # OS version
ps aux                     # Running processes
env                        # Environment variables
sudo -l                    # Sudo permissions
cat /etc/passwd            # User enumeration
history                    # Command history
ifconfig / ip route        # Network configuration
netstat -ano               # Network connections
find / -perm -u=s -type f 2>/dev/null  # SUID files
```

**Escalation Techniques**:
- Kernel exploits
- Sudo misconfigurations (GTFOBins)
- SUID/SGID binary exploitation
- Linux capabilities abuse
- Cron job manipulation
- PATH variable hijacking
- NFS no_root_squash exploitation
- LD_PRELOAD exploitation

### Target Audience
**Beginner to Advanced** - Structured from basics to advanced techniques with practical examples.

### Practical Workflows or Procedures
1. **Initial Enumeration**: Gather system information (kernel, users, network)
2. **Identify Attack Vectors**: Check sudo, SUID, cron, capabilities
3. **Research Exploits**: Use GTFOBins, searchsploit, CVE databases
4. **Prepare Exploit**: Transfer tools or compile exploits
5. **Execute Attack**: Run privilege escalation technique
6. **Verify Access**: Confirm root shell

### Prerequisites or Dependencies
- Basic Linux command knowledge
- SSH or shell access to target
- File transfer capability (wget, curl, nc)
- Automated tools: LinPEAS, LinEnum, LES, linux-smart-enumeration

### Common Use Cases
- CTF challenges
- Penetration testing post-exploitation
- Red team operations
- OSCP exam preparation
- Security auditing

---

## 6. Linux Commands.pdf

### Main Topic/Focus Area
Comprehensive Linux command reference for system administration, file management, and security operations.

### Key Techniques, Tools, or Commands Covered
**User/Group Management**:
```bash
useradd/userdel/usermod    # User management
groupadd/groupdel/groupmod # Group management
passwd                     # Password management
chage                      # Password expiration
getent passwd/shadow/group # Database queries
```

**File Permissions**:
```bash
chmod 660 file.txt         # Numeric permissions
chown user:group file      # Change ownership
getfacl/setfacl            # Access Control Lists
```

**Disk/LVM Management**:
```bash
fdisk/gdisk/parted         # Partition tables
mkfs                       # Create filesystems
pvcreate/vgcreate/lvcreate # LVM operations
mount/umount               # Filesystem mounting
```

**Text Processing**:
```bash
grep -E "pattern"          # Extended regex search
sed 's/old/new/g'          # Stream editor
awk '{print $1}'           # Text processing
find / -name "file"        # File search
```

### Target Audience
**Beginner to Intermediate** - Reference guide with practical examples.

### Practical Workflows or Procedures
- User account creation and management
- File system permission configuration
- Disk partitioning and LVM setup
- Log file analysis and filtering
- Backup and archiving operations

### Prerequisites or Dependencies
- Linux system access
- Terminal/shell environment
- Root or sudo privileges for administrative tasks

### Common Use Cases
- System administration
- Security hardening
- Log analysis
- User management
- Backup operations
- Penetration testing enumeration

---

## 7. Linux Production Shell Scripts.pdf

### Main Topic/Focus Area
Ready-to-use shell scripts for Linux system administration, automation, and security operations.

### Key Techniques, Tools, or Commands Covered
**30 Production Scripts Including**:
1. **Backup Scripts**: Timestamped tar archives, rsync to remote servers
2. **Monitoring Scripts**: CPU usage, disk space, system health
3. **User Management**: Account creation, password expiry checking
4. **Log Analysis**: Error extraction, web server log analysis
5. **Security Scripts**: Password generation, file encryption (OpenSSL)
6. **Network Scripts**: Connectivity checks, interface information
7. **Maintenance Scripts**: Data cleanup, backup rotation
8. **Database Operations**: MySQL backup, cleanup old backups

**Key Commands Used**:
```bash
tar -czf backup.tar.gz /source      # Archive creation
openssl rand -base64 12             # Password generation
openssl enc -aes-256-cbc            # File encryption
rsync -avz source/ remote:/backup   # Remote sync
find /dir -mtime +7 -exec rm {} \;  # Old file cleanup
mysqldump -u user -p db > backup.sql # DB backup
```

### Target Audience
**Beginner to Intermediate** - Practical scripts with clear comments.

### Practical Workflows or Procedures
- Scheduled task automation via cron
- System monitoring and alerting
- Automated backup strategies
- Security automation (password generation, encryption)
- Log rotation and analysis

### Prerequisites or Dependencies
- Bash shell environment
- Cron for scheduling
- OpenSSL for encryption
- rsync for remote backups
- MySQL client for database operations

### Common Use Cases
- DevOps automation
- System administration
- Security operations
- Backup management
- Monitoring and alerting
- Incident response scripting

---

## 8. Linux_Pentest.pdf

### Main Topic/Focus Area
Comprehensive Linux fundamentals and penetration testing guide covering system basics to bash scripting.

### Key Techniques, Tools, or Commands Covered
**Navigation & File Operations**:
```bash
pwd, cd, ls -la            # Navigation
cat, head, tail, less      # File viewing
touch, mkdir, cp, mv, rm   # File manipulation
locate, find, whereis      # File searching
grep, sed, awk             # Text processing
```

**System Information**:
```bash
whoami, id                 # User info
uname -a                   # System info
ifconfig, netstat          # Network info
ps aux                     # Process listing
```

**Package Management**:
```bash
apt-cache search           # Search packages
apt-get install/remove     # Install/remove software
apt-get update/upgrade     # Update system
```

**Permissions & Networking**:
```bash
chmod, chown               # Permission management
ifconfig, dhclient         # Network configuration
/etc/hosts, /etc/resolv.conf  # DNS configuration
```

### Target Audience
**Beginner** - Designed for newcomers to Linux and penetration testing.

### Practical Workflows or Procedures
1. System navigation and exploration
2. File and text manipulation
3. Software installation and management
4. User and permission management
5. Network configuration and enumeration
6. Process management
7. Bash scripting basics
8. Service management with systemd

### Prerequisites or Dependencies
- Linux distribution (Kali Linux recommended)
- Terminal access
- Basic command-line familiarity

### Common Use Cases
- Learning Linux for security
- Setting up penetration testing environment
- Basic system administration
- Automation with bash scripts
- Network reconnaissance

---

## 9. Metasploit.pdf

### Main Topic/Focus Area
Introduction to the Metasploit Framework - the industry-standard penetration testing and exploitation platform.

### Key Techniques, Tools, or Commands Covered
**Core Commands**:
```bash
msfconsole -q              # Start Metasploit console
show exploits              # List exploit modules
use exploit/windows/misc/bopup_comm  # Select exploit
show options               # Display module options
set RHOSTS 192.168.74.128  # Set target IP
exploit / run              # Execute exploit
```

**Module Types**:
1. **Exploit Modules**: Target specific vulnerabilities
2. **Payload Modules**: Code executed after exploitation
3. **Auxiliary Modules**: Scanning, fuzzing, DoS, enumeration
4. **Post-Exploitation Modules**: Privilege escalation, persistence
5. **Encoders**: Bypass AV detection
6. **Nops**: NOP sled generation for buffer overflows
7. **Evasion**: Firewall/IDS bypass

### Target Audience
**Beginner** - Basic introduction to Metasploit concepts and usage.

### Practical Workflows or Procedures
1. **Start Framework**: Launch msfconsole
2. **Search Exploits**: Find relevant exploit for target
3. **Select Module**: Use exploit/auxiliary module
4. **Configure Options**: Set RHOSTS, LHOST, payload
5. **Execute Attack**: Run the exploit
6. **Post-Exploitation**: Use post modules for persistence

### Prerequisites or Dependencies
- Kali Linux (Metasploit pre-installed)
- Ruby runtime
- PostgreSQL (for database)
- Network access to targets
- Understanding of networking and vulnerabilities

### Common Use Cases
- Vulnerability exploitation
- Payload generation
- Network scanning and enumeration
- Post-exploitation activities
- Security assessments
- CTF competitions

---

## 10. Mobile Security Testing Guide.pdf

### Main Topic/Focus Area
Comprehensive Android mobile application penetration testing guide covering static analysis, dynamic analysis, and vulnerability exploitation.

### Key Techniques, Tools, or Commands Covered
**Lab Setup Tools**:
- ADB (Android Debug Bridge)
- JADX-GUI (Java decompiler)
- Apktool (APK reverse engineering)
- Frida/Frida-Server (dynamic instrumentation)
- Objection (mobile exploration toolkit)
- MobSF (Mobile Security Framework)
- Drozer (Android security testing)
- Genymotion (Android emulator)

**ADB Commands**:
```bash
adb devices                # List connected devices
adb shell                  # Open device shell
adb tcpip 5555            # Enable wireless debugging
adb connect IP:5555       # Connect over network
adb install app.apk       # Install application
adb push/pull             # File transfer
```

**Frida Commands**:
```bash
frida-ps -Uai             # List running apps
frida -U -f package -l script.js  # Inject script
```

**OWASP Mobile Top 10 Vulnerabilities**:
1. Improper Platform Usage
2. Insecure Data Storage
3. Insecure Communication
4. Insecure Authentication
5. Insufficient Cryptography
6. Insecure Authorization
7. Code Tampering

### Target Audience
**Intermediate to Advanced** - Requires understanding of Android architecture and security concepts.

### Practical Workflows or Procedures
**Static Analysis**:
1. Extract APK components using Apktool
2. Decompile to Java using JADX-GUI
3. Analyze AndroidManifest.xml for permissions
4. Search for hardcoded strings and credentials
5. Review source code for vulnerabilities

**Dynamic Analysis**:
1. Set up proxy (Burp Suite) for traffic interception
2. Install and configure Frida-server
3. Bypass SSL pinning using Objection/Frida
4. Bypass root detection
5. Hook and manipulate application functions
6. Analyze runtime behavior

### Prerequisites or Dependencies
- Rooted Android device or emulator
- ADB tools
- Python environment (for Frida/Objection)
- Docker (for MobSF)
- Burp Suite for traffic analysis
- Java/JDK for decompilation tools

### Common Use Cases
- Mobile application security assessments
- Bug bounty hunting on mobile apps
- Bypassing security controls (SSL pinning, root detection)
- Data leakage detection
- Authentication/authorization testing
- Malware analysis
- Reverse engineering Android applications

---

## Summary Statistics

| PDF | Pages | Skill Level | Primary Focus |
|-----|-------|-------------|---------------|
| Introduction to IDOR | 41 | Intermediate | Web App Security |
| JSON Web Token Hacking | 13 | Intermediate-Advanced | Authentication |
| John the Ripper | 33 | Beginner-Intermediate | Password Cracking |
| LDAP Injection | 18 | Advanced | Web App Security |
| Linux Privilege Escalation | 42 | Beginner-Advanced | Post-Exploitation |
| Linux Commands | 31 | Beginner-Intermediate | System Admin |
| Linux Production Shell Scripts | 10 | Beginner-Intermediate | Automation |
| Linux Pentest | 48 | Beginner | Linux Fundamentals |
| Metasploit | 6 | Beginner | Exploitation Framework |
| Mobile Security Testing Guide | 110 | Intermediate-Advanced | Mobile Security |

---

*Generated: January 2, 2026*
*Batch 3 of PDF Analysis for SecOps-CLI-Guides*
