# PDF Analysis - Batch 1 (10 Files)

This document contains structured analysis of 10 security-focused PDF documents for creating Claude AI SKILLS.md files.

---

## 1. 40 Methods for Privilege Escalation

### Main Topic/Focus Area
Comprehensive guide to Linux and Windows privilege escalation techniques covering 40+ different methods for gaining elevated access on compromised systems.

### Key Techniques, Tools, or Commands Covered
- **Linux Sudo Binary Abuse**: vim, find, nmap, env, awk, perl, python, less, man, ftp, socat, zip, gcc
- **Scheduled Task Exploitation**: cron jobs, Windows Task Scheduler with Mimikatz
- **Capability Abuse**: getcap, interpreter capabilities (Python, Perl), binary capabilities (tar)
- **Service Exploitation**: MySQL running as root, journalctl, VDS, Browser service
- **LDAP Abuse**: SSH key injection via LDAP modification
- **Network Attacks**: LLMNR poisoning with Responder, Certificate Services abuse
- **Token Impersonation**: SweetPotato, SharpImpersonation
- **SQL Server Attacks**: PowerUpSQL, Trustworthy database escalation
- **Active Directory**: Golden Ticket with scheduled tasks, DCSync

### Target Audience
**Advanced** - Requires understanding of operating system internals, Active Directory, and exploitation techniques

### Practical Workflows
1. Enumerate sudo permissions → Find GTFOBins exploitable binaries → Execute privilege escalation
2. Check for scheduled tasks running as root → Inject malicious commands
3. Use getcap to find capabilities → Abuse cap_setuid for privilege escalation
4. Identify services running as root → Exploit misconfigured services

### Prerequisites/Dependencies
- Access to target system (low-privilege shell)
- Kali Linux or similar penetration testing distribution
- Tools: Mimikatz, PowerView, PowerUpSQL, Responder, Impacket
- Understanding of Windows/Linux privilege models

### Common Use Cases
- Post-exploitation privilege escalation
- OSCP/penetration testing engagements
- Red team operations
- Security assessments

---

## 2. APIs Fuzzing for Bug Bounty

### Main Topic/Focus Area
Comprehensive guide to testing REST, SOAP, and GraphQL APIs for security vulnerabilities during bug bounty hunting.

### Key Techniques, Tools, or Commands Covered
**Tools**:
- Fuzzapi, API-fuzzer, Astra, APICheck, Kiterunner
- GraphQL: GraphCrawler, graphw00f, clairvoyance, InQL, GraphQLmap
- Wordlists: api_wordlist, SecLists API endpoints

**Vulnerabilities**:
- IDOR/BOLA (Insecure Direct Object Reference)
- SQL Injection in JSON parameters
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)
- Rate limiting bypass
- GraphQL introspection attacks
- Authorization issues

### Target Audience
**Intermediate to Advanced** - Bug bounty hunters and API security testers

### Practical Workflows
1. Identify API type (REST/SOAP/GraphQL) → Use appropriate fuzzing tools
2. Test authentication mechanisms → Check for rate limiting → Brute force if vulnerable
3. IDOR testing: Wrap IDs in arrays, use wildcards, parameter pollution
4. GraphQL: Run introspection query → Enumerate mutations → Test for DoS

### Prerequisites/Dependencies
- Burp Suite or similar proxy
- API wordlists from SecLists
- Understanding of REST/GraphQL/SOAP protocols
- Python for scripting

### Common Use Cases
- Bug bounty hunting
- API penetration testing
- Web application security assessments
- Mobile app backend testing

---

## 3. AWS Pentest

### Main Topic/Focus Area
Comprehensive guide to penetration testing AWS cloud environments, covering enumeration, privilege escalation, and persistence techniques.

### Key Techniques, Tools, or Commands Covered
**Tools**:
- Pacu (AWS exploitation framework)
- SkyArk (Shadow Admin discovery)
- Prowler (AWS security auditing)
- Principal Mapper (IAM analysis)
- ScoutSuite (multi-cloud auditing)
- CloudMapper, enumerate-iam

**Attacks**:
- SSRF to metadata endpoint (169.254.169.254)
- IAM privilege escalation (20+ methods)
- Shadow Admin exploitation
- Golden SAML attacks
- EBS volume shadow copy
- Lambda code extraction
- SSM command execution

### Target Audience
**Advanced** - Cloud security specialists and penetration testers

### Practical Workflows
1. Enumerate IAM permissions → Identify privilege escalation paths
2. SSRF → Metadata endpoint → Extract temporary credentials
3. Create AMI snapshot → Mount to attacker instance → Extract secrets
4. Identify Lambda functions → Extract source code → Find hardcoded secrets

### Prerequisites/Dependencies
- AWS CLI configured
- Valid AWS credentials (even low-privilege)
- Understanding of AWS IAM model
- Python 3, boto3 library

### Common Use Cases
- Cloud penetration testing
- AWS security assessments
- Red team cloud operations
- Compliance testing (CIS, GDPR, HIPAA)

---

## 4. Active Directory Attacks

### Main Topic/Focus Area
Extensive reference for attacking Microsoft Active Directory environments, covering reconnaissance through domain dominance.

### Key Techniques, Tools, or Commands Covered
**Tools**:
- Impacket suite, Mimikatz, BloodHound
- CrackMapExec, Rubeus, Kerbrute
- PowerView, ADRecon, PingCastle

**Attack Categories**:
- Kerberos attacks: Kerberoasting, AS-REP Roasting, Golden/Silver tickets
- Credential attacks: DCSync, LSASS dumping, Pass-the-Hash
- Relay attacks: NTLM relay, SMB relay, LDAP relay
- ADCS attacks: ESC1-ESC11 certificate vulnerabilities
- CVEs: ZeroLogon, PrintNightmare, MS14-068

### Target Audience
**Intermediate to Advanced** - Red teamers and penetration testers

### Practical Workflows
1. BloodHound collection → Identify attack paths → Execute privilege escalation
2. Kerberoast → Crack service account hashes → Lateral movement
3. DCSync → Extract all domain hashes → Golden ticket persistence
4. ADCS enumeration → Exploit ESC vulnerabilities → Domain Admin

### Prerequisites/Dependencies
- Kali Linux or Windows attack platform
- Domain user credentials
- Network access to DC
- BloodHound + Neo4j database

### Common Use Cases
- Internal penetration testing
- Red team assessments
- Active Directory security audits
- Incident response validation

---

## 5. All About Hacking

### Main Topic/Focus Area
Comprehensive introduction to hacking concepts, covering classification of hackers, computer security fundamentals, network basics, and intelligence agencies.

### Key Techniques, Tools, or Commands Covered
- Hacker classifications: White hat, Black hat, Grey hat, Script kiddie
- Security concepts: Firewalls, routers, software updates
- Network types: LAN, WAN, MAN, VPN, Intranet, Extranet
- Threat types: Malware, worms, identity theft
- Computer crime categories and cyber terrorism

### Target Audience
**Beginner** - Foundational knowledge for aspiring security professionals

### Practical Workflows
- Understanding hacker motivations and ethics
- Learning network fundamentals
- Recognizing threat categories
- Understanding computer crime laws

### Prerequisites/Dependencies
- Basic computer literacy
- Interest in cybersecurity
- No prior technical knowledge required

### Common Use Cases
- Cybersecurity career orientation
- Security awareness training
- Introduction to ethical hacking concepts
- Understanding the hacking landscape

---

## 6. Attacking Active Directory from Kali Linux

### Main Topic/Focus Area
Practical guide to attacking Active Directory environments using Linux-based tools from Kali Linux instead of Windows-based attacks.

### Key Techniques, Tools, or Commands Covered
**Reconnaissance**:
- nbtscan, nmap LDAP scripts, windapsearch
- BloodHound-python for AD enumeration

**Exploitation**:
- Password spraying with kerbrute/CrackMapExec
- Kerberoasting with Impacket GetUserSPNs
- AS-REP roasting with GetNPUsers

**Post-Exploitation**:
- evil-winrm for WinRM access
- secretsdump for DCSync
- Responder for credential harvesting
- Pass-the-Hash attacks

### Target Audience
**Intermediate** - Penetration testers familiar with AD concepts

### Practical Workflows
1. Network scan → Identify AD environment → Enumerate users via LDAP
2. Password spray → Gain initial access → BloodHound enumeration
3. Kerberoast/AS-REP roast → Crack hashes → Privilege escalation
4. DCSync → Extract domain hashes → Lateral movement with PTH

### Prerequisites/Dependencies
- Kali Linux
- Network access to AD environment
- Impacket, BloodHound-python, kerbrute
- hashcat/john for password cracking

### Common Use Cases
- OSCP-style penetration testing
- Red team operations from Linux
- Internal security assessments
- CTF competitions

---

## 7. BGP Routing Protocol Practice Labs

### Main Topic/Focus Area
Hands-on lab exercises for learning BGP (Border Gateway Protocol) routing configuration and path manipulation techniques on Cisco routers.

### Key Techniques, Tools, or Commands Covered
**BGP Attributes**:
- MED (Multi-Exit Discriminator)
- Local Preference
- AS-Path prepending
- Weight attribute
- Community attributes

**BGP Features**:
- Route reflectors
- Confederations
- Route aggregation
- Conditional advertisement
- ORF (Outbound Route Filtering)
- Peer groups

### Target Audience
**Intermediate to Advanced** - Network engineers and CCNP/CCIE candidates

### Practical Workflows
1. Configure eBGP/iBGP peering between routers
2. Implement path selection using route-maps
3. Configure MED/Local Preference for traffic engineering
4. Set up confederations for large-scale BGP deployments

### Prerequisites/Dependencies
- Cisco IOS routers or GNS3/EVE-NG
- CCNA-level networking knowledge
- Understanding of IP routing fundamentals
- Lab environment with multiple routers

### Common Use Cases
- CCNP/CCIE lab preparation
- ISP network engineering
- Enterprise WAN design
- Multi-homed network configuration

---

## 8. Buffer Overflow

### Main Topic/Focus Area
Step-by-step guide to exploiting buffer overflow vulnerabilities using Immunity Debugger and Mona.py, with practical examples on vulnerable applications.

### Key Techniques, Tools, or Commands Covered
**Exploitation Process**:
1. Fuzzing to crash application
2. Pattern creation for EIP offset
3. Bad character identification
4. JMP ESP location finding
5. Shellcode generation with msfvenom

**Tools**:
- Immunity Debugger with Mona.py
- msfvenom for shellcode
- Python 2 exploit scripts

**Target Applications**:
- Minishare 1.4.1 (HTTP)
- PCMan FTP Server 2.0.7 (FTP)
- Various FTP servers

### Target Audience
**Intermediate** - OSCP candidates and exploit developers

### Practical Workflows
1. Fuzz application → Identify crash point
2. Create pattern → Find EIP offset → Control EIP
3. Generate bytearray → Find bad characters
4. Locate JMP ESP → Generate shellcode → Execute exploit

### Prerequisites/Dependencies
- Immunity Debugger + Mona.py
- Windows XP/7 test environment (no DEP/ASLR)
- Kali Linux for exploit development
- Python 2 scripting knowledge

### Common Use Cases
- OSCP exam preparation
- Exploit development training
- Vulnerability research
- Security testing of legacy applications

---

## 9. Build A Malicious Lab (Credential Harvesting)

### Main Topic/Focus Area
Lab guide for setting up credential harvesting attacks using ARP and DNS poisoning with Apache web server to create phishing pages.

### Key Techniques, Tools, or Commands Covered
**Tools**:
- Apache2 web server
- arpspoof (dsniff package)
- dnsspoof
- PHP for credential logging

**Techniques**:
- ARP cache poisoning
- DNS spoofing
- Fake website hosting
- Credential capture and logging

### Target Audience
**Beginner to Intermediate** - Security students and junior pentesters

### Practical Workflows
1. Install and configure Apache2
2. Create fake login page (HTML + PHP)
3. Enable IP forwarding
4. Run arpspoof in both directions
5. Start dnsspoof with target domains
6. Capture credentials from login_log.txt

### Prerequisites/Dependencies
- Kali Linux
- Apache2 web server
- Network on same subnet as target
- HTML/PHP knowledge for fake pages

### Common Use Cases
- Security awareness training
- Phishing simulation testing
- Network security labs
- Penetration testing training

---

## 10. Burp Suite User Manual

### Main Topic/Focus Area
User guide for Burp Suite web application security testing platform, covering proxy interception, request modification, repeater, and scanning features.

### Key Techniques, Tools, or Commands Covered
**Burp Suite Features**:
- Proxy: HTTP traffic interception
- Repeater: Request manipulation and resubmission
- Scanner: Automated vulnerability scanning (Professional)
- Target scope configuration
- HTTP history analysis

**Testing Techniques**:
- Request interception and modification
- Parameter tampering (price manipulation)
- Input validation testing
- Error message analysis

### Target Audience
**Beginner to Intermediate** - Web application security testers

### Practical Workflows
1. Configure browser proxy → Intercept requests
2. Identify interesting parameters → Send to Repeater
3. Modify values → Analyze responses
4. Set target scope → Filter noise
5. Run automated scan → Review findings

### Prerequisites/Dependencies
- Burp Suite Community or Professional
- Web browser (Burp's browser or configured proxy)
- Target web application
- Basic HTTP protocol knowledge

### Common Use Cases
- Web application penetration testing
- Bug bounty hunting
- Security code review support
- Automated vulnerability scanning

---

## Summary Table

| # | Document | Focus | Difficulty | Primary Tools |
|---|----------|-------|------------|---------------|
| 1 | 40 Methods for Privilege Escalation | Linux/Windows PrivEsc | Advanced | GTFOBins, Mimikatz, PowerUpSQL |
| 2 | APIs Fuzzing for Bug Bounty | API Security Testing | Intermediate | Fuzzapi, Burp, GraphQL tools |
| 3 | AWS Pentest | Cloud Security | Advanced | Pacu, SkyArk, Prowler, boto3 |
| 4 | Active Directory Attacks | AD Exploitation | Intermediate-Advanced | BloodHound, Impacket, Mimikatz |
| 5 | All About Hacking | Security Fundamentals | Beginner | Conceptual knowledge |
| 6 | Attacking AD from Kali | Linux-based AD Attacks | Intermediate | Impacket, kerbrute, evil-winrm |
| 7 | BGP Routing Protocol | Network Engineering | Intermediate-Advanced | Cisco IOS, GNS3 |
| 8 | Buffer Overflow | Exploit Development | Intermediate | Immunity Debugger, msfvenom |
| 9 | Build A Malicious Lab | Credential Harvesting | Beginner-Intermediate | Apache, arpspoof, dnsspoof |
| 10 | Burp Suite User Manual | Web App Testing | Beginner-Intermediate | Burp Suite |

---

*Generated for Claude AI SKILLS.md files - January 2026*
