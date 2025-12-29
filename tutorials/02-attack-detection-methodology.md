# Attack Detection Methodology

## Detection Approaches

### Signature-Based Detection
Looks for known patterns of malicious activity.

**Advantages**:
- High accuracy for known attacks
- Low false positive rate
- Fast matching

**Disadvantages**:
- Cannot detect new (zero-day) attacks
- Requires constant signature updates
- Can be evaded with obfuscation

### Anomaly-Based Detection
Identifies deviations from normal behavior.

**Advantages**:
- Can detect unknown attacks
- Adapts to environment

**Disadvantages**:
- High false positive rate
- Requires baseline training period
- Difficult to tune

### Hybrid Approach
Combines signatures and anomalies for best results.

---

## Attack Taxonomy

### 1. Reconnaissance Attacks

#### Port Scanning
**Indicators**:
- Multiple SYN packets to sequential ports
- Connection attempts to many closed ports
- Short time intervals between probes

**Detection**:
```bash
# Find IPs scanning many ports
awk '{print $2, $4}' network_traffic.log | \
  grep SYN | \
  cut -d: -f1 | \
  uniq -c | \
  sort -rn
```

**Tools used by attackers**:
- Nmap
- Masscan
- ZMap

#### Network Mapping
**Indicators**:
- ICMP ping sweeps
- Traceroute activity
- DNS zone transfer attempts

### 2. Web Application Attacks

#### SQL Injection
**Indicators**:
- SQL keywords in URLs (UNION, SELECT, DROP)
- Single/double quotes in parameters
- OR '1'='1' patterns
- Comment sequences (-- or /*)

**Example malicious URLs**:
```
/login.php?user=admin' OR '1'='1
/search.php?q='; DROP TABLE users--
/products?id=1 UNION SELECT password FROM users
```

**Detection**:
```bash
# Find SQL injection attempts
grep -E "(UNION|SELECT|DROP|INSERT|'--|\bOR\b.*=)" web_access.log
```

#### Cross-Site Scripting (XSS)
**Indicators**:
- `<script>` tags in URLs
- JavaScript event handlers (onload, onerror)
- Encoded JavaScript (%3Cscript%3E)

**Example attacks**:
```
/comment?text=<script>alert('XSS')</script>
/search?q=<img src=x onerror=alert(1)>
```

#### Directory Traversal
**Indicators**:
- `../` sequences in paths
- Attempts to access /etc/passwd
- Null byte injection (%00)

**Example attempts**:
```
/download.php?file=../../../../etc/passwd
/view?page=..\..\..\..\windows\system32\config\sam
```

### 3. Brute Force Attacks

#### SSH Brute Force
**Indicators**:
- High volume of failed authentication
- Sequential username attempts
- Same source IP, different usernames
- Common password attempts

**Detection**:
```bash
# Count failed login attempts by IP
grep "Failed password" ssh_auth.log | \
  awk '{print $11}' | \
  sort | \
  uniq -c | \
  sort -rn
```

**Common attack patterns**:
- Dictionary attack (common passwords)
- Credential stuffing (leaked credentials)
- Password spraying (one password, many users)

#### Password Spray Detection
**Characteristics**:
- Low frequency per account (avoid lockout)
- High breadth (many accounts)
- Common passwords (Password123, Spring2025)

### 4. Command & Control (C2)

#### HTTP/HTTPS Beaconing
**Indicators**:
- Regular interval connections
- Fixed payload sizes
- Connections to suspicious domains
- Unusual User-Agent strings

**Detection**:
```bash
# Find connections with regular intervals
grep "45.142.212.61" network_traffic.log | \
  awk '{print $1, $2}' | \
  uniq -c
```

**Beacon patterns**:
- Every 5 minutes (300 seconds)
- Every hour
- Golden ratio intervals (avoid pattern detection)

#### DNS Tunneling
**Indicators**:
- Unusually long subdomain names
- High volume of TXT queries
- Queries to single domain
- Random-looking subdomains

**Example tunneled data**:
```
a4b7c2d9e1f3.evil-c2.com
data-here-encoded.malware.tk
```

**Detection**:
```bash
# Find suspiciously long DNS queries
awk '{if (length($6) > 30) print}' dns_queries.log
```

### 5. Data Exfiltration

#### Network Indicators
- Large outbound transfers
- Uploads during off-hours
- Unusual protocols (FTP from workstation)
- Encrypted channels to unknown hosts

#### DNS Exfiltration
**Pattern**: Encode data in subdomain names

```
# Example: Exfiltrating "SECRET DATA"
query: 5345435245542044415441.attacker.com
```

**Detection**:
```bash
# Find DNS queries with hex-encoded subdomains
grep -E "[0-9a-f]{20,}" dns_queries.log
```

### 6. Malware Traffic

#### Domain Generation Algorithm (DGA)
**Indicators**:
- NXDOMAIN responses (domains don't exist)
- Random-looking domain names
- High volume of failed DNS queries
- Algorithmic patterns

**Example DGA domains**:
```
jkdklsdfklsdfjk.com
xmqpwoeirutyzmn.net
asdkfjhqwoeiru.org
```

**Detection**:
```bash
# Find NXDOMAIN patterns
grep "NXDOMAIN" dns_queries.log | \
  awk '{print $6}' | \
  sort | \
  uniq -c
```

---

## Attack Kill Chain

### 1. Reconnaissance
- Port scanning
- Service enumeration
- Vulnerability scanning
- Social engineering

### 2. Weaponization
- Creating exploits
- Preparing payloads
- Setting up infrastructure

### 3. Delivery
- Phishing emails
- Drive-by downloads
- Exploit kits
- USB drops

### 4. Exploitation
- Buffer overflow
- SQL injection
- Command injection
- Privilege escalation

### 5. Installation
- Backdoor deployment
- Persistence mechanisms
- Rootkit installation

### 6. Command & Control
- Beaconing
- Remote access
- Data staging

### 7. Actions on Objectives
- Data theft
- Destruction
- Denial of service
- Lateral movement

---

## Detection Strategies by Attack Type

### Port Scan Detection

**Method 1: Count unique destination ports**
```bash
awk '{print $2, $4}' network_traffic.log | \
  grep SYN | \
  awk '{print $1}' | \
  cut -d: -f1 | \
  sort | \
  uniq -c | \
  awk '$1 > 20 {print $2, $1}'
```

**Method 2: Time-based clustering**
- Track connections per time window
- Alert if >20 ports in 60 seconds

### SQL Injection Detection

**Regex patterns**:
```bash
UNION.*SELECT
'\s*OR\s*'1'\s*=\s*'1
;.*DROP.*TABLE
INSERT.*INTO.*VALUES
```

**Validation checks**:
- Length anomalies
- Forbidden characters
- Multiple SQL keywords

### Brute Force Detection

**Threshold-based**:
- >5 failed logins in 5 minutes
- >20 failed logins in 1 hour

**Velocity-based**:
- Logins too fast for human (100ms intervals)

**Pattern-based**:
- Sequential usernames (user1, user2, user3)
- Common passwords (admin, password, 123456)

### C2 Beacon Detection

**Statistical analysis**:
```python
# Calculate connection intervals
intervals = timestamps[1:] - timestamps[:-1]
mean = intervals.mean()
stdev = intervals.std()

# Low standard deviation = beaconing
if stdev < mean * 0.1:
    alert("Beaconing detected")
```

**Frequency analysis**:
- Plot connections over time
- Look for periodic patterns
- Use FFT for frequency detection

---

## MITRE ATT&CK Mapping

Map detected activities to ATT&CK framework:

| Attack Type | ATT&CK Technique |
|------------|------------------|
| Port Scan | T1046 - Network Service Scanning |
| SQL Injection | T1190 - Exploit Public-Facing Application |
| Brute Force | T1110 - Brute Force |
| DNS Tunneling | T1071.004 - Application Layer Protocol: DNS |
| Data Exfiltration | T1048 - Exfiltration Over Alternative Protocol |
| C2 Beaconing | T1071 - Application Layer Protocol |

---

## Correlation Techniques

### 1. Time-Based Correlation
Link events occurring in temporal proximity:

```
T+0:00  Port scan detected
T+0:05  SQL injection attempt
T+0:07  Failed authentication
T+0:15  Successful login (compromised account?)
```

### 2. IP-Based Correlation
Track all activities from suspicious IP:

```bash
# Create IP activity timeline
IP="91.219.236.131"
{
  grep "$IP" network_traffic.log | sed 's/^/[NET] /'
  grep "$IP" firewall.log | sed 's/^/[FW] /'
  grep "$IP" web_access.log | sed 's/^/[WEB] /'
  grep "$IP" ssh_auth.log | sed 's/^/[SSH] /'
} | sort
```

### 3. Indicator Clustering
Group related indicators:

- All attempts from same IP
- Common user agent strings
- Similar attack signatures
- Shared C2 infrastructure

### 4. Behavioral Chains
Identify attack sequences:

```
Recon → Exploitation → Persistence → Lateral Movement → Exfiltration
```

---

## False Positive Reduction

### 1. Whitelisting
Exclude known benign activity:

- Vulnerability scanners (authorized)
- Backup systems (large transfers)
- Development servers (test attacks)

### 2. Contextual Analysis
Consider:
- Time of day
- User role
- Geographic location
- Historical behavior

### 3. Threshold Tuning
Start conservative, adjust based on:
- False positive rate
- Investigation capacity
- Risk tolerance

---

## Automated Detection Rules

### Example: SIEM Rule for SQL Injection

```yaml
rule: sql_injection_detection
description: Detect SQL injection in web logs
severity: high
condition:
  all_of:
    - field: url
      regex: "(UNION|SELECT|DROP|INSERT).*"
    - field: status_code
      equals: [403, 400, 500]
    - field: user_agent
      not_equals: "HealthCheck/1.0"
threshold:
  count: 3
  timeframe: 5m
actions:
  - alert_security_team
  - block_source_ip
  - log_to_siem
```

### Example: Network Anomaly Detection

```yaml
rule: beaconing_detection
description: Detect C2 beaconing patterns
severity: critical
condition:
  statistical:
    field: connection_interval
    metric: coefficient_of_variation
    threshold: < 0.15  # Low variance = regular
minimum_connections: 10
timeframe: 1h
actions:
  - isolate_host
  - capture_traffic
  - immediate_investigation
```

---

## Next Steps

- [Log Analysis Techniques](03-log-analysis-techniques.md)
- [Incident Response Playbooks](04-incident-response-playbooks.md)
- [Hands-on Practice](../Net4nSICs.ipynb)

---

*"The best time to detect an attack is before it succeeds"*
