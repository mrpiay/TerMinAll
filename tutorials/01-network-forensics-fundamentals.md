# Network Forensics Fundamentals

## Introduction

Network forensics is the capture, recording, and analysis of network events to discover the source of security attacks or other problem incidents. Unlike traditional digital forensics, network forensics deals with volatile and dynamic data.

## Core Principles

### 1. Preservation of Evidence [sic]

The Latin term *sic* ("thus/as found") embodies the fundamental principle of forensics:

- **Non-alteration**: Evidence must be preserved in its original state
- **Chain of custody**: Document every interaction with evidence
- **Integrity verification**: Use cryptographic hashes (MD5, SHA-256)
- **Write protection**: Work with copies, never originals

### 2. The Five W's of Network Forensics

Every investigation should answer:

- **Who**: Source IP, username, user agent
- **What**: Type of attack, malware, data accessed
- **When**: Timestamps, duration, frequency
- **Where**: Target systems, network segments
- **Why**: Motivation (financial, espionage, vandalism)

## Log Types and Their Purpose

### Network Traffic Logs
**Format**: Packet captures (PCAP), flow data (NetFlow)

**Contains**:
- Source/destination IPs and ports
- Protocols used
- Packet sizes and timing
- Connection states (SYN, ACK, FIN)

**Use cases**:
- Identify scanning activity
- Detect C2 communications
- Analyze data exfiltration

### Firewall Logs
**Format**: Structured logs with action (ACCEPT/DROP)

**Contains**:
- Source/destination information
- Action taken (allow/block)
- Rule matched
- Reason for block

**Use cases**:
- Identify blocked attacks
- Detect reconnaissance
- Monitor policy violations

### Web Server Logs
**Format**: Common/Combined Log Format (CLF)

**Contains**:
- Client IP and user agent
- Requested URLs
- HTTP status codes
- Referrer information

**Use cases**:
- Detect web application attacks
- Identify compromised accounts
- Track attacker reconnaissance

### Authentication Logs
**Format**: Syslog-style entries

**Contains**:
- Login attempts (success/failure)
- Source IP addresses
- Usernames attempted
- Authentication methods

**Use cases**:
- Detect brute force attacks
- Identify credential stuffing
- Track unauthorized access

### DNS Logs
**Format**: Query/response records

**Contains**:
- Queried domains
- Query types (A, AAAA, TXT, MX)
- Response codes (NXDOMAIN)
- Client IPs

**Use cases**:
- Detect DNS tunneling
- Identify DGA malware
- Track C2 communications

## Evidence Collection Methods

### 1. Full Packet Capture
**Tools**: tcpdump, Wireshark, tshark

```bash
# Capture all traffic on interface
tcpdump -i eth0 -w capture.pcap

# Capture specific protocol
tcpdump -i eth0 'tcp port 80' -w web_traffic.pcap
```

**Pros**: Complete visibility
**Cons**: Storage intensive, privacy concerns

### 2. Flow Data Collection
**Tools**: NetFlow, sFlow, IPFIX

**Pros**: Metadata only, scalable
**Cons**: No payload inspection

### 3. Log Aggregation
**Tools**: Syslog, rsyslog, syslog-ng

**Centralized collection benefits**:
- Tamper resistance
- Correlation across systems
- Long-term retention

## Timeline Construction

Correlating events across logs:

1. **Normalize timestamps** (convert to UTC)
2. **Align log sources** (account for clock skew)
3. **Sort chronologically**
4. **Identify patterns** (clustering, sequences)

### Example Timeline

```
2025-01-15 10:00:00 [NETWORK] Port scan detected from 91.219.236.131
2025-01-15 10:02:30 [FIREWALL] Multiple SYN packets blocked
2025-01-15 10:05:15 [WEB] SQL injection attempt on /login.php
2025-01-15 10:07:42 [AUTH] Failed login as 'admin' from attacker IP
2025-01-15 10:12:18 [IDS] Alert: Web application attack signature matched
```

## Indicators of Compromise (IOCs)

### Network-Based IOCs

**IP Addresses**:
- Known malicious IPs
- Tor exit nodes
- Suspicious geolocation

**Domain Names**:
- Recently registered domains
- DGA-generated names
- Typosquatting domains

**URLs**:
- Exploit kit URLs
- Phishing pages
- C2 endpoints

**Traffic Patterns**:
- Beaconing (regular intervals)
- Large uploads (exfiltration)
- Unusual ports

### Behavioral IOCs

- **Volume anomalies**: Sudden traffic spikes
- **Timing anomalies**: Activity during off-hours
- **Protocol anomalies**: HTTP on non-standard ports
- **Geographic anomalies**: Connections to unusual countries

## Analysis Workflow

### Phase 1: Preparation
- Define scope
- Identify data sources
- Establish baseline normal behavior

### Phase 2: Collection
- Gather relevant logs
- Preserve original evidence
- Document collection process

### Phase 3: Examination
- Parse and normalize data
- Filter noise
- Extract relevant events

### Phase 4: Analysis
- Correlate events
- Identify patterns
- Reconstruct attack timeline

### Phase 5: Reporting
- Document findings
- Provide recommendations
- Create executive summary

## Common Pitfalls

### 1. Confirmation Bias
- Don't assume first hypothesis is correct
- Look for contradictory evidence
- Consider alternative explanations

### 2. Incomplete Data
- Multiple log sources required
- Time gaps can hide activity
- Deleted logs may indicate compromise

### 3. Clock Skew
- Unsynchronized clocks distort timelines
- Always normalize to UTC
- Document time zones

### 4. Log Tampering
- Attackers may modify logs
- Check for gaps or inconsistencies
- Use write-once storage when possible

## Best Practices

1. **Automate collection**: Don't rely on manual gathering
2. **Centralize logs**: Single pane of glass for analysis
3. **Retain appropriately**: Balance storage vs. investigation needs
4. **Practice regularly**: Run tabletop exercises
5. **Document everything**: Chain of custody is critical
6. **Use version control**: Track analysis scripts and findings

## Legal Considerations

- **Authorization**: Ensure you have permission to monitor
- **Privacy**: Comply with data protection regulations
- **Evidence handling**: Maintain admissibility for court
- **Notification**: Know when to involve law enforcement

## Next Steps

- [Attack Detection Methodology](02-attack-detection-methodology.md)
- [Log Analysis Techniques](03-log-analysis-techniques.md)
- [Hands-on Exercises](../Net4nSICs.ipynb)

---

*Preserving evidence [sic] - as found, unaltered*
