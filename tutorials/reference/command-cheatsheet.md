# Command-Line Forensics Cheat Sheet

## Quick Reference

### SED (Stream Editor)

| Command | Description | Example |
|---------|-------------|---------|
| `s/old/new/` | Replace first occurrence | `sed 's/ERROR/CRITICAL/' log.txt` |
| `s/old/new/g` | Replace all occurrences | `sed 's/ERROR/CRITICAL/g' log.txt` |
| `s/old/new/gi` | Case-insensitive replace | `sed 's/error/CRITICAL/gi' log.txt` |
| `/pattern/d` | Delete matching lines | `sed '/DEBUG/d' log.txt` |
| `/^$/d` | Delete empty lines | `sed '/^$/d' log.txt` |
| `/pattern/i text` | Insert before match | `sed '/ERROR/i ALERT' log.txt` |
| `/pattern/a text` | Append after match | `sed '/ERROR/a Check this' log.txt` |
| `-n '/pattern/p'` | Print only matches | `sed -n '/ERROR/p' log.txt` |

### GREP (Pattern Search)

| Command | Description | Example |
|---------|-------------|---------|
| `grep pattern` | Basic search | `grep "ERROR" log.txt` |
| `grep -i` | Case-insensitive | `grep -i "error" log.txt` |
| `grep -v` | Invert match | `grep -v "DEBUG" log.txt` |
| `grep -c` | Count matches | `grep -c "ERROR" log.txt` |
| `grep -n` | Show line numbers | `grep -n "ERROR" log.txt` |
| `grep -l` | Show filenames only | `grep -l "ERROR" *.log` |
| `grep -r` | Recursive search | `grep -r "ERROR" /var/log/` |
| `grep -A n` | Show n lines after | `grep -A 3 "ERROR" log.txt` |
| `grep -B n` | Show n lines before | `grep -B 3 "ERROR" log.txt` |
| `grep -C n` | Show n lines context | `grep -C 3 "ERROR" log.txt` |
| `grep -E` | Extended regex | `grep -E "ERROR\|CRITICAL" log.txt` |
| `grep -o` | Extract match only | `grep -o "[0-9.]\+" log.txt` |
| `grep -w` | Match whole word | `grep -w "error" log.txt` |

### AWK (Field Processing)

| Command | Description | Example |
|---------|-------------|---------|
| `{print $N}` | Print column N | `awk '{print $3}' data.txt` |
| `{print $NF}` | Print last column | `awk '{print $NF}' data.txt` |
| `-F` | Set field separator | `awk -F, '{print $2}' data.csv` |
| `NR>1` | Skip header row | `awk 'NR>1 {print}' data.csv` |
| `/pattern/` | Match pattern | `awk '/ERROR/ {print $1}' log.txt` |
| `$N > value` | Numeric filter | `awk '$3 > 100 {print}' data.txt` |
| `$N == "text"` | String filter | `awk '$2 == "active" {print}' data.txt` |
| `{sum+=$N}` | Sum column | `awk '{sum+=$3} END {print sum}' data.txt` |
| `{count++}` | Count lines | `awk '{count++} END {print count}' data.txt` |
| `BEGIN` | Run before input | `awk 'BEGIN {print "Start"}' data.txt` |
| `END` | Run after input | `awk 'END {print "Done"}' data.txt` |
| `{count[$N]++}` | Count occurrences | `awk '{count[$1]++} END {for (i in count) print i, count[i]}' data.txt` |

### Useful Combinations

| Task | Command |
|------|---------|
| **Count unique IPs** | `awk '{print $1}' log.txt \| sort \| uniq -c` |
| **Top 10 IPs** | `awk '{print $1}' log.txt \| sort \| uniq -c \| sort -rn \| head -10` |
| **Extract IP addresses** | `grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' log.txt` |
| **Extract email addresses** | `grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' log.txt` |
| **Count errors per hour** | `awk '{print substr($2,1,2)}' log.txt \| sort \| uniq -c` |
| **Remove duplicates** | `sort log.txt \| uniq` |
| **Find common lines in 2 files** | `comm -12 <(sort file1.txt) <(sort file2.txt)` |

---

## Network Forensics Patterns

### Port Scan Detection
```bash
# Count unique destination ports per source IP
awk '{print $2, $4}' network.log | cut -d: -f1,2 | awk '{src=$1; dst=$2; count[src]++} END {for (ip in count) print ip, count[ip]}' | awk '$2 > 20'
```

### SQL Injection Detection
```bash
# Find SQL keywords in web logs
grep -E "(UNION|SELECT|DROP|INSERT|'--)" web.log
```

### Brute Force Detection
```bash
# Count failed logins per IP
grep "Failed password" ssh.log | awk '{print $11}' | sort | uniq -c | sort -rn
```

### DNS Tunneling Detection
```bash
# Find suspiciously long DNS queries
awk '{if (length($6) > 30) print $1, $2, $6}' dns.log
```

### C2 Beaconing Detection
```bash
# Find regular interval connections
grep "TARGET_IP" network.log | awk '{print $1, $2}' | head -20
```

---

## Regular Expressions

### Common Patterns

| Pattern | Matches | Example |
|---------|---------|---------|
| `.` | Any character | `a.c` matches "abc", "a9c" |
| `*` | Zero or more | `ab*c` matches "ac", "abc", "abbc" |
| `+` | One or more | `ab+c` matches "abc", "abbc" (not "ac") |
| `?` | Zero or one | `ab?c` matches "ac", "abc" |
| `^` | Start of line | `^ERROR` matches lines starting with ERROR |
| `$` | End of line | `timeout$` matches lines ending with timeout |
| `[abc]` | Character class | `[aeiou]` matches any vowel |
| `[^abc]` | Negated class | `[^0-9]` matches non-digits |
| `\d` | Digit | `\d+` matches one or more digits |
| `\w` | Word character | `\w+` matches word |
| `\s` | Whitespace | `\s+` matches spaces/tabs |
| `\b` | Word boundary | `\bword\b` matches "word" not "sword" |
| `(...)` | Capture group | `([0-9]+)` captures number |
| `\|` | Alternation (OR) | `cat\|dog` matches "cat" or "dog" |

### Forensic Regex Examples

**IPv4 Address**:
```regex
[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
```

**Email Address**:
```regex
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
```

**URL**:
```regex
https?://[a-zA-Z0-9.-]+(/[a-zA-Z0-9._-]*)*
```

**MAC Address**:
```regex
([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}
```

**Credit Card (for DLP)**:
```regex
\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b
```

**SSH Private Key**:
```regex
-----BEGIN.*PRIVATE KEY-----
```

---

## One-Liners for Common Tasks

### Investigation Starters

```bash
# Quick overview of log file
head -100 log.txt | tail -20

# Find unique event types
awk '{print $3}' log.txt | sort -u

# Count events by type
awk '{print $3}' log.txt | sort | uniq -c | sort -rn

# Extract time range
awk '$1 >= "2025-01-15" && $1 <= "2025-01-16"' log.txt

# Find long-running connections
awk '{diff=$5-$4; if (diff > 3600) print}' connections.log
```

### Attack Detection

```bash
# Find IPs hitting many different URLs
awk '{print $1, $7}' access.log | sort -u | cut -d' ' -f1 | uniq -c | sort -rn

# Detect password spraying
awk '{print $1, $9}' ssh.log | sort -u | cut -d' ' -f1 | uniq -c | awk '$1 > 10'

# Find DGA domains (NXDOMAIN responses)
awk '/NXDOMAIN/ {print $6}' dns.log | sed 's/\..*//' | awk 'length($1) > 10'

# Identify beaconing (connections at regular intervals)
grep "EXTERNAL_IP" network.log | awk '{print $2}' | awk '{if (NR>1) print $1-prev; prev=$1}'
```

### Data Extraction

```bash
# Extract all IPs (source and destination)
grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' log.txt | sort -u

# Extract all URLs
grep -oE 'https?://[^ "]+' log.txt

# Extract user-agent strings
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn

# Create CSV from logs
awk '{print $1","$2","$3}' log.txt > output.csv
```

### Reporting

```bash
# Generate summary statistics
echo "Total lines: $(wc -l < log.txt)"
echo "Errors: $(grep -c ERROR log.txt)"
echo "Warnings: $(grep -c WARNING log.txt)"
echo "Unique IPs: $(awk '{print $1}' log.txt | sort -u | wc -l)"

# Create timeline of events
awk '{print $1, $2, $3}' log.txt | sort

# Top 10 report
echo "=== TOP 10 SOURCE IPS ==="
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -10
```

---

## Performance Tips

1. **Use grep before awk/sed** - Filter first, process later
   ```bash
   # Good: Filter then process
   grep "ERROR" huge.log | awk '{print $1, $2}'

   # Bad: Process everything
   awk '/ERROR/ {print $1, $2}' huge.log
   ```

2. **Avoid unnecessary sorting**
   ```bash
   # If you only need counts, sort once
   awk '{print $1}' log.txt | sort | uniq -c | sort -rn
   ```

3. **Use field cuts instead of awk for simple extraction**
   ```bash
   # Faster
   cut -d' ' -f1 log.txt

   # Slower
   awk '{print $1}' log.txt
   ```

4. **Process in parallel**
   ```bash
   # Split large file and process in parallel
   parallel -j 4 grep "ERROR" ::: file1.log file2.log file3.log file4.log
   ```

---

## Debugging Your Commands

### Test with Small Samples
```bash
# Don't run on entire file first
head -100 large.log | your_command

# Or use a small test file
grep "pattern" large.log | head -100 > test.log
your_command test.log
```

### Add Verbose Output
```bash
# See what sed is doing
sed -n 's/old/new/gp' log.txt

# See awk processing
awk '{print "Processing:", $0; ...}' log.txt
```

### Check Intermediate Results
```bash
# Break pipeline into steps
grep "ERROR" log.txt > step1.txt
awk '{print $1, $2}' step1.txt > step2.txt
sort step2.txt | uniq -c > final.txt
```

---

## Common Gotchas

1. **Forgetting to escape special characters**
   - Use `\.` not `.` for literal dot
   - Use `\$` not `$` for literal dollar sign

2. **Case sensitivity**
   - Use `-i` flag for case-insensitive matching
   - Or use `[Ee]rror` pattern

3. **Whitespace handling**
   - Default AWK separator is any whitespace
   - Use `-F` to specify exact delimiter

4. **Quote hell**
   - Use single quotes for literal strings
   - Use double quotes when variables needed
   - Escape quotes inside quotes: `"He said \"hello\""`

5. **Regex flavor differences**
   - `grep` uses basic regex by default
   - `grep -E` for extended regex
   - `sed` uses basic regex
   - AWK uses extended regex

---

*Quick reference for the Net4nSICs framework*
