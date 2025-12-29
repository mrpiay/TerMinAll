# Log Analysis Techniques

## Command-Line Tools Mastery

### SED - Stream Editor

#### Basic Substitution
```bash
# Replace first occurrence
sed 's/ERROR/CRITICAL/' logs.txt

# Replace all occurrences (global)
sed 's/ERROR/CRITICAL/g' logs.txt

# Case-insensitive replace
sed 's/error/CRITICAL/gi' logs.txt
```

#### Deletion
```bash
# Delete lines containing pattern
sed '/DEBUG/d' logs.txt

# Delete empty lines
sed '/^$/d' logs.txt

# Delete line numbers 1-5
sed '1,5d' logs.txt

# Delete from pattern to end
sed '/ERROR/,$d' logs.txt
```

#### Insertion and Appending
```bash
# Insert line before pattern
sed '/ERROR/i === CRITICAL EVENT ===' logs.txt

# Append line after pattern
sed '/ERROR/a Check system immediately' logs.txt

# Insert at specific line number
sed '10i New line inserted' logs.txt
```

#### Capture Groups and Back-References
```bash
# Extract IP addresses
sed -n 's/.*IP: \([0-9.]*\).*/\1/p' logs.txt

# Reformat dates YYYY-MM-DD to DD/MM/YYYY
sed 's/\([0-9]\{4\}\)-\([0-9]\{2\}\)-\([0-9]\{2\}\)/\3\/\2\/\1/' logs.txt

# Swap first two fields
sed 's/\([^ ]*\) \([^ ]*\)/\2 \1/' data.txt
```

#### Advanced: Multi-Line Operations
```bash
# Join lines ending with backslash
sed ':a;N;$!ba;s/\\\n//g' multiline.txt

# Delete duplicate consecutive lines
sed '$!N; /^\(.*\)\n\1$/!P; D' logs.txt
```

### GREP - Pattern Matching

#### Basic Searches
```bash
# Case-insensitive search
grep -i "error" logs.txt

# Invert match (lines NOT containing pattern)
grep -v "DEBUG" logs.txt

# Count matches
grep -c "ERROR" logs.txt

# Show line numbers
grep -n "ERROR" logs.txt

# Show only filenames
grep -l "ERROR" *.log
```

#### Regular Expressions
```bash
# Match IP addresses
grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" logs.txt

# Match email addresses
grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" logs.txt

# Match beginning of line
grep "^ERROR" logs.txt

# Match end of line
grep "timeout$" logs.txt

# Match word boundaries
grep -w "fail" logs.txt  # Matches "fail" but not "failed"
```

#### Context Display
```bash
# Show 2 lines before match
grep -B 2 "ERROR" logs.txt

# Show 2 lines after match
grep -A 2 "ERROR" logs.txt

# Show 2 lines before and after (context)
grep -C 2 "ERROR" logs.txt
```

#### Advanced Patterns
```bash
# Multiple patterns (OR)
grep -E "ERROR|CRITICAL|FATAL" logs.txt

# Multiple patterns (AND) - two-stage filter
grep "ERROR" logs.txt | grep "database"

# Recursive search in directories
grep -r "ERROR" /var/log/

# Search in compressed files
zgrep "ERROR" logs.gz
```

### AWK - Field Processing

#### Printing Columns
```bash
# Print specific column
awk '{print $3}' logs.txt

# Print multiple columns
awk '{print $1, $3, $5}' logs.txt

# Print with custom separator
awk '{print $1 ":" $2}' logs.txt

# Print last column
awk '{print $NF}' logs.txt

# Print all but first column
awk '{$1=""; print $0}' logs.txt
```

#### Field Separators
```bash
# Comma-separated values
awk -F, '{print $2}' data.csv

# Multiple character separator
awk -F": " '{print $2}' logs.txt

# Tab-separated
awk -F'\t' '{print $1, $3}' data.tsv
```

#### Conditional Processing
```bash
# Print lines where column 3 > 100
awk '$3 > 100 {print}' data.txt

# Print lines matching pattern
awk '/ERROR/ {print $1, $2}' logs.txt

# Multiple conditions (AND)
awk '$3 > 100 && $4 == "active" {print}' data.txt

# Multiple conditions (OR)
awk '$3 > 100 || $4 == "critical" {print}' data.txt
```

#### Skip Headers
```bash
# Skip first line
awk 'NR>1 {print}' data.csv

# Skip first 5 lines
awk 'NR>5 {print}' logs.txt

# Process only lines 10-20
awk 'NR>=10 && NR<=20 {print}' logs.txt
```

#### Calculations and Aggregation
```bash
# Sum column
awk '{sum+=$3} END {print sum}' data.txt

# Average
awk '{sum+=$3; count++} END {print sum/count}' data.txt

# Count occurrences
awk '{count[$1]++} END {for (i in count) print i, count[i]}' logs.txt

# Find maximum
awk 'BEGIN {max=0} {if ($3>max) max=$3} END {print max}' data.txt

# Count lines per category
awk '{count[$2]++} END {for (c in count) print c":", count[c]}' data.txt
```

#### Formatted Output
```bash
# Printf formatting
awk '{printf "%-15s %10.2f\n", $1, $2}' data.txt

# Fixed-width columns
awk 'BEGIN {printf "%-10s %-20s %8s\n", "ID", "NAME", "VALUE"}
     {printf "%-10s %-20s %8d\n", $1, $2, $3}' data.txt

# Add thousand separators
awk '{printf "%\047d\n", $1}' numbers.txt
```

#### BEGIN and END Blocks
```bash
# Print header
awk 'BEGIN {print "=== REPORT ==="} {print} END {print "=== END ==="}' logs.txt

# Initialize variables
awk 'BEGIN {count=0; sum=0} {count++; sum+=$1} END {print sum/count}' data.txt

# Set output field separator
awk 'BEGIN {OFS=","} {print $1, $2, $3}' data.txt
```

---

## Analysis Patterns

### Pattern 1: Frequency Analysis

**Count occurrences of each event type:**
```bash
awk '{print $3}' logs.txt | sort | uniq -c | sort -rn
```

**Top 10 source IPs:**
```bash
awk '{print $2}' network.log | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
```

### Pattern 2: Time-Series Analysis

**Events per hour:**
```bash
awk '{print substr($2, 1, 2)}' logs.txt | sort | uniq -c
```

**Plot daily trends:**
```bash
awk '{print substr($1, 1, 10)}' logs.txt | sort | uniq -c
```

### Pattern 3: Threshold Detection

**IPs with >100 requests:**
```bash
awk '{count[$1]++} END {for (ip in count) if (count[ip]>100) print ip, count[ip]}' access.log
```

**Failed logins >5 per user:**
```bash
grep "Failed" auth.log | awk '{count[$9]++} END {for (u in count) if (count[u]>5) print u, count[u]}'
```

### Pattern 4: Correlation

**Find IPs in both SSH and web logs:**
```bash
# Extract IPs from each log
awk '{print $1}' ssh.log | sort -u > ssh_ips.txt
awk '{print $1}' web.log | sort -u > web_ips.txt

# Find common IPs
comm -12 ssh_ips.txt web_ips.txt
```

### Pattern 5: Anomaly Detection

**Find unusual port numbers:**
```bash
# Extract all destination ports
awk '{print $4}' network.log | cut -d: -f2 | sort | uniq -c | sort -n | tail -20

# Find ports with only 1-2 connections (suspicious)
awk '{print $4}' network.log | cut -d: -f2 | sort | uniq -c | awk '$1 < 3 {print}'
```

**Detect time anomalies (off-hours activity):**
```bash
# Extract hour from timestamp
awk '{hour=substr($2, 1, 2); if (hour<6 || hour>20) print}' logs.txt
```

---

## Pipeline Recipes

### Recipe 1: Attack Source Analysis
```bash
# Find top attack sources with attack types
grep "DROP" firewall.log | \
  sed 's/.*src=\([^ ]*\).*/\1/' | \
  sort | uniq -c | sort -rn | head -10
```

### Recipe 2: Web Attack Summary
```bash
# Count attacks by type
{
  echo "SQL Injection: $(grep -c 'UNION\|SELECT' web.log)"
  echo "XSS: $(grep -c '<script>' web.log)"
  echo "Directory Traversal: $(grep -c '\.\.' web.log)"
  echo "Command Injection: $(grep -c ';\s*\(cat\|ls\|whoami\)' web.log)"
}
```

### Recipe 3: Failed Login Analysis
```bash
# Extract username and IP from failed logins
grep "Failed password" ssh.log | \
  awk '{print "User:", $9, "IP:", $11}' | \
  sort | uniq -c | sort -rn
```

### Recipe 4: DNS Tunneling Detection
```bash
# Find suspiciously long DNS queries
awk '{if (length($6) > 30) print $1, $2, $6, length($6)}' dns.log | \
  sort -k4 -rn
```

### Recipe 5: C2 Beacon Interval Calculation
```bash
# Calculate time differences between connections
grep "45.142.212.61" network.log | \
  awk '{print $1, $2}' | \
  awk '{
    if (prev) {
      cmd = "date -d \""$1" "$2"\" +%s"
      cmd | getline curr
      close(cmd)
      print curr - prev, "seconds"
    }
    cmd = "date -d \""$1" "$2"\" +%s"
    cmd | getline prev
    close(cmd)
  }'
```

### Recipe 6: User Agent Analysis
```bash
# Extract and count unique user agents
grep -o '"[^"]*"$' web.log | sort | uniq -c | sort -rn
```

### Recipe 7: Geolocation Anomaly
```bash
# Identify IPs from unexpected countries (requires geoip)
awk '{print $1}' access.log | \
  sort -u | \
  while read ip; do
    country=$(geoiplookup $ip | cut -d: -f2 | tr -d ' ')
    if [[ ! "$country" =~ US|CA|GB ]]; then
      echo "$ip -> $country"
    fi
  done
```

---

## Advanced Techniques

### Multi-Log Correlation Script
```bash
#!/bin/bash
# correlate_attack.sh - Track an IP across all logs

IP="$1"

echo "=== Activity for $IP ==="
echo ""

echo "[NETWORK TRAFFIC]"
grep "$IP" network_traffic.log | wc -l
echo "connections"

echo ""
echo "[FIREWALL BLOCKS]"
grep "$IP" firewall.log | grep DROP | wc -l
echo "blocked attempts"

echo ""
echo "[WEB ATTACKS]"
grep "$IP" web_access.log | grep -E "(UNION|SELECT|<script>|\.\.)" | wc -l
echo "attack attempts"

echo ""
echo "[SSH ATTEMPTS]"
grep "$IP" ssh_auth.log | grep -E "(Failed|Invalid)" | wc -l
echo "failed logins"

echo ""
echo "[TIMELINE]"
{
  grep "$IP" network_traffic.log | awk '{print $1, $2, "[NET]", $0}'
  grep "$IP" firewall.log | awk '{print $1, $2, "[FW]", $0}'
  grep "$IP" ssh_auth.log | awk '{print $1, $2, "[SSH]", $0}'
} | sort | head -20
```

### Statistical Analysis with AWK
```bash
# Calculate mean, median, stdev of connection sizes
awk '{sizes[NR]=$5; sum+=$5; sumsq+=$5*$5}
     END {
       mean=sum/NR
       variance=sumsq/NR - mean*mean
       stdev=sqrt(variance)

       # Sort for median
       asort(sizes)
       median = NR%2 ? sizes[(NR+1)/2] : (sizes[NR/2]+sizes[NR/2+1])/2

       printf "Mean: %.2f\n", mean
       printf "Median: %.2f\n", median
       printf "StdDev: %.2f\n", stdev
     }' network.log
```

### JSON Log Parsing
```bash
# Extract specific fields from JSON logs
cat app.log | \
  grep -o '"timestamp":"[^"]*"' | cut -d'"' -f4

# More complex: extract nested values
cat app.log | \
  sed 's/.*"user":{"id":"\([^"]*\)".*$/\1/'
```

---

## Performance Optimization

### 1. Process Large Files Efficiently
```bash
# Don't: Load entire file
grep "ERROR" hugefile.log | sort | uniq -c

# Do: Stream processing
grep "ERROR" hugefile.log | sort | uniq -c

# Best: Parallel processing
parallel -j 4 grep "ERROR" ::: file1.log file2.log file3.log file4.log
```

### 2. Reduce Memory Usage
```bash
# Don't: Store all in memory
awk '{lines[NR]=$0} END {for (i in lines) print lines[i]}' large.log

# Do: Stream processing
awk '{print}' large.log
```

### 3. Use Appropriate Tools
```bash
# Slow: sed for simple extraction
sed -n 's/.*IP: \([0-9.]*\).*/\1/p' logs.txt

# Fast: grep for extraction
grep -oP 'IP: \K[0-9.]+' logs.txt

# Fastest: cut for fixed position
cut -d' ' -f3 logs.txt
```

---

## Common Mistakes and Solutions

### Mistake 1: Not Escaping Special Characters
```bash
# Wrong: . matches any character
grep "192.168.1.1" logs.txt

# Right: Escape the dots
grep "192\.168\.1\.1" logs.txt
```

### Mistake 2: Incorrect Quoting
```bash
# Wrong: Variable expansion in single quotes
grep '$pattern' logs.txt

# Right: Use double quotes
grep "$pattern" logs.txt
```

### Mistake 3: Not Anchoring Patterns
```bash
# Wrong: Matches "error" anywhere in word
grep "error" logs.txt  # Matches "errors", "printerror"

# Right: Match whole word
grep -w "error" logs.txt
```

### Mistake 4: Inefficient Pipelines
```bash
# Inefficient: Multiple grep calls
cat logs.txt | grep "ERROR" | grep "database" | grep "timeout"

# Better: Single grep with all patterns
grep "ERROR.*database.*timeout" logs.txt

# Or: Extended regex
grep -E "ERROR.*database.*timeout" logs.txt
```

---

## Forensic Analysis Checklist

- [ ] Preserve original logs (create copies)
- [ ] Verify log integrity (check timestamps)
- [ ] Normalize time zones (convert to UTC)
- [ ] Identify log format and fields
- [ ] Extract relevant time window
- [ ] Filter noise (DEBUG, INFO)
- [ ] Identify anomalies
- [ ] Correlate across sources
- [ ] Document findings
- [ ] Create timeline
- [ ] Generate report

---

## Next Steps

- [Incident Response Playbooks](04-incident-response-playbooks.md)
- [Command Reference Sheet](reference/command-cheatsheet.md)
- [Practice Exercises](../Net4nSICs.ipynb)

---

*"The art of log analysis is finding signal in the noise"*
