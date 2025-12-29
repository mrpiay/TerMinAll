# Net4nSICs Quick Start Guide

## 5-Minute Introduction to Network Forensics

### What is Net4nSICs?

**Net4nSICs** is a hands-on network forensics learning framework that teaches you to:
- Analyze security logs using command-line tools
- Detect attacks and malicious activity
- Investigate security incidents
- Preserve digital evidence

The name combines three meanings:
- **Network Forensics** (sounds like "4nSICs")
- **[sic]** - Latin for "thus/as found" (evidence preservation)
- **SIC** - **S**ecurity **I**ncident **C**ases

---

## Instant Practice (Zero Install)

### Option 1: Google Colab (Recommended)
1. Click: [Open in Colab](https://colab.research.google.com/github/YOUR_USERNAME/Net4nSICs/blob/main/Net4nSICs.ipynb)
2. Run the first cell to generate sample logs
3. Start analyzing attacks!

### Option 2: Local Setup
```bash
git clone https://github.com/YOUR_USERNAME/Net4nSICs.git
cd Net4nSICs
python3 generate_sample_data.py
```

---

## Your First Investigation

### 1. View the Evidence
```bash
# See what logs we have
ls -lh *.log

# Peek at network traffic
head network_traffic.log
```

### 2. Find the Attacker
```bash
# Who's doing port scans?
grep "\[SYN\]" network_traffic.log | \
  awk '{print $2}' | cut -d: -f1 | \
  sort | uniq -c | sort -rn
```

**Result**: You'll find IP `91.219.236.131` scanned 80 ports!

### 3. What Did They Try?
```bash
# Check firewall blocks
grep "91.219.236.131" firewall.log | grep DROP | wc -l

# Check web attacks
grep "91.219.236.131" web_access.log | grep -E "(UNION|SELECT|<script>)"

# Check SSH brute force
grep "91.219.236.131" ssh_auth.log | grep "Failed password" | wc -l
```

### 4. Build the Attack Timeline
```bash
# All activity from this attacker, sorted by time
{
  grep "91.219.236.131" network_traffic.log | sed 's/^/[NET] /'
  grep "91.219.236.131" firewall.log | sed 's/^/[FW] /'
  grep "91.219.236.131" web_access.log | sed 's/^/[WEB] /'
  grep "91.219.236.131" ssh_auth.log | sed 's/^/[SSH] /'
} | sort | head -20
```

**Congratulations!** You just completed your first forensic investigation! 🎉

---

## Essential Commands (Copy-Paste Ready)

### Find Attack Types
```bash
# SQL Injection
grep -E "(UNION|SELECT|DROP)" web_access.log

# XSS Attempts
grep -i "<script>" web_access.log

# Brute Force
grep -c "Failed password" ssh_auth.log

# DNS Tunneling
awk '{if (length($6) > 30) print}' dns_queries.log
```

### Count and Sort
```bash
# Top attacking IPs
grep "DROP" firewall.log | \
  sed 's/.*src=\([^ ]*\).*/\1/' | \
  sort | uniq -c | sort -rn | head -10

# Most targeted usernames
grep "Failed password" ssh_auth.log | \
  awk '{print $9}' | \
  sort | uniq -c | sort -rn
```

### Extract Specific Data
```bash
# All IP addresses
grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' network_traffic.log | sort -u

# All email addresses
grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' web_access.log

# User-Agent strings
grep -o '"[^"]*"$' web_access.log | sort | uniq -c | sort -rn
```

---

## Learning Path

### Week 1: Foundations
- [x] Run Quick Start (you're here!)
- [ ] Read [Network Forensics Fundamentals](01-network-forensics-fundamentals.md)
- [ ] Complete beginner exercises in [Net4nSICs.ipynb](../Net4nSICs.ipynb)
- [ ] Practice with [Command Cheat Sheet](reference/command-cheatsheet.md)

### Week 2: Attack Detection
- [ ] Study [Attack Detection Methodology](02-attack-detection-methodology.md)
- [ ] Learn attack patterns from [Attack Patterns Reference](reference/attack-patterns.md)
- [ ] Complete intermediate exercises
- [ ] Try [TerMinAll.ipynb](../TerMinAll.ipynb) for command-line mastery

### Week 3: Advanced Analysis
- [ ] Master [Log Analysis Techniques](03-log-analysis-techniques.md)
- [ ] Build custom detection scripts
- [ ] Complete advanced and expert exercises
- [ ] Create your own attack scenarios

---

## Common Questions

### Q: Do I need to be a programmer?
**A:** No! If you can copy-paste commands, you can start. Skills build progressively.

### Q: What if I get stuck?
**A:** Each exercise has collapsible solutions. Click "💡 Click to see solution" to reveal.

### Q: Can I use this for certification prep?
**A:** Yes! This helps with GCFA, GNFA, CEH, OSCP, and Security+.

### Q: Is this legal to practice?
**A:** Yes! All data is synthetic. No real attacks or victims involved.

### Q: What if I want to analyze real logs?
**A:** Start here to learn techniques, then apply to sanitized production logs (with permission).

---

## Three Command Patterns You'll Use Daily

### 1. Filter → Extract → Count
```bash
grep "ERROR" logs.txt | awk '{print $3}' | sort | uniq -c
#    ↓                  ↓                  ↓      ↓
# Find lines         Get column        Sort   Count
```

### 2. Time-Window Analysis
```bash
awk '$1 >= "2025-01-15" && $1 <= "2025-01-16"' logs.txt
#    ↓
# Filter by date range
```

### 3. Cross-Log Correlation
```bash
# Find IPs in both failed SSH and web attacks
comm -12 <(awk '{print $11}' ssh.log | sort -u) \
         <(awk '{print $1}' web.log | sort -u)
```

---

## Your Investigation Checklist

When analyzing an incident:

- [ ] Preserve original logs (work on copies)
- [ ] Identify the time window
- [ ] Find the attacker IP/username
- [ ] Determine attack types used
- [ ] Check what was accessed/modified
- [ ] Build a timeline
- [ ] Document findings
- [ ] Recommend mitigations

---

## What Makes Net4nSICs Different?

✅ **Hands-on** - Learn by doing, not reading
✅ **Realistic** - Real attack patterns, real techniques
✅ **Progressive** - Beginner to expert path
✅ **Interactive** - Notebooks with instant feedback
✅ **Practical** - Transfer skills to real jobs
✅ **Free** - Open source, no paywalls

---

## Next Steps

1. **Pick your path**:
   - Visual learner? → [Net4nSICs.ipynb](../Net4nSICs.ipynb)
   - Deep dive? → [Tutorial series](README.md)
   - Quick reference? → [Cheat sheet](reference/command-cheatsheet.md)

2. **Join the community**:
   - Star the repo on GitHub
   - Share your findings
   - Contribute attack scenarios
   - Help others learn

3. **Practice daily**:
   - One exercise per day
   - Build your own detection rules
   - Analyze public datasets
   - Share your scripts

---

## Emergency Cheat Sheet

**I need to find...**

| What | Command |
|------|---------|
| Top attacking IPs | `awk '{print $1}' log.txt \| sort \| uniq -c \| sort -rn \| head` |
| Failed logins | `grep -c "Failed password" ssh.log` |
| SQL injection | `grep -E "(UNION\|SELECT)" web.log` |
| Large transfers | `awk '$5 > 10000000' network.log` |
| Off-hours activity | `awk '{h=substr($2,1,2); if (h<6 \|\| h>20) print}' log.txt` |
| Suspicious domains | `grep -E "\.(tk\|ml\|xyz)" dns.log` |

---

## Resources

- 📚 [Full Tutorial Series](README.md)
- 🔧 [Hands-on Notebook](../Net4nSICs.ipynb)
- 📖 [Command Reference](reference/command-cheatsheet.md)
- 🎯 [Attack Patterns](reference/attack-patterns.md)

---

**Ready to become a network forensics expert?**

Start with the [hands-on notebook](../Net4nSICs.ipynb) and learn by investigating real attack scenarios!

*Remember: In forensics, preserve evidence [sic] - as found, unaltered* 🔍🛡️
