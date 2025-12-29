# Net4nSICs Tutorials

> **Net4nSICs** = Network **Forensics** (4nSICs)
> **[sic]** = Latin "thus/as found" - Preserving evidence in its original state
> **SIC** = **S**ecurity **I**ncident **C**ases

Welcome to the Net4nSICs tutorial collection! These guides provide comprehensive coverage of network forensics, attack detection, and log analysis techniques using command-line tools.

## 📚 Tutorial Series

### Core Tutorials

1. **[Network Forensics Fundamentals](01-network-forensics-fundamentals.md)**
   - Evidence preservation principles
   - Log types and their uses
   - Collection methodologies
   - Timeline construction
   - Indicators of Compromise (IOCs)
   - Analysis workflow
   - Best practices and pitfalls

2. **[Attack Detection Methodology](02-attack-detection-methodology.md)**
   - Detection approaches (signature vs. anomaly)
   - Attack taxonomy (recon, web apps, brute force, C2, exfiltration)
   - Attack kill chain
   - MITRE ATT&CK mapping
   - Correlation techniques
   - Automated detection rules

3. **[Log Analysis Techniques](03-log-analysis-techniques.md)**
   - Command-line tools mastery (SED, GREP, AWK)
   - Analysis patterns
   - Pipeline recipes
   - Advanced techniques
   - Performance optimization
   - Common mistakes and solutions

### Reference Materials

- **[Command Cheat Sheet](reference/command-cheatsheet.md)**
  - Quick reference for SED, GREP, AWK
  - Common forensic patterns
  - Regular expressions
  - One-liners for investigation
  - Performance tips

- **[Attack Patterns Reference](reference/attack-patterns.md)**
  - Signatures for common attacks
  - Detection rules
  - Mitigation strategies

## 🎯 Learning Path

### Beginner Track
1. Start with [Network Forensics Fundamentals](01-network-forensics-fundamentals.md)
2. Practice with basic exercises in [Net4nSICs.ipynb](../Net4nSICs.ipynb)
3. Use the [Command Cheat Sheet](reference/command-cheatsheet.md) as reference

### Intermediate Track
1. Study [Attack Detection Methodology](02-attack-detection-methodology.md)
2. Learn [Log Analysis Techniques](03-log-analysis-techniques.md)
3. Complete intermediate and advanced exercises

### Advanced Track
1. Deep dive into correlation techniques
2. Build custom detection rules
3. Create automated analysis scripts
4. Practice incident response scenarios

## 🔧 Hands-On Practice

Each tutorial includes practical examples. To practice:

1. **Run the Interactive Notebook**: [Net4nSICs.ipynb](../Net4nSICs.ipynb)
   - Generates realistic attack data
   - Provides guided exercises
   - Includes collapsible solutions

2. **Use the Sample Data Generator**: [generate_sample_data.py](../generate_sample_data.py)
   - Creates 6 types of security logs
   - Includes embedded attack scenarios
   - Can be run locally or in Colab

3. **Try the Command-Line Tutorial**: [TerMinAll.ipynb](../TerMinAll.ipynb)
   - Comprehensive SED, GREP, AWK training
   - 10 progressive exercises
   - Transferable skills for any log analysis

## 📊 Attack Scenarios Covered

The tutorials use realistic examples including:

- **Port Scanning** - Network reconnaissance from 91.219.236.131
- **SQL Injection** - Web application attacks using sqlmap
- **Cross-Site Scripting (XSS)** - Client-side injection attempts
- **SSH Brute Force** - 50+ authentication attempts
- **DNS Tunneling** - Data exfiltration via DNS queries
- **C2 Beaconing** - Regular callbacks to 45.142.212.61
- **DGA Domains** - Malware command & control
- **Directory Traversal** - Path manipulation attacks

## 💡 Key Concepts

### The [sic] Principle
In forensics, *sic* (Latin for "thus") means evidence is preserved exactly as found:
- No alteration of original data
- Work with copies only
- Document all actions
- Maintain chain of custody
- Verify integrity with hashes

### The Five W's
Every investigation answers:
- **Who**: Attacker identity and attribution
- **What**: Attack type and techniques used
- **When**: Timeline and duration
- **Where**: Affected systems and data
- **Why**: Attacker motivation

### MITRE ATT&CK Framework
Map detected activities to the kill chain:
- Reconnaissance → Initial Access → Execution → Persistence →
- Privilege Escalation → Defense Evasion → Credential Access →
- Discovery → Lateral Movement → Collection → Exfiltration → Impact

## 🛠️ Tools Covered

### Command-Line Tools
- **SED**: Stream editing and text transformation
- **GREP**: Pattern matching and extraction
- **AWK**: Field processing and calculations
- **CUT**: Column extraction
- **SORT/UNIQ**: Deduplication and counting
- **WC**: Line/word/character counting

### Analysis Techniques
- Frequency analysis
- Time-series analysis
- Threshold detection
- Anomaly detection
- Cross-log correlation
- Statistical analysis

## 📖 Additional Resources

### Complementary Learning
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SANS Reading Room](https://www.sans.org/reading-room/)

### Community
- Share your findings and scripts
- Contribute new attack scenarios
- Report issues or suggest improvements
- Create pull requests with enhancements

## 🎓 Certification Preparation

These tutorials help prepare for:
- **GCFA** (GIAC Certified Forensic Analyst)
- **GNFA** (GIAC Network Forensic Analyst)
- **CEH** (Certified Ethical Hacker)
- **OSCP** (Offensive Security Certified Professional)
- **Security+** (CompTIA Security+)

## 📝 Contributing

Found something that could be improved?
1. Open an issue describing the enhancement
2. Fork the repository
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License - Free for learning and teaching

## 🙏 Acknowledgments

Built with inspiration from:
- Real-world incident response experience
- SANS forensic courses
- MITRE ATT&CK framework
- Open-source security community

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/Net4nSICs.git
cd Net4nSICs

# Generate sample data
python3 generate_sample_data.py

# Start analyzing!
grep "ERROR" *.log
awk -F, 'NR>1 {print $2}' users.csv
sed 's/TODO/DONE/g' sample.txt
```

Or **jump straight into** [Google Colab](https://colab.research.google.com/github/YOUR_USERNAME/Net4nSICs/blob/main/Net4nSICs.ipynb) with zero setup!

---

*"In forensics, we don't guess - we analyze [sic]"*

Happy hunting! 🔍🛡️
