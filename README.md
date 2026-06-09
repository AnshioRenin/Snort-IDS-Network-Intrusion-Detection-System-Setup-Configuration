# 🚨 Snort IDS — Network Intrusion Detection System Setup & Configuration

![Snort](https://img.shields.io/badge/Snort-IDS-CC0000?style=for-the-badge)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)
![Network Security](https://img.shields.io/badge/Network-Security-blue?style=for-the-badge)
![Module](https://img.shields.io/badge/Module-Communications%20%26%20Networking%20Security-orange?style=for-the-badge)

> **Module:** Communications and Networking Security (B9CY103) | Dublin Business School  
> Full setup, configuration, and testing of Snort IDS with 8 custom detection rules — successfully detecting ICMP reconnaissance, TCP port scans, SSH brute force, SQL injection attempts, and DNS zone transfer attacks in real time.

---

## 📌 Overview

This project demonstrates the complete setup and configuration of **Snort** — an open-source, rule-based Intrusion Detection System (IDS) — from directory structure creation through to live traffic monitoring and alert generation.

Custom detection rules were written for 8 distinct attack types, tested against live traffic, and verified through alert log analysis. The project confirms Snort's capability as a real-time network security monitoring tool.

**Alerts successfully triggered during testing:**
- ✅ ICMP echo request detection (reconnaissance)
- ✅ ICMP ping sweep (host discovery)
- ✅ TCP SYN port scan detection
- ✅ SSH brute force detection (port 22)
- ✅ Suspicious HTTP user-agent (scanner detection)
- ✅ SQL injection attempt (`%27` detection)
- ✅ FTP brute force detection (port 21)
- ✅ DNS zone transfer attempt (port 53)

---

## 🎯 Objectives

- Configure a complete Snort IDS environment from scratch on Kali Linux
- Write custom detection rules targeting 8 common attack patterns
- Run Snort in live monitoring mode against a test network interface
- Analyse generated alert logs and evaluate security implications
- Assess Snort's strengths and limitations as a network defence tool

---

## 🏗️ Directory Structure

```
/etc/snort/                    # Main configuration directory
├── snort.conf                 # Master configuration file
├── rules/
│   └── local.rules            # Custom detection rules
├── builtin_rules/             # Snort pre-configured rules
└── so_rules/                  # Shared object (dynamically loaded) rules

/var/log/snort/                # Alert and packet logs
/usr/local/lib/snort_plugins/  # Optional third-party plugins
```

### Setup Commands

```bash
# Create all required directories
sudo mkdir -p /etc/snort
sudo mkdir -p /etc/snort/rules
sudo mkdir -p /etc/snort/builtin_rules
sudo mkdir -p /etc/snort/so_rules
sudo mkdir -p /var/log/snort
sudo mkdir -p /usr/local/lib/snort_plugins
```

---

## ⚙️ Configuration

### snort.conf (Key Settings)

```bash
sudo nano /etc/snort/snort.conf
```

```lua
-- Network scope
HOME_NET = "10.0.2.0/24"      -- Internal network to monitor
EXTERNAL_NET = "any"           -- All external traffic analysed

-- Enable all rules by default
ips = {
    enable_builtin_rules = true,
    rules = local_rules
}

-- Alert output format
outputs = {
    alert_fast = {
        enabled = true,
        file = true,
        packet = true
    }
}

-- Include custom rules file
include = '/etc/snort/rules/local.rules'
```

---

## 📋 Custom Rules (local.rules)

8 custom rules written to detect common attack patterns:

```bash
sudo nano /etc/snort/rules/local.rules
```

### Rule 1 — ICMP Echo Request Detection
Alerts on any ICMP ping to the home network — indicates reconnaissance activity.
```
alert icmp any any -> $HOME_NET any (msg:"ICMP Test"; sid:1000001; rev:1;)
```

### Rule 2 — ICMP Ping Sweep
Detects multiple ICMP requests from the same source within 1 second — host discovery scanning.
```
alert icmp any any -> any any (msg:"ICMP Ping Sweep"; detection_filter:track by_src, count 5, seconds 1; sid:1000002; rev:1;)
```

### Rule 3 — TCP Port Scan
Flags multiple SYN packets from the same source — classic port scan behaviour.
```
alert tcp any any -> any any (msg:"Potential TCP Port Scan"; flags:S; detection_filter:track by_src, count 5, seconds 2; sid:1000003; rev:1;)
```

### Rule 4 — SSH Brute Force
Detects rapid repeated connection attempts to port 22 — automated brute force attacks.
```
alert tcp any any -> any 22 (msg:"Potential SSH Brute Force"; flags:S; flow:stateless; detection_filter:track by_src, count 5, seconds 10; sid:1000004; rev:1;)
```

### Rule 5 — Suspicious HTTP User-Agent
Alerts on HTTP requests from known scanner user-agent strings (Nmap, Spider, Proxy, Scan).
```
alert tcp any any -> any 80 (msg:"Suspicious User Agent - Possible Scanner"; flow:established,to_server; content:"User-Agent|3A| "; http_header; pcre:"/(?:Scan|Proxy|Spider|Nmap)/i"; sid:1000005; rev:1;)
```

### Rule 6 — SQL Injection Attempt
Detects `%27` (URL-encoded single quote) in HTTP requests — common SQL injection indicator.
```
alert tcp any any -> any any (msg:"SQL Injection Attempt"; flow:to_server,established; content:"%27"; sid:1000006; rev:1;)
```

### Rule 7 — FTP Brute Force
Monitors multiple login attempts to port 21 — brute force against FTP services.
```
alert tcp any any -> any 21 (msg:"FTP Brute Force Attempt"; flow:established,to_server; detection_filter:track by_src, count 5, seconds 10; sid:1000007; rev:1;)
```

### Rule 8 — DNS Zone Transfer Attempt
Detects unauthorized DNS AXFR zone transfer requests — can expose full internal DNS structure.
```
alert tcp any any -> $HOME_NET 53 (msg:"DNS Zone Transfer Attempt"; flow:established,to_server; content:"|00 00 FC|"; offset:12; depth:3; sid:1000008; rev:1;)
```

---

## 🔒 File Permissions

Secure permissions applied to all Snort directories:

```bash
# Allow Snort to write logs (read/write for all)
sudo chmod 666 /var/log/snort

# Restrict config, logs, and plugins — root only (read/write/execute)
# Group members: read and execute | Others: no access
sudo chmod -R 750 /etc/snort
sudo chmod -R 750 /var/log/snort
sudo chmod -R 750 /usr/local/lib/snort_plugins
```

---

## 🚀 Running Snort

### Step 1 — Test Configuration (no live capture)
```bash
sudo snort -T -c /etc/snort/snort.conf -i eth0
```
Validates `snort.conf` syntax and rule loading without starting live monitoring. Fix any errors shown before proceeding.

### Step 2 — Live Monitoring Mode
```bash
sudo snort -c /etc/snort/snort.conf -i eth0 -A alert_fast
```
Starts Snort in live mode on the `eth0` interface, outputting alerts in `alert_fast` format — a quick summary of each detected event.

---

## 🚨 Alerts Generated During Testing

All 5 core alert types were successfully triggered and logged:

| Alert | Source | Description |
|-------|--------|-------------|
| **ICMP Test** | 192.168.1.10 → internal | ICMP echo request detected — possible reconnaissance |
| **ICMP Ping Sweep** | Single source → multiple hosts | Multiple ICMP packets within seconds — host discovery scan |
| **TCP Port Scan** | External → 10.0.2.10 | Multiple SYN packets to multiple ports — service discovery |
| **SSH Brute Force** | External → port 22 | Repeated failed logins — automated credential attack |
| **Suspicious User Agent** | HTTP request | Scanner/bot user-agent string detected in HTTP header |

### Sample Alert Log Format (alert_fast)
```
[**] [1:1000001:1] ICMP Test [**]
[Priority: 0]
04/22-14:32:11.123456 192.168.1.10 -> 10.0.2.5
ICMP TTL:64 TOS:0x0 ID:1234 IpLen:20 DgmLen:84
Type:8  Code:0  ID:12345   Seq:1  ECHO
```

---

## 🔐 Security Implications

| Alert Type | Security Risk | Severity |
|-----------|--------------|----------|
| ICMP flood / ping sweep | DoS or reconnaissance — mapping live hosts | 🟠 High |
| TCP SYN flood | DoS/DDoS — exhausting server resources | 🔴 Critical |
| SSH/FTP brute force | Credential compromise — unauthorized access | 🔴 Critical |
| SQL injection | Database manipulation — data theft | 🔴 Critical |
| DNS zone transfer | Network topology disclosure — enabling future attacks | 🟠 High |

---

## 📊 Security Analysis

**Strengths of this Snort configuration:**
- `detection_filter:track by_src` reduces false positives by requiring threshold counts before alerting
- Custom rules target specific attack patterns relevant to the monitored network
- Covers both network layer (ICMP, TCP) and application layer (HTTP, SSH, DNS, FTP) threats

**Limitations:**
- Rule-based detection cannot identify zero-day attacks or novel APT techniques
- Requires regular rule updates to stay current with new threat patterns
- Operates as IDS only (detection and alerting) — not IPS (active blocking)

**Recommendations:**
- Integrate Snort with Talos Intelligence threat feeds for rule updates
- Combine with a firewall or IPS (e.g. Suricata) for active blocking capability
- Add SIEM integration (e.g. Splunk, ELK) for centralised log analysis

---

## 🔧 Tools & Environment

| Tool | Purpose |
|------|---------|
| Snort (open-source) | Network IDS — real-time traffic monitoring and alerting |
| Kali Linux | Testing environment |
| Nano | Configuration file editing |
| eth0 interface | Network interface monitored |

---

## 📚 References

- Snort Documentation — https://www.snort.org/documentation
- Talos Intelligence (Snort rule feeds) — https://talosintelligence.com/
- SANS Institute — https://www.sans.org/

---

## 👤 Author

**Anshio Renin Micheal Antony Xavier Soosammal**
MSc Cybersecurity | Dublin Business School 
Module: Communications and Networking Security (B9CY103) | Lecturer: Arturo Vázquez Zepeda
🔗 [LinkedIn](https://linkedin.com/in/anshio-renin-ms) | Open to Work in Ireland
