<div align="center">
  <h1>🌌 PacketNova 🌌</h1>
  <h3>Advanced Network Analysis & Security Toolkit</h3>

  ![License](https://img.shields.io/badge/license-MIT-blue)
  ![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen)
  ![Version](https://img.shields.io/badge/version-1.0.0-orange)
  ![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
  ![Status](https://img.shields.io/badge/status-active-success)

  <p>
    <b>Decode your network's secrets with precision and elegance</b>
  </p>
  
![image](https://github.com/user-attachments/assets/e517f8e8-4374-4fb4-88ed-7cacf7f36344)

</div>

## ✨ Features at a Glance

- **🔍 Comprehensive Network Discovery** - Map your entire network ecosystem
- **📊 Advanced PCAP Analysis** - Forensic-level inspection of network traffic
- **📝 Professional Report Generation** - Detailed documentation with visualizations
- **🛡️ IP Reputation Intelligence** - Check IPs against global threat databases
- **ℹ️ WHOIS Information Retrieval** - Access registration data for any IP/domain
- **📈 Interactive Visual Analysis** - Dynamic, data-rich charts for traffic patterns
- **🔐 Security-Focused Design** - Built with network security best practices

## 📋 Requirements

```
Python 3.8+
nmap (with admin/root privileges for full functionality)
Matplotlib and related visualization libraries
Scapy for packet manipulation
Python-docx for report generation
API keys for services (VirusTotal)
```

## 🚀 Installation

1. **Clone the repository**
   ```bash
   https://github.com/Dark-Angel1020/PacketNova.git
   cd PacketNova
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirement.txt
   ```

3. **Configure API keys**
   ```bash
   # Create a .env file with your API keys
   echo "API_KEY=your_virustotal_api_key" > .env
   echo "API_URL=https://www.virustotal.com/api/v3/ip_addresses/" >> .env
   ```

4. **Run with elevated privileges (for full functionality)**
   ```bash
   # On Linux/macOS
   sudo python maiin.py
   
   # On Windows (Run PowerShell/CMD as Administrator)
   python maiin.py
   ```

## 📊 Complete Workflow & Command Outputs

### Main Menu

```
==================================================
        Network Scanner and Analysis Tool
==================================================
1. Get IP Addresses of All Network Devices
2. Complete Network Scan
3. Analyze Old Capture Files (Log Files)
4. Generate Consolidated Report
5. Graphical Analysis
6. Whois Lookup
7. Blacklist Check
8. Exit
==================================================
```

### 1. Get IP Addresses of All Network Devices

This quick scan identifies all active hosts on your network.

**Output Example:**
```
[+] Detecting active network interface...
[i] Interface: eth0
[i] Scanning subnet: 192.168.1.0/24
[+] Running Nmap scan...

============================================================
              Live Hosts on Network:
============================================================
192.168.1.1     | MAC: 00:11:22:33:44:55
192.168.1.5     | MAC: AA:BB:CC:DD:EE:FF
192.168.1.10    | MAC: 11:22:33:44:55:66
192.168.1.25    | MAC: FF:EE:DD:CC:BB:AA

Total live hosts found: 4
```

### 2. Complete Network Scan

Performs a comprehensive scan including OS detection, vendor identification, and open service enumeration.

**Output Example:**
```
=== NMAP SCAN (Detailed) ===
[+] Scanning network: 192.168.1.0/24 with Nmap (fast scan on specific ports)...

=== ARP SCAN ===
[+] Performing ARP scan on 192.168.1.0/24 ...

📋 Network Devices:
IP              MAC                  Vendor                    Model                          Services
------------------------------------------------------------------------------------------------------------------------
192.168.1.1     00:11:22:33:44:55    Cisco Systems             Linux Router 3.4 (Router)      80/tcp (http Apache 2.4.6), 443/tcp (https)
192.168.1.5     AA:BB:CC:DD:EE:FF    Apple Inc.                macOS 12.0 (Computer)          None
192.168.1.10    11:22:33:44:55:66    Samsung Electronics       Android 10 (Mobile device)     None
192.168.1.25    FF:EE:DD:CC:BB:AA    Intel Corporate           Windows 10 21H2 (Computer)     445/tcp (microsoft-ds), 139/tcp (netbios-ssn)

Do you want to save the results? (yes/no): yes
[+] Results saved to ipsscan_2025-04-23_15-30-45.txt
```

### 3. Analyze Old Capture Files (Log Files)

Select and analyze PCAP/PCAPNG files with detailed protocol breakdown.

**Output Example:**
```
[+] Analyzing file: capture_2025-04-22.pcap

============================================================
                PCAP ANALYSIS RESULTS
============================================================

File Name:         capture_2025-04-22.pcap
File Size:         4275.34 KB
Total Packets:     2863
Capture Duration:  120.57 seconds

------------------------------------------------------------
                PROTOCOL DISTRIBUTION
------------------------------------------------------------
TCP             1542 packets ( 53.9%)
UDP              763 packets ( 26.7%)
HTTP             341 packets ( 11.9%)
DNS              189 packets (  6.6%)
HTTPS            156 packets (  5.4%)
ICMP              28 packets (  1.0%)

------------------------------------------------------------
                ALL SOURCE IPs
------------------------------------------------------------
192.168.1.5        1245 packets
192.168.1.25        658 packets
8.8.8.8             189 packets
...

------------------------------------------------------------
                ALL DESTINATION IPs
------------------------------------------------------------
8.8.8.8             245 packets
142.250.185.174     342 packets
192.168.1.25        789 packets
...

------------------------------------------------------------
                TOP DNS QUERIES
------------------------------------------------------------
  example.com.                                          35
  googleapis.com.                                       24
  google.com.                                           22
  cloudfront.net.                                       18
  amazonaws.com.                                        15
```

### 4. Generate Consolidated Report

Creates a comprehensive DOCX report with analysis results and visualizations.

**Output Example:**
```
[+] Report Generation Selected
[+] Analyzing file for report: capture_2025-04-22.pcap
[+] Generating charts and visualizations...
[+] Compiling report sections...
[+] Report successfully generated at: /home/user/PacketNova/PCAP_Report_capture_2025-04-22_pcap_PROFESSIONAL_2025-04-23 15_35_22.docx
```

The generated report includes:
- Executive summary of traffic patterns
- Detailed protocol analysis
- Communication patterns between devices
- Visual charts for traffic distribution
- Anomaly detection and security recommendations

### 5. Graphical Analysis

Provides interactive visualizations for deeper analysis.

**Output Example:**
```
[+] Graphical Analysis Selected
[+] Analyzing file for visualization: capture_2025-04-22.pcap
[+] Rendering visualizations...
```
*[The tool then displays interactive matplotlib charts showing protocol distribution, packet sizes, port usage, and timeline]*

### 6. Whois Lookup

Retrieves registration and ownership information for an IP address.

**Output Example:**
```
Enter IP address to analyze: 8.8.8.8

Information for: 8.8.8.8
Network Name:    GOOGL-IPV4-3
Network Handle:  NET-8-8-8-0-1
Country:         US
IP Range:        8.8.8.0 - 8.8.8.255
Status:          active
----------------------------------
Abuse Contact Info
Email:           network-abuse@google.com
----------------------------------
Other Contacts
Entity Handle:   GOGL
Roles:           registrant
Name:            Google LLC
Email:           dns-admin@google.com
Phone:           +1-650-253-0000
----------------------------------
```

### 7. Blacklist Check

Checks an IP address against the VirusTotal database to evaluate its reputation.

**Output Example:**
```
 
 IP Reputation Checker 

============================================================

[+] Checking IP: 203.0.113.42...
[~] Querying VirusTotal API... ✓ Done!

============================================================
VirusTotal Report for 203.0.113.42
============================================================

Reputation Scores:
  Harmless: 76
  Malicious: 3 ⚠️ WARNING!
  Suspicious: 1 ⚠️ Caution
  Undetected: 12

============================================================

Risk Assessment:
  ⚠️⚠️ Medium risk detected

============================================================
```

## 🔄 Workflow Integration

PacketNova is designed to provide a complete network analysis workflow:

1. **Discovery Phase**
   - Begin with basic IP address discovery to map devices
   - Follow with complete network scan for detailed inventory

2. **Analysis Phase**
   - Collect traffic with your preferred packet capture tool
   - Use the PCAP analysis feature to examine traffic patterns
   - Apply visual analysis to identify anomalies and patterns

3. **Intelligence Phase**
   - Investigate suspicious IPs with Whois lookups
   - Check reputation of external IPs with Blacklist Check
   - Generate comprehensive reports for documentation

4. **Action Phase**
   - Use findings to update firewall rules
   - Identify unauthorized devices and services
   - Document network state for compliance and security

## 🏗️ Project Structure

```
PacketNova/
├── maiin.py             # Main application entry point and menu system
├── networkscanner.py    # Network discovery and device identification
├── fileanalyzer.py      # PCAP analysis engine with visualization capabilities
├── checkblacklist.py    # IP reputation analysis via VirusTotal API
├── whois.py             # IP/Domain WHOIS information retrieval
└── requirement.txt      # Project dependencies
```

## 🛠️ Advanced Usage

### Running as a Service

Create a systemd service to run periodic scans:

```bash
[Unit]
Description=PacketNova Network Scanner
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/PacketNova
ExecStart=/usr/bin/python3 /path/to/PacketNova/maiin.py --auto-scan
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Integrating with Other Security Tools

PacketNova output can be piped to other security tools:

```bash
# Scan network and pass to intrusion detection system
python networkscanner.py --output=json | jq '.devices[] | .ip' | xargs suricata -c /etc/suricata/suricata.yaml -i eth0
```

### Automated Report Generation

Set up cron jobs for periodic reporting:

```bash
# Add to crontab for daily reports at 1 AM
0 1 * * * cd /path/to/PacketNova && python maiin.py --generate-report --input=/path/to/daily_capture.pcap --output=/path/to/reports/
```

## 🔒 Security Considerations

- Run with appropriate privileges (admin/root) only when necessary
- Secure your API keys and .env file
- Ensure you have authorization before scanning networks
- Use on networks you own or have explicit permission to analyze
- Some features may trigger IDS/IPS systems

## 🤝 Contributing

We welcome contributions to PacketNova!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

---
<div align="center">
  <p><i>Illuminate your network. Secure your data.</i></p>
  <p>Made with ❤️ by Network Security Enthusiasts</p>
</div>
