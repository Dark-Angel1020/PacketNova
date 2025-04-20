# 🌐 **Network Scanner & PCAP Analyzer**

![Network Analysis](https://img.shields.io/badge/Network-Analysis-blue?style=for-the-badge) ![Python](https://img.shields.io/badge/Python-3.8%2B-green?style=for-the-badge) ![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

> 🚀 **Unleash the Power of Network Insights!**  
> A sleek, all-in-one tool for **real-time network scanning** and **deep PCAP analysis**—perfect for security pros, network admins, and curious tech enthusiasts.

## 🎉 **Why You’ll Love This Tool**

🔍 **Scan Networks Like a Pro**  
Discover devices, map services, and profile your network with ease.  

📊 **Dive Deep into Packet Data**  
Analyze PCAP files with stunning visualizations and detailed insights.  

📝 **Impress with Reports**  
Generate polished, professional DOCX reports in a snap.  

## 🌟 **Features That Shine**

### 🔎 **Network Scanning**
- **Live Host Detection**: Spot every active device on your network in seconds.  
- **Rich Device Profiles**:  
  - 💻 IP & MAC addresses  
  - 🏭 Vendor lookup  
  - 🖥️ OS detection  
  - 🔓 Open ports & services  
- **Choose Your Scan Style**:  
  - ⚡ Fast ARP scanning for quick results  
  - 🛠️ Nmap-powered deep scans for ultimate detail  

### 📈 **PCAP Analysis**
- **Protocol Insights**: See the breakdown of TCP, UDP, HTTP, DNS, and more.  
- **IP & Port Analytics**: Track sources, destinations, and top ports.  
- **Traffic Visuals**: Explore packet size histograms and arrival timelines.  
- **Interactive Charts**: Powered by Matplotlib for dynamic exploration.  

### 📚 **Reporting Made Simple**
- **Professional DOCX Reports**: Auto-generated with embedded charts.  
- **Console Summaries**: Quick, clean outputs for command-line fans.  
- **Graphical Dashboards**: Visualize your data with style.  

## 📦 **Get Started in Minutes**

1. **Clone the Repo**:
   ```bash
   git clone https://github.com/yourusername/network-scanner-pcap-analyzer.git
   cd network-scanner-pcap-analyzer
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Optional Vendor Database Update**:
   ```bash
   python -m mac_vendor_lookup --update
   ```

## 🚀 **How to Use It**

Launch the tool and explore its intuitive menu:

```bash
python main.py
```

### 🖱️ **Menu Options**
1. 🔎 **Quick Scan**: Find all devices on your network.  
2. 🧠 **Complete Scan**: Get detailed device profiles.  
3. 🕵️‍♂️ **PCAP Analysis**: Dig into packet captures.  
4. 📝 **Generate Report**: Create a professional DOCX report.  
5. 📊 **Visualize Data**: Explore interactive PCAP charts.  
6. 🚪 **Exit**: Close the tool.  

## 📊 **Sneak Peek at the Output**

### ✅ **Network Scan Results**
```
🌐 Network Devices Discovered:
IP              MAC                 Vendor                Device Type                   Services
192.168.1.1     AA:BB:CC:DD:EE:FF  Cisco Systems         Wireless Router               80/http, 443/https
192.168.1.101   11:22:33:44:55:66  Apple Inc.            iPhone (iOS 15)               62078/tcp
```

### 🧪 **PCAP Analysis Snapshot**
```
📊 PCAP Analysis Summary
============================================================
File:               example.pcap
Size:               1.45 MB
Total Packets:      10,241
Duration:           42.31 seconds

🔍 Protocol Breakdown
------------------------------------------------------------
TCP              7843 packets (76.6%) 🟢
HTTP             2104 packets (20.5%) 🟠
DNS               893 packets (8.7%) 🔵
```

## 🛠️ **Under the Hood**

- **Tech Stack**:  
  - 🐍 **Scapy**: Precision packet analysis  
  - 🔎 **Nmap**: Robust network scanning  
  - 📊 **Matplotlib**: Eye-catching visualizations  
  - 📄 **Python-docx**: Professional report generation  

- **Supported Protocols**:  
  - Ethernet, IP, TCP, UDP  
  - HTTP, HTTPS, DNS, ICMP, ARP  

## 🤝 **Join the Community**

Got ideas? Found a bug? Want to add a feature?  
👉 **Open an issue** or **submit a pull request**—we’d love to collaborate!  

## 📜 **License**

**MIT License** – Free to use, modify, and share. See [LICENSE](LICENSE) for details.

## 🌍 **Your Network, Your Insights**

**Analyze. Visualize. Document.**  
With this powerful toolkit, you’re in control of your network’s story.  
⭐ **Star the repo** and start exploring today!
