Suricata Intrusion Detection System (IDS) Setup
Project Overview
This project demonstrates the configuration and deployment of Suricata, an open-source network threat detection engine, for real-time monitoring and analysis of network traffic. The system is designed to detect suspicious activities such as port scans, malware downloads, DNS tunneling, and SQL injections, providing valuable insights into network security.

Table of Contents
Project Overview
System Requirements
Installation
Configuration
Usage
Examples of Detection
Contributing
License
System Requirements
Operating System: Linux-based system (Ubuntu, Debian, or a Security Onion environment)
Suricata Version: 6.x or later
Memory: Minimum 2 GB of RAM (depending on traffic load)
Storage: Minimum 20 GB of free disk space
Network: Access to a live network for traffic monitoring or a simulated network setup
Installation
Step 1: Install Suricata
To install Suricata on your Linux system, follow these steps:

sudo apt update
sudo apt install suricata -y
Step 2: Install Additional Tools (Optional)
You can install other useful tools like the ELK Stack for log aggregation and visualization:

sudo apt install elasticsearch logstash kibana -y
Step 3: Enable Suricata Service
Enable and start the Suricata service to run in the background:

sudo systemctl enable suricata
sudo systemctl start suricata
Configuration
Step 1: Configure Suricata for Network Monitoring
Edit the suricata.yaml configuration file to specify which interfaces to monitor:

sudo nano /etc/suricata/suricata.yaml
Set the network interfaces for monitoring

af-packet:
  - interface: eth0
Rule Configuration: Add or modify rules to detect specific network intrusions. Suricata uses the Emerging Threats (ET) rules by default:

sudo suricata-update
sudo systemctl restart suricata
Step 2: Customize Detection Rules
You can add custom detection rules by modifying the rule files in /etc/suricata/rules/.

For example, to detect HTTP traffic with potential SQL injection patterns:

alert http any any -> any any (msg:"SQL Injection Attempt"; content:"select * from"; nocase; sid:100001;)
Usage
Start Network Monitoring
To start monitoring network traffic using Suricata, run:

sudo suricata -c /etc/suricata/suricata.yaml -i eth0
eth0 is your network interface to monitor.
Viewing Alerts
Suricata logs alerts and events in the /var/log/suricata/ directory. The primary log file is fast.log:

cat /var/log/suricata/fast.log
You can use Kibana or other visualization tools to create dashboards from the logs for easier analysis.

Examples of Detection
Port Scanning (Nmap):

Suricata detects and logs a SYN scan (performed by tools like Nmap):
alert tcp any any -> any any (msg:"Port Scan Detected"; flags:S; sid:200001;)
Malware Downloads:

Suricata can detect the EICAR test string, which is commonly used to simulate malwar
alert http any any -> any any (msg:"EICAR Test String"; content:"X5O!P%@AP[4\PZX54(P^)7CC)7}";
sid:100002;)
SQL Injection Detection:

SQL injection attacks are identified by specific SQL keywords in HTTP requests:
alert http any any -> any any (msg:"SQL Injection Attempt"; content:"union select"; nocase; sid:100003;)
DNS Tunneling:

Suricata can detect DNS queries with suspicious patterns (like long strings or abnormal traffic spikes):
alert dns any any -> any any (msg:"Suspicious DNS Query"; content:"www.suspicious-domain.com"; sid:100004;)
Contributing
If you'd like to contribute to this project, feel free to fork the repository and submit pull requests. Bug reports, feature requests, and improvements are welcome.

License
This project is licensed under the MIT License. For more details, see the LICENSE file in this repository.
