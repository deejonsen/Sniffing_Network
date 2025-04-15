# Sniffing_Network# Network Security Lab Exercise: Sniffers for Network and Protocol Analysis

## Overview  
This lab exercise demonstrates the use of network sniffers (**Wireshark** and **tcpdump**) to capture, analyze, and extract information from network traffic. The exercise focuses on identifying protocols (HTTP, DNS, TCP), observing TCP handshakes, and detecting security risks like plaintext credentials.  

---

## Table of Contents  
- [Learning Objectives](#learning-objectives)  
- [Prerequisites](#prerequisites)  
- [Lab Tasks](#lab-tasks)  
  - [Step 1: Packet Capture](#step-1-packet-capture)  
  - [Step 2: Traffic Generation](#step-2-traffic-generation)  
  - [Step 3: Protocol Analysis](#step-3-protocol-analysis)  
  - [Step 4: Data Extraction](#step-4-data-extraction)  
- [Validation Checklist](#validation-checklist)  
- [Screenshots](#screenshots)  
- [Conclusion](#conclusion)  
- [Repository Links](#repository-links)  

---

## Learning Objectives  
By the end of this lab, you will:  
- Capture network traffic using **tcpdump** and **Wireshark**.  
- Analyze common protocols (HTTP, DNS, TCP).  
- Identify source/destination IPs, ports, and TCP handshakes.  
- Extract sensitive data (e.g., credentials) from unencrypted traffic.  

---

## Prerequisites  
- **Wireshark** installed on your machine.  
- **tcpdump** (Linux/Kali VM recommended).  
- Access to a test network (e.g., `localhost/dvwa`).  
- Basic terminal/command-line knowledge.  

---

## Lab Tasks  

### Step 1: Packet Capture  
1. Use `tcpdump` to capture traffic on the `eth0` interface:  
   ```bash
   sudo tcpdump -i eth0 -nn -v -w capture.pcap



   Stop the capture with Ctrl+C after generating traffic.

Step 2: Traffic Generation
Generate test traffic by:

Visiting http://localhost/dvwa/login.php in a browser.

Running ping google.com and nslookup example.com in the terminal.

Sending a test HTTP POST request with credentials.

Step 3: Protocol Analysis
Open capture.pcap in Wireshark.

Apply filters to isolate traffic:

http.request: View HTTP GET/POST requests.

dns: Analyze DNS queries/responses.

tcp.port == 80: Inspect TCP handshakes.

Step 4: Data Extraction
Identify HTTP headers (Host, User-Agent).

Locate unencrypted credentials in POST requests.

Note DNS responses (e.g., example.com → 93.184.216.34).

Validation Checklist
Task	Evidence
Packet capture file generated	capture.pcap uploaded to the repository.
Protocols identified	HTTP, DNS, TCP observed in Wireshark.
IP addresses and ports documented	Source: 192.168.1.5, Destination: 192.168.1.2
Credentials extracted	username=admin&password=p@ssw0rd found in HTTP POST request.
Screenshots
Wireshark Protocol Filtering
Wireshark Filters

Plaintext Credentials in HTTP POST
POST Request

Conclusion
This lab highlights the importance of encrypting network traffic (e.g., using HTTPS) and the risks of unsecured protocols like HTTP. Key takeaways:

Sniffers like Wireshark are essential for traffic analysis and threat detection.

Unencrypted traffic exposes sensitive data (credentials, headers, etc.).

Always validate network security configurations to prevent data leaks.

Repository Links
Full Packet Capture (capture.pcap)

Wireshark Setup Guide

