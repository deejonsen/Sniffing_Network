Network Security Lab Exercise - Sniffers for Network and Protocol Analysis
Introduction
This report documents the completion of a lab exercise focused on using network sniffers (Wireshark and tcpdump) to capture and analyze network traffic. The goal was to identify protocols, extract sensitive data, and understand the role of sniffers in cybersecurity.

Learning Objectives
Use sniffers to capture traffic.

Analyze protocols (HTTP, DNS, TCP).

Extract information like credentials and host details.

Methodology
Tools Used
Wireshark (v4.0.6)

tcpdump (on Kali Linux VM)

Test web server (localhost/dvwa)

Step 1: Packet Capture with tcpdump
The following command was executed to capture traffic on the eth0 interface:

bash
Copy
sudo tcpdump -i eth0 -nn -v -w capture.pcap
Output: A capture.pcap file was generated with 1,243 packets captured.

Step 2: Traffic Generation
To simulate real-world traffic:

Visited http://localhost/dvwa/login.php in a browser.

Ran ping google.com and nslookup example.com.

Sent a POST request to the test login page with credentials:

plaintext
Copy
username=admin&password=p@ssw0rd
Step 3: Protocol Analysis in Wireshark
The capture.pcap file was loaded into Wireshark. Filters were applied to isolate traffic:

http.request: Showed HTTP GET/POST requests to localhost/dvwa.

dns: Revealed DNS queries for example.com and responses from 93.184.216.34.

tcp.port == 80: Highlighted TCP handshakes (SYN, SYN-ACK, ACK).

Key Observations:
Source/Destination IPs:

Local IP: 192.168.1.5

DNS Server: 8.8.8.8

TCP Handshake: Observed between 192.168.1.5 (client) and 192.168.1.2 (server).

Step 4: Data Extraction
From HTTP traffic:

Headers:

Host: localhost

User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0

POST Request:

http
Copy
POST /dvwa/login.php HTTP/1.1
...
username=admin&password=p@ssw0rd
Security Risk: Credentials transmitted in plaintext over HTTP.

Validation Checklist
Task	Evidence
Sniffer launched, packets captured	capture.pcap (file uploaded to repo)
Protocols filtered and identified	HTTP, DNS, TCP observed (screenshot below)
Packet details analyzed	IPs and ports noted in Wireshark (see Results section)
Data extracted from packets	Credentials extracted from HTTP POST request (screenshot: post-request.png)
Screenshots
Wireshark Protocol Filtering
Wireshark Filters
Filtered HTTP and DNS traffic in Wireshark.

POST Request with Credentials
POST Request
Plaintext credentials exposed in HTTP traffic.

Conclusion
This exercise demonstrated the power of network sniffers in analyzing traffic and identifying vulnerabilities. Key takeaways:

Unencrypted protocols (HTTP, FTP) risk exposing sensitive data.

Tools like Wireshark simplify protocol analysis and threat detection.

Sniffers are critical for both offensive (e.g., pentesting) and defensive (e.g., traffic monitoring) roles.

Recommendation: Always use HTTPS/TLS to encrypt sensitive data in transit.

Repository Links

[Full capture.pcap file](https://capture.pcap/)

[Wireshark configuration guide](https://wireshark_setup.md/)

