# **Network Security Lab Exercise: Sniffers for Network and Protocol Analysis**

### **Overview**  
This repository contains the lab exercise report that demonstrates the use of network sniffers (**Wireshark** and **tcpdump**) to capture, analyze, and extract information from network traffic. The exercise focuses on identifying protocols (HTTP, DNS, TCP), observing TCP handshakes, and detecting security risks like plaintext credentials.  

---

### **Contents**  
- 🔹 **Learning Objectives** – Solving encryption/decryption challenges.  
- 🔹 **Prerequisites** – Analyzing binaries with Python.  
- 🔹 **Lab Tasks** – Extracting hidden data from files.  
  - 🔹 **Step 1: Packet Capture** – Automating interactions with remote services.
  - 🔹 **Step 2: Traffic Generation** – Solving encryption/decryption challenges.  
  - 🔹 **Step 3: Protocol Analysis** – Analyzing binaries with Python.  
  - 🔹 **Step 4: Data Extraction** – Extracting hidden data from files.  
- 🔹 **Validation Checklist**

---

### **Learning Objectives**
By the end of this lab, you will:  
- Capture network traffic using **tcpdump** and **Wireshark**.  
- Analyze common protocols (HTTP, DNS, TCP).  
- Identify source/destination IPs, ports, and TCP handshakes.  
- Extract sensitive data (e.g., credentials) from unencrypted traffic.  

---

### **Prerequisites** 
- **Wireshark** installed on your machine.  
- **tcpdump** (Linux/Kali VM recommended).  
- Access to a test network (e.g., `localhost/dvwa`).  
- Basic terminal/command-line knowledge.  

---

### **Lab Tasks** 

### **Step 1: Packet Capture**  
- Use `tcpdump` to capture traffic on the `eth0` interface:  
   ```bash
   sudo tcpdump -i eth0 -nn -v -w capture.pcap
   ```

### **Step 2: Traffic Generation**
- Generate test traffic by:
  - Visiting `http://localhost/dvwa/login.php` in a browser.
  - Running `google.com` and `nslookup example.com` in the terminal.
  - Sending a test HTTP POST request with credentials.

### **Step 3: Protocol Analysis**
- Open `capture.pcap` in Wireshark.
- Apply filters to isolate traffic:
  - `http.request`: View HTTP GET/POST requests.
  - `dns`: Analyze DNS queries/responses.
  - `tcp.port == 21`: Inspect TCP handshakes.

### **Step 4: Data Extraction**
- Identify HTTP headers (`Host`, `User-Agent`).
- Locate unencrypted credentials in GET/POST requests.
- Note DNS responses (e.g., `example.com` → `93.184.216.34`).

---

## **Validation Checklist**
|**Task**	                              | **Evidence**	                                                    | 
|---------------------------------------|-------------------------------------------------------------------|
| Packet capture file generated	        | `capture.pcap` uploaded to the repository                         |
| Protocols Identified                  | HTTP, DNS, TCP observed in Wireshark                              |
| IP addresses and ports documented     | Source: `192.168.1.5`, Destination: `192.168.1.2`                 |
| Credentials extracted        	        | `username=admin&password=p@ssw0rd` found in HTTP GET/POST request	|


### **Screenshots**
- Wireshark Protocol Filtering
  - Wireshark Filters

- Plaintext Credentials in HTTP POST
-   - POST Request


### **Conclusion**
This lab highlights the importance of encrypting network traffic (e.g., using HTTPS) and the risks of unsecured protocols like HTTP. Key takeaways:

- Sniffers like Wireshark are essential for traffic analysis and threat detection.
- Unencrypted traffic exposes sensitive data (credentials, headers, etc.).
- Always validate network security configurations to prevent data leaks.

### **Contributing**  
If you'd like to contribute:  
1. Fork the repo  
2. Create a new branch: `git checkout -b my-feature`  
3. Commit your changes: `git commit -m "Added new challenge solution"`  
4. Push and open a Pull Request  

### **Resources**  
- 🔗 [https://github.com/deejonsen/Sniffing_Network/blob/main/Sniffing_Network_Report.md](https://github.com/deejonsen/Sniffing_Network/blob/main/Sniffing_Network_Report.md) 

### **License**  
This project is open-source and licensed under the **MIT License**.

---
