---
# **Network Security Lab Exercise - Sniffers for Network and Protocol Analysis**

---

## Introduction
This report documents the completion of a lab exercise focused on using network sniffers (Wireshark and tcpdump) to capture and analyze network traffic. The goal was to identify protocols, extract sensitive data, and understand the role of sniffers in cybersecurity.

### **Learning Objectives**
- Use sniffers to capture traffic.
- Analyze protocols (HTTP, DNS, TCP).
- Extract information like credentials and host details.

### **Methodology**
**Tools Used:**
  - Wireshark (v4.0.6)
  - tcpdump (on Kali Linux VM)
  - Test web server (localhost/dvwa)

### **Step 1:** Packet Capture with tcpdump
- The following command was executed to capture traffic on the eth0 interface:

```bash
sudo tcpdump -i eth0 -nn -v -w capture.pcap

Stopped the capture with Ctrl+C after generating traffic.
```

- Output:
  - A `capture.pcap` file was generated with 4,985 packets captured.


### **Step 2: Traffic Generation**
- To simulate real-world traffic:
  - Visited `http://localhost/dvwa/login.php` in a browser.
  - Ran `192.168.0.5` and `nslookup www.harvoxx.com`.

- Sent a `POST request` to the test login page with credentials:
```plaintext
username=admin&password=p@ssw0rd
```

### **Step 3: Protocol Analysis in Wireshark**
- The `capture.pcap` file was loaded into Wireshark. Filters were applied to isolate traffic:
  - `http.request`: Showed HTTP GET/POST requests to localhost/dvwa.
  - `dns`: Revealed DNS queries for `www.harvoxx.com` and responses from `192.168.43.70`.
  - `tcp.port == 21`: Highlighted TCP handshakes (SYN, SYN-ACK, ACK).

### **Key Observations:**
- **Source/Destination IPs:**
  - **Local IP:** 192.168.0.5
  - **DNS Server:** 8.8.8.8
  - **TCP Handshake:** Observed between 192.168.0.4 (client) and 192.168.0.5 (server).


### **Step 4: Data Extraction**
- **From HTTP traffic:**
  -  **HTTP Headers:**
  - Host: 192.168.0.5/dvwa/setup.php HTTP/1.1

User-Agent:
```http
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

- **POST Request:**
```
http
POST /dvwa/login.php HTTP/1.1
...
username=admin&password=p@ssw0rd
Security Risk: Credentials transmitted in plaintext over HTTP.
```

---


## **Validation Checklist**
### **1. Sniffer Launched and Packets Captured**  
**Task**: Launch a sniffer (tcpdump/Wireshark) and capture network traffic.

**Evidence**:  
- **Command Used**:  
  ```bash
  sudo tcpdump -i eth0 -nn -v -w capture.pcap
  ```

- Output:
  - File `capture.pcap` created with 4,985 packets captured.

 ![Screenshot 2025-04-15 200153](https://github.com/user-attachments/assets/11f240ef-069a-4994-9c41-85f039bc7661)


### **2. Protocols Filtered and Identified**
**Task:** Filter and identify protocols in the captured traffic.

**Evidence:**

- **Protocols Observed:**

|**Protocol**	| **Purpose**	                            | **Filter**      |
|-------------|-----------------------------------------|-----------------|
|HTTP	        | Web traffic (GET/POST requests)         | http.request    |
|DNS	        | Domain name resolution	                | dns             |
|TCP	        | Connection handshakes/data transmission	| tcp.port == 21  |

- **Wireshark Filters Applied:**

```plaintext
http.request || dns || tcp.port == 21
```

### **3. Packet Details Analyzed**
**Task:** Analyze IP addresses, flags, and ports.

**Evidence:**

- **Key Packet Details:**

| Packet #	| Source IP	  | Destination IP	| Protocol	| Flags	         |Port	|Notes                                                |
|-----------|-------------|-----------------|-----------|----------------|------|-----------------------------------------------------|
| 28        |	192.168.0.4 |	192.168.43.70   |	DNS	      | -              | 53   | Query for mozilla.com                               |
| 111	      | 192.168.0.4	| 192.168.0.5	    | HTTP      |	[GET]	         | 80	  | Client initiates HTTP                               |
| 540	      | 192.168.0.4	| 192.168.0.5	    | HTTP      |	[POST]	       | 80	  | Client uploads jpeg file                            |
| 969       | 192.168.0.4 | 192.168.43.70   | DNS       | -              | 53   | Query for [www.harvoxx.com](https://harvoxx.com/) | |
| 993       |	192.168.0.4	| 192.168.0.5     |	TCP	      | [SYN]	         | 21   |	Client initiates HTTP                               |
| 994       |	192.168.0.5	| 192.168.0.4     |	TCP	      | [SYN, ACK]	   | 21   |	Server responds                                     |
| 995       |	192.168.0.5	| 192.168.0.4     |	TCP	      | [ACK]	         | 21   |	Handshake complete                                  |

### **4. Data Extracted from Packets**
**Task:** Extract hostnames, URL paths, or credentials.

**Evidence:**

- **HTTP Headers:**
  - Host: 192.168.0.5/dvwa/setup.php HTTP/1.1

User-Agent:
```http
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

- **GET Request:**
```http
GET /dvwa/vulnerabilities/sqli/ HTTP/1.1
Host: 192.168.0.5
```

- **GET Request with Credentials (Security Risk!):**
```http
GET /dvwa/vulnerabilities/brute/?username=admin&password=password&Login=Login HTTP/1.1
Host: 192.168.0.5
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://192.168.0.5/dvwa/vulnerabilities/brute/
Cookie: security=high; PHPSESSID=a314a909a9afcf62266c7f8d467d85bc
Upgrade-Insecure-Requests: 1
```

- **POST Request with Credentials**
```http
POST /dvwa/vulnerabilities/exec/ HTTP/1.1
Host: 192.168.0.5
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://192.168.0.5
Connection: keep-alive
Referer: http://192.168.0.5/dvwa/vulnerabilities/exec/
Cookie: security=high; PHPSESSID=a314a909a9afcf62266c7f8d467d85bc
Upgrade-Insecure-Requests: 1
```

- **DNS Query:**
  - `www.harvoxx.com` resolved to `192.168.43.70`.

---

### **Conclusion**
This exercise demonstrated the power of network sniffers in analyzing traffic and identifying vulnerabilities. Key takeaways:

- Unencrypted protocols (HTTP, FTP) risk exposing sensitive data.

- Tools like Wireshark simplify protocol analysis and threat detection.

- Sniffers are critical for both offensive (e.g., pentesting) and defensive (e.g., traffic monitoring) roles.


### **Recommendation:**
- Always use `HTTPS/TLS` to encrypt sensitive data in transit.


### **Resources**  
- 🔗 [https://github.com/deejonsen/Sniffing_Network/blob/main/Sniffing_Network_Report.md](https://github.com/deejonsen/Sniffing_Network/blob/main/Sniffing_Network_Report.md) 

### **License**  
This project is open-source and licensed under the **MIT License**.

---

![Screenshot 2025-04-15 193754](https://github.com/user-attachments/assets/f2fe5969-cd81-4638-a7cd-f7c8d897c3c4)
![Screenshot 2025-04-15 193812](https://github.com/user-attachments/assets/3956a095-c292-477c-b514-8fcb2fc6197a)
![Screenshot 2025-04-15 193928](https://github.com/user-attachments/assets/f3ff2ce9-b710-4db7-8572-55bce6d1a979)
![Screenshot 2025-04-15 194209](https://github.com/user-attachments/assets/4add077e-e167-47ba-8a9a-34010b6ff5b6)
![Screenshot 2025-04-15 194512](https://github.com/user-attachments/assets/450bd93f-9f45-45f2-b8c7-387a10b3669e)
![Screenshot 2025-04-15 194549](https://github.com/user-attachments/assets/153fe140-7b3c-47c5-a535-1c59f1989b4f)
![Screenshot 2025-04-15 195923](https://github.com/user-attachments/assets/dcdff303-cce9-4c9c-aa95-d4504d6ef932)
![Screenshot 2025-04-15 195957](https://github.com/user-attachments/assets/c0749ab3-1c8b-4f83-a161-343824a7d749)
![Screenshot 2025-04-15 200046](https://github.com/user-attachments/assets/85a4b6c3-9827-4c5d-addc-bc14b443021e)
![Screenshot 2025-04-15 200102](https://github.com/user-attachments/assets/9c57c91c-4ddb-430d-ab83-517dddad40d6)
![Screenshot 2025-04-15 200153](https://github.com/user-attachments/assets/c5c9a471-cb04-4b2d-a2f0-ee5b5d146ca5)
![Screenshot 2025-04-15 200319](https://github.com/user-attachments/assets/07843d77-3c86-41c8-a19d-382ce7403e0d)
![Screenshot 2025-04-15 200704](https://github.com/user-attachments/assets/6b163a00-e817-4e32-9d47-4bcd9af7fc67)
![Screenshot 2025-04-15 200733](https://github.com/user-attachments/assets/d2659812-3494-4acd-9f9e-3838bb983d5d)
![Screenshot 2025-04-15 210446](https://github.com/user-attachments/assets/135db5cb-046a-4008-99ff-8b30f09cfa9b)
![Screenshot 2025-04-15 230510](https://github.com/user-attachments/assets/82630e4f-c5d4-4264-805c-898b7b9f59a4)
![Screenshot 2025-04-15 230501](https://github.com/user-attachments/assets/a49bcda5-0d57-4227-8d15-8081ededf397)
![Screenshot 2025-04-15 230334](https://github.com/user-attachments/assets/48defc39-4d78-41ef-96d1-5fcfe500dbce)
![Screenshot 2025-04-15 230307](https://github.com/user-attachments/assets/47aaf968-e21b-4dfb-a56a-1b6ddc2a1070)
![Screenshot 2025-04-15 230210](https://github.com/user-attachments/assets/c80c143e-cf71-4c68-8325-6b7dbd8de0b4)
![Screenshot 2025-04-15 225928](https://github.com/user-attachments/assets/61d32801-3dbc-4062-a296-341bdbfbf3b8)
![Screenshot 2025-04-15 225857](https://github.com/user-attachments/assets/a948ac7a-3b62-4777-a0c9-0f28d817eb6e)
![Screenshot 2025-04-15 225821](https://github.com/user-attachments/assets/ba99c271-73d1-4f68-ad78-dcf792663590)
![Screenshot 2025-04-15 225659](https://github.com/user-attachments/assets/28ab1892-4754-4fbb-91a0-d20c62997461)
![Screenshot 2025-04-15 225201](https://github.com/user-attachments/assets/fd29ec00-12d2-4359-844a-41107222fb29)
![Screenshot 2025-04-15 225029](https://github.com/user-attachments/assets/375c70ce-3f7d-49c7-b79f-4b09f19244a6)
![Screenshot 2025-04-15 224944](https://github.com/user-attachments/assets/5cd11d0a-32e7-42bd-8101-e04baa76c86a)
![Screenshot 2025-04-15 224913](https://github.com/user-attachments/assets/d6309be7-b92d-47df-bcb1-643ccae57686)
![Screenshot 2025-04-15 210808](https://github.com/user-attachments/assets/e545efd5-5676-4e60-96c6-dc7dce7a73a2)
![Screenshot 2025-04-15 210721](https://github.com/user-attachments/assets/244942ff-c6b3-418b-b4e0-938b86738b81)
![Screenshot 2025-04-15 210626](https://github.com/user-attachments/assets/b74fbd07-0a22-477c-93f8-293593d43145)
