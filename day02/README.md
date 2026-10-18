# Day 2 — SOC Analyst Learning Journey
## Network Traffic Analysis

### Objective
Practise packet capture and network traffic analysis using Kali Linux and TShark.

### Environment
- OS: Kali Linux persistent live USB
- Interface: wlan0
- Local IPv4: 192.168.31.80
- Default gateway: 192.168.31.1
- Tools: tcpdump, TShark, Wireshark

### Activities
- Identified the network interface and default gateway.
- Captured traffic visible to my own machine.
- Analysed DNS queries and responses.
- Reviewed A and AAAA DNS records.
- Observed local mDNS service discovery.
- Filtered TCP SYN packets and reviewed TCP conversations.

### Findings
DNS requests for `ws.chatgpt.com` received A and AAAA responses. DNS queries for `example.com` also returned address records. TCP SYN packets to port 443 were observed.

These observations alone do not establish malicious activity. The capture does not independently identify the processes responsible for each connection.

### Conclusion
This exercise improved my understanding of DNS resolution, TCP connection initiation, packet filters, and evidence-based SOC investigation.

### Next Steps
- Investigate TCP handshakes and connection outcomes.
- Learn to interpret TLS metadata.
- Practise correlating packet evidence with host logs.

### Safety and Privacy
This exercise analysed traffic visible to my own device. Raw packet captures are not included in this public report.
