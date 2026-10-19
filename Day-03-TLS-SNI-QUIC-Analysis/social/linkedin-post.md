Day 3 of my SOC Analyst learning journey: TLS SNI & QUIC traffic analysis 🔎

Today I used TShark on Kali Linux to inspect my own packet capture and practiced:
• Filtering TLS Client Hello packets by SNI
• Summarizing observed hostnames
• Identifying QUIC traffic over UDP port 443
• Recording endpoints, timestamps, and frame sizes
• Separating observations from assumptions

Finding: the capture showed QUIC traffic from my local host to a remote server and SNI names associated with the main site and third-party web resources. The evidence reviewed did not establish malicious activity.

Key lesson: encrypted traffic, repeated packets, or port 443 alone do not mean an attack. A SOC analyst needs context, bidirectional traffic, and corroborating evidence before escalating.

Tools: Kali Linux • TShark • PCAP analysis

#CyberSecurity #SOCAnalyst #BlueTeam #Wireshark #TShark #NetworkSecurity #LearningInPublic
