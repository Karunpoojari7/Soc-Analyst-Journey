Day 2 — Network traffic analysis

# Identify network interfaces and addresses
ip -br addr

# Inspect IPv4 interface details
ip -4 addr show

# Inspect the routing table and default gateway
ip route

# Review saved lab evidence
ls -lh ~/cyber-lab/day02/evidence/

# Select the packet capture for analysis
PCAP=~/cyber-lab/day02/evidence/live-traffic.pcap

# Display DNS packets
tshark -r "$PCAP" -Y dns

# Display DNS queries only
tshark -r "$PCAP" -Y 'dns.flags.response == 0'

# Display DNS responses only
tshark -r "$PCAP" -Y 'dns.flags.response == 1'

# Filter TCP connection-initiation SYN packets
tshark -r "$PCAP" \
  -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0'

# Summarize TCP conversations
tshark -r "$PCAP" -q -z conv,tcp

# Extract selected DNS fields
tshark -r "$PCAP" -Y dns -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e dns.qry.name \
  -e dns.flags.response
