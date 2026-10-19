# Day 3 Evidence Notes

- Capture: `~/cyber-lab/day03/evidence/day03-own-traffic.pcap`
- Reported capture size: 3.1 MB
- Local host: `192.168.31.80`
- Remote IP: `117.236.191.67`
- UDP source port: `33130`
- UDP destination port: `443`
- Matching QUIC packets in the pasted output: 13
- Listed frame length: 1399 bytes
- Relative time span: 35.406713–56.835043 seconds

SNI counts from the terminal output:
- 7 `gmu.ac.in`
- 6 `fonts.googleapis.com`
- 4 `www.google.com`
- 4 `cdn.jsdelivr.net`
- 4 `cdnjs.cloudflare.com`
- 3 `unpkg.com`
- 2 `www.googletagmanager.com`
- 2 `www.google.co.in`
- 2 `stats.g.doubleclick.net`
- 2 `googleads.g.doubleclick.net`
- 2 `fonts.gstatic.com`
- 2 `analytics.google.com`
- 2 `ad.doubleclick.net`
- 1 `kit.fontawesome.com`
- 1 `github.com`
- 1 `ads-img.mozilla.org`

These are observations from the provided command outputs. They do not independently prove successful sessions, the process responsible for each packet, or malicious behavior.
