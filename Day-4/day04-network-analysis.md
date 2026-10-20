
## Finding 1: TCP Stream 7

- Client: 192.168.31.80:50924
- Remote endpoint: 20.207.73.82:443
- TCP handshake: Complete (frames 117-119)
- TLS SNI: github.com (frame 120)
- Later activity: TLS application-data packets observed
- Termination evidence: Client RST at frames 373 and 375;
  server FIN-ACK at frame 374
- Assessment: Connection lifecycle observed; reset cause
  and security significance remain undetermined.
- Next step: Correlate DNS evidence and inspect the
  connection's TLS and termination context.

## Finding 2: DNS and TLS Correlation

- DNS query: github.com (frame 115)
- DNS response: 20.207.73.82 (frame 116)
- TCP connection: 192.168.31.80:50924 -> 20.207.73.82:443
- TCP handshake: Completed (frames 117-119)
- TLS ClientHello: github.com SNI (frame 120)
- Assessment: DNS, TCP destination and TLS SNI are consistent.
- Security verdict: No malicious activity established.
- Limitation: The reason for later TCP resets remains unknown.
- Follow-up: Inspect available TLS alerts and handshake evidence.

## Finding 3: TCP Termination Sequence

- Stream: 7
- Frame 333: Client application-data packet
- Frame 373: Client TCP RST
- Frame 374: Server TCP FIN-ACK
- Frame 375: Client TCP RST
- Assessment: Reset and closure packets occur close together.
- Limitation: Packet evidence alone does not identify the
  application-level cause of termination.
- Security verdict: No malicious activity established.
- Recommended follow-up: Correlate endpoint/application logs
  if investigating a real incident.
