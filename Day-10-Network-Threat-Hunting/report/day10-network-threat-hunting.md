# Day 10: Network Threat Hunting and HTTP Analysis

## Objective
Investigate HTTP traffic in a packet capture, identify the request
and response, and assess the evidence without overclaiming.

## Environment
- OS: Kali Linux
- Tool: TShark
- Input: Reused Day 8 controlled test capture
- Capture: day08-test.pcap

## Investigation Hypothesis
Can the HTTP request and response in the capture be identified and
compared with the expected controlled test activity?

## Evidence Summary
- Packets in capture: 12
- Capture size: 1,761 bytes
- Protocols observed: Ethernet, IPv4, TCP, HTTP
- Client IP: 127.0.0.1
- Client source port: 51618
- Server IP: 127.0.0.1
- Server port: 8080
- HTTP method: GET
- Requested URI: /training-check
- HTTP response: 404 Not Found

## Analysis
The capture contains a local HTTP request from 127.0.0.1:51618 to
127.0.0.1:8080 for /training-check. The server returned HTTP status
404. This is consistent with the controlled local test performed
during Day 8.

The request and response timestamps in the capture were approximately
0.952 milliseconds apart.

## Assessment
The observed packets match the known controlled test activity.
An HTTP 404 response does not, by itself, indicate malicious activity.

This capture is small and contains only 12 packets. It is not
representative of a complete enterprise network threat hunt and
cannot establish whether other malicious activity occurred elsewhere.

## Tooling Note
Zeek installation was blocked by a Kali package dependency conflict:
the available Zeek package requires libc6 below 2.38, while the system
offers libc6 2.43-6. No forced installation or libc6 downgrade was
performed. This exercise used TShark instead.

## Conclusion
This exercise demonstrated how to extract HTTP request and response
metadata from a packet capture, identify the client and server ports,
and distinguish observed evidence from unsupported conclusions.

## Next Steps
- Resolve the Zeek installation approach safely.
- Analyze DNS and connection metadata in a suitable capture.
- Correlate network evidence with endpoint or security logs.
