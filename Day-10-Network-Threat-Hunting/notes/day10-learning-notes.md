# Day 10 Learning Notes

## Concept
Network threat hunting is the proactive investigation of network
telemetry to identify activity that may warrant further analysis.

## Fields Investigated
- `ip.src` and `ip.dst`: source and destination IP addresses
- `tcp.srcport` and `tcp.dstport`: TCP ports
- `http.request.method`: HTTP request method
- `http.request.uri`: requested resource
- `http.response.code`: HTTP response status

## Observed Test
GET /training-check to 127.0.0.1:8080 returned HTTP 404.

## Analyst Lesson
A finding must be interpreted in context. A 404 response is not
automatically malicious, and this local test cannot establish
whether unrelated activity elsewhere is malicious.

## Next Learning Goal
Safely set up Zeek and investigate structured connection and DNS logs.
