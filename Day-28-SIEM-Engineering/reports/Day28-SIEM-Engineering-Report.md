# Day 28 – SIEM Engineering Report

## 1. Executive Summary

A local educational SIEM pipeline was developed using Python
to ingest, normalize, detect and correlate synthetic security events.

## 2. Architecture

The pipeline consists of:

1. JSONL event ingestion
2. Event validation
3. Event normalization
4. Authentication detection
5. Event correlation
6. Alert generation
7. Investigation reporting

## 3. Dataset

The NEXORA Technologies training dataset contains 11
synthetic security events.

## 4. Ingestion Results

- Received: 11
- Accepted: 11
- Rejected: 0

## 5. Detection Engineering

DET-SSH-001 identifies five or more failed authentication
events from the same source and account within ten minutes.

COR-SSH-001 identifies successful authentication after
the repeated authentication failure threshold.

## 6. Correlation

Subsequent session, privileged command, process and
network events were associated using host, account,
source IP and event time.

Session-level attribution was not established.

## 7. Testing

Automated tests cover:

- Event normalization
- Five-failure threshold
- Four-failure non-alert
- Time-window enforcement
- Source isolation
- Successful-login correlation

## 8. Assessment

The training dataset produced one high-priority
authentication investigation alert.

No real compromise was established.

## 9. Engineering Limitations

- Local file-based processing only.
- No distributed ingestion.
- No message queue.
- No production-scale indexing.
- No real-time streaming.
- No threat-intelligence enrichment.
- No multi-tenant authentication.
- No production access control.

## 10. Conclusion

This project demonstrates the fundamental engineering
components of a SIEM pipeline.

It provides a reproducible learning environment for
log ingestion, normalization, detection, correlation,
testing and investigation reporting.
