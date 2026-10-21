# Day 5: Linux Authentication Log Analysis

## Overview
This lab practises the analysis of Linux SSH authentication events using a synthetic log dataset.

## Objectives
- Identify failed and successful authentication events.
- Count events and extract source IP addresses.
- Build a basic authentication timeline.
- Investigate a failure-followed-by-success pattern.
- Record findings and verify evidence integrity with SHA-256.

## Lab Structure

```text
Day-05-Linux-Authentication-Log-Analysis/
├── README.md
├── commands/
│   └── day05-log-analysis.md
├── evidence/
│   ├── authentication-sample.log
│   └── SHA256SUMS.txt
└── report/
    └── day05-linux-authentication-investigation.md
```

## Key Findings
- Four failed attempts targeted invalid usernames from `198.51.100.23`.
- Two failed attempts for `kali` were followed by an accepted password login from `203.0.113.44`.
- A public-key login was accepted from `192.0.2.55`.
- The sample does not provide sufficient evidence to establish a confirmed compromise.

## Limitations
The dataset is synthetic and uses documentation IP addresses. It does not represent a real intrusion or a live incident.

## Skills Practised
Linux command-line analysis, grep, sort, uniq, event correlation, timeline construction, SHA-256 integrity checking, and incident reporting.
