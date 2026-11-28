# Day 42 – Operation RedOps

## Overview
A lightweight SOC threat-hunting lab inspired by reporting
about the WeaveLotus espionage campaign in Southeast Asia.

## Objective
Practice identifying:
- Possible password spraying.
- Suspicious SSH connections over port 443.

## Dataset
Synthetic authentication events created for this lab.
The IP addresses belong to documentation ranges.

## Tools
- Python 3
- JSONL
- Basic log analysis

## Execution

Run:

python detect.py

## Detection Logic
See detections/detection-rules.md.

## Security Note
This is a defensive training simulation.
It does not contain actual victim telemetry and does
not establish that any real-world compromise occurred.
