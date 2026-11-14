# Day 28 – SIEM Engineering

## Overview

A local SIEM engineering prototype developed using Python.

The project demonstrates security event ingestion,
validation, normalization, detection, correlation,
alert generation and investigation reporting.

## Architecture

1. Security event ingestion
2. Event validation
3. Event normalization
4. Authentication detection
5. Event correlation
6. Alert generation
7. Investigation reporting

## Technology

- Kali Linux
- Python 3
- JSON
- JSON Lines
- Git
- Python unittest

## Detection Rules

| Rule | Purpose |
|---|---|
| DET-SSH-001 | SSH authentication failure threshold |
| COR-SSH-001 | Successful login after repeated failures |

## Run the SIEM

python3 -B scripts/siem_pipeline.py

## Run Tests

python3 -B -m unittest discover -s tests -p 'test_*.py' -v

## Learning Outcomes

- SIEM architecture
- Log ingestion and normalization
- Detection engineering
- Threshold-based detection
- Event correlation
- Alert generation
- Automated testing
- Investigation reporting

## Limitations

This is an educational, local file-based SIEM prototype.
All security events are synthetic training data.

It is not a production SIEM.
Correlation does not prove causation or session attribution.

## Status

Day 28 – SIEM Engineering practical lab.
