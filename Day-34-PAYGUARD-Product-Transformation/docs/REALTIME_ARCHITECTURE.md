# PAYGUARD — Real-Time Event Architecture

## 1. Overview

PAYGUARD uses a backend-driven event architecture to provide timely visibility into financial transaction activity and security operations.

The objective is to deliver operational updates without relying entirely on manual page refreshes.

## 2. Communication Architecture

Server-Sent Events (SSE) are the preferred communication mechanism for delivering backend events to the monitoring interface.

```text
FINANCIAL API
     |
TRANSACTION ENGINE
     |
DETECTION ENGINE
     |
DATABASE COMMIT
     |
EVENT PUBLISHER
     |
SSE EVENT STREAM
     |
REACT FRONTEND
     |
LIVE SOC INTERFACE
```

Events should be published only after the associated database operation commits successfully.

## 3. Event Types

| Event | Description |
|---|---|
| TRANSACTION_RECEIVED | A transaction request was received |
| TRANSACTION_VALIDATED | Transaction validation completed |
| TRANSACTION_HELD | Transaction placed on hold |
| TRANSACTION_APPROVED | Transaction approved |
| TRANSACTION_REJECTED | Transaction rejected |
| FRAUD_DETECTED | A detection rule generated an alert |
| AUTH_FAILURE | Authentication failure recorded |
| REPLAY_DETECTED | Replay attempt detected |
| CALLER_BLOCKED | Synthetic caller blocked |
| INCIDENT_CREATED | New incident created |
| INCIDENT_UPDATED | Incident information changed |
| EVIDENCE_EXPORTED | Evidence bundle exported |

## 4. Event Structure

Example event:

```json
{
  "event_id": "evt-synthetic-001",
  "event_type": "FRAUD_DETECTED",
  "timestamp": "2026-11-20T12:00:00Z",
  "entity_id": "TX-SYNTHETIC-001",
  "severity": "HIGH",
  "source": "DETECTION_ENGINE"
}
```

This is an illustrative synthetic event, not a record from a real financial system.

## 5. Reliability Requirements

- Authenticated event-stream access.
- Authorization checks.
- Reconnection handling.
- Heartbeat events.
- Event identifiers.
- Duplicate event handling.
- Bounded event queues.
- Sensitive-field redaction.
- Appropriate event retention.
- Graceful fallback when streaming is unavailable.

## 6. Frontend Responsibilities

The React application should:

- Establish the event connection.
- Display connection status.
- Receive and process events.
- Update relevant views.
- Handle reconnection.
- Avoid duplicate notifications.
- Display the latest successful update time.

## 7. Security Considerations

Event streams must not expose:
- Passwords.
- API tokens.
- Session secrets.
- Sensitive personal information.
- Unnecessary financial information.

Only authorized analysts should receive events appropriate to their permissions.

## 8. Testing

Test:
- Event-stream authentication.
- Event publication.
- Event delivery.
- Reconnection.
- Heartbeats.
- Duplicate prevention.
- Unauthorized access.
- Sensitive data redaction.

## 9. Implementation Status

Document the actual transport, endpoint, event publisher, reconnection behavior and test results implemented in PAYGUARD.