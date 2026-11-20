# PAYGUARD — Financial Transaction Processing and Payment Flow

## 1. Overview

This document describes the transaction validation and defensive decision-making workflow implemented in PAYGUARD.

The project uses synthetic financial records and does not execute real financial transfers.

## 2. Transaction Lifecycle

```text
              API REQUEST
                   |
             AUTHENTICATION
                   |
           REQUEST VALIDATION
                   |
              LOAN CHECK
                   |
           BENEFICIARY CHECK
                   |
            FRAUD DETECTION
                   |
           TRANSACTION DECISION
                   |
              AUDIT LEDGER
```

## 3. Transaction States

| State | Meaning |
|---|---|
| RECEIVED | Request received |
| VALIDATED | Required validation passed |
| HELD | Requires additional review |
| REJECTED | Request rejected |
| APPROVED | Request approved in the synthetic application |

## 4. Validation Controls

The backend should validate:

- Request structure.
- Authentication.
- Token scope.
- Timestamp.
- Nonce.
- Idempotency key.
- Loan reference.
- Loan approval status.
- Borrower relationship.
- Beneficiary registration.
- Beneficiary authorization.
- Transaction amount.
- Applicable synthetic risk rules.

Client-side values must never replace server-side validation.

## 5. Detection Integration

DET-01:
Identifies a micro-value probe followed by a high-value transaction within the configured time window.

DET-02:
Identifies suspicious transaction velocity involving an unseen beneficiary.

DET-03:
Identifies attempts involving invalid or unapproved loan references or statuses.

DET-04:
Identifies repeated authentication failures or suspicious authentication bursts.

## 6. Transaction Decision

Possible decisions:

- APPROVED
- HELD
- REJECTED

Every decision should have an explainable reason.

A held transaction must not be approved merely because a frontend button was clicked.

Authorized analyst decisions require:
- Authentication.
- Permission checks.
- Valid transaction state.
- Mandatory decision reason.
- Audit record.

## 7. Idempotency and Concurrency

The transaction engine should prevent duplicate processing.

Required controls include:
- Idempotency-key validation.
- Duplicate request detection.
- Payload consistency checking.
- Atomic database operations.
- Concurrency testing.
- Balance and transaction integrity checks where applicable.

## 8. Auditability

Record:
- Transaction identifier.
- Previous state.
- New state.
- Decision reason.
- Timestamp.
- Associated detection.
- Authorized analyst action.

Do not store authentication secrets in transaction records.

## 9. Financial Scope

All amounts are synthetic and represented in Indian Rupees (INR).

PAYGUARD does not initiate UPI payments, banking transfers or production financial disbursements.

## 10. Testing

Validate:
- Valid synthetic transaction.
- Invalid beneficiary.
- Invalid loan status.
- Micro-value probe.
- Unseen beneficiary velocity.
- Authentication abuse.
- Duplicate transaction.
- Replay attempt.
- Concurrent requests.
- Unauthorized approval.

## 11. Implementation Status

Document actual transaction behavior and test results after inspecting the backend implementation.