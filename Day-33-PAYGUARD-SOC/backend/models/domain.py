"""PAYGUARD SOC - Domain Models, Enums, and Schemas.

All financial amounts are strictly typed and modeled in INR (₹).
"""

from enum import Enum
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class TransactionState(str, Enum):
    RECEIVED = "RECEIVED"
    VALIDATED = "VALIDATED"
    HELD = "HELD"
    REJECTED = "REJECTED"
    APPROVED = "APPROVED"


class LoanStatus(str, Enum):
    APPROVED = "APPROVED"
    PENDING = "PENDING"
    CLOSED = "CLOSED"


class BeneficiaryStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class DecisionReason(str, Enum):
    # Success
    APPROVED_OK = "APPROVED_OK"
    ANALYST_OVERRIDE_APPROVED = "ANALYST_OVERRIDE_APPROVED"
    
    # Rejections & Violations
    INSUFFICIENT_APPROVED_LOAN_BALANCE = "INSUFFICIENT_APPROVED_LOAN_BALANCE"
    INVALID_OR_UNAPPROVED_LOAN_STATUS = "INVALID_OR_UNAPPROVED_LOAN_STATUS"
    BENEFICIARY_NOT_REGISTERED = "BENEFICIARY_NOT_REGISTERED"
    IDEMPOTENCY_PAYLOAD_MISMATCH = "IDEMPOTENCY_PAYLOAD_MISMATCH"
    
    # API Security Failures
    SECURITY_TOKEN_INVALID = "SECURITY_TOKEN_INVALID"
    SECURITY_TOKEN_EXPIRED = "SECURITY_TOKEN_EXPIRED"
    SECURITY_TOKEN_REVOKED = "SECURITY_TOKEN_REVOKED"
    SECURITY_INSUFFICIENT_SCOPE = "SECURITY_INSUFFICIENT_SCOPE"
    SECURITY_REPLAY_DETECTED = "SECURITY_REPLAY_DETECTED"
    SECURITY_TIMESTAMP_SKEWED = "SECURITY_TIMESTAMP_SKEWED"
    SECURITY_AUTH_ABUSE_DETECTED = "SECURITY_AUTH_ABUSE_DETECTED"
    
    # Fraud Detection Flags (Transits to HELD)
    FRAUD_PROBE_MICRO_HIGH_VALUE = "FRAUD_PROBE_MICRO_HIGH_VALUE"
    FRAUD_UNSEEN_BENEFICIARY_VELOCITY = "FRAUD_UNSEEN_BENEFICIARY_VELOCITY"
    
    # Analyst Resolutions
    ANALYST_OVERRIDE_REJECTED = "ANALYST_OVERRIDE_REJECTED"


class AuditAction(str, Enum):
    TRANSACTION_RECEIVED = "TRANSACTION_RECEIVED"
    TRANSACTION_VALIDATED = "TRANSACTION_VALIDATED"
    TRANSACTION_HELD = "TRANSACTION_HELD"
    TRANSACTION_REJECTED = "TRANSACTION_REJECTED"
    TRANSACTION_APPROVED = "TRANSACTION_APPROVED"
    ANALYST_HOLD_RESOLUTION = "ANALYST_HOLD_RESOLUTION"
    AUTH_FAILURE = "AUTH_FAILURE"
    TOKEN_REVOCATION = "TOKEN_REVOCATION"


# --- Request & Response Schemas ---

class DisbursementRequest(BaseModel):
    loan_id: str = Field(..., description="Approved loan reference identifier")
    borrower_id: str = Field(..., description="Unique borrower identifier")
    beneficiary_id: str = Field(..., description="Registered recipient beneficiary identifier")
    amount_inr: float = Field(..., gt=0.0, description="Disbursement amount in INR (₹)")
    currency: str = Field(default="INR", description="Financial currency code (always INR)")
    purpose: Optional[str] = Field(default="Micro-Disbursement Loan Facility", description="Transaction description")

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v: str) -> str:
        if v.upper() != "INR":
            raise ValueError("Only synthetic INR currency is supported in this environment.")
        return "INR"


class DisbursementResponse(BaseModel):
    transaction_id: str
    state: TransactionState
    loan_id: str
    borrower_id: str
    beneficiary_id: str
    amount_inr: float
    currency: str = "INR"
    decision_reason: str
    correlation_id: str
    created_at: str


class AnalystReviewRequest(BaseModel):
    action: str = Field(..., pattern="^(APPROVE|REJECT)$", description="Analyst review decision (APPROVE or REJECT)")
    analyst_id: str = Field(..., min_length=3, description="Identified SOC analyst ID")
    decision_reason: str = Field(..., min_length=10, description="Documented operational rationale for the decision")
    analyst_notes: Optional[str] = Field(default=None, description="Forensic notes and telemetry observations")


class TokenInfo(BaseModel):
    token_id: str
    client_id: str
    scopes: List[str]
    is_revoked: bool
    expires_at: str
    created_at: str


class AuditRecord(BaseModel):
    id: Optional[int] = None
    event_id: str
    timestamp: str
    correlation_id: str
    actor: str
    action: str
    state_from: Optional[str] = None
    state_to: Optional[str] = None
    decision_reason: str
    payload_sha256: str
    prev_hash: str
    record_hash: str


class IncidentResponse(BaseModel):
    incident_id: str
    rule_code: str
    severity: str
    title: str
    description: str
    affected_entity: str
    transaction_id: Optional[str] = None
    status: str
    recommended_action: str
    analyst_notes: Optional[str] = ""
    assigned_analyst: Optional[str] = None
    created_at: str
    updated_at: str


class IncidentUpdateRequest(BaseModel):
    status: str = Field(..., pattern="^(OPEN|INVESTIGATING|CONTAINED|RESOLVED|FALSE_POSITIVE)$")
    analyst_id: str = Field(..., min_length=3)
    notes: str = Field(..., min_length=5)
    action: Optional[str] = Field(default=None, description="Optional defensive action: BLOCK_SYNTHETIC_CALLER, REVOKE_TOKEN")


class CallerBlockRequest(BaseModel):
    client_id: str
    reason: str = Field(..., min_length=5)
    analyst_id: str = Field(..., min_length=3)


class TokenRevokeRequest(BaseModel):
    token_identifier: str
    reason: str = Field(..., min_length=5)
    analyst_id: str = Field(..., min_length=3)


class SimulatorScenarioRequest(BaseModel):
    scenario: int = Field(..., ge=1, le=7, description="Scenario number between 1 and 7")

