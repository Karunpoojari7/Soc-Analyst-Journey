"""PAYGUARD SOC - Synthetic Configuration & Lab Settings.

ALL FINANCIAL LIMITS AND PARAMETERS IN THIS FILE ARE CONFIGURABLE SYNTHETIC LAB
VALUES FOR SOC TRAINING, DETECTION ENGINEERING, AND SYSTEM VERIFICATION.
NO REAL-WORLD MONETARY TRANSFERS OR EXTERNAL FINANCIAL SERVICES ARE UTILIZED.
"""

from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="PAYGUARD_",
        case_sensitive=False,
    )

    # Core Environment Configuration
    APP_NAME: str = "PAYGUARD-SOC-Core"
    ENVIRONMENT: str = "synthetic-lab"
    DEBUG: bool = False
    
    # Financial Configuration (INR)
    SYNTHETIC_CURRENCY: str = "INR"
    SYNTHETIC_CURRENCY_SYMBOL: str = "₹"
    
    # Database Configuration (SQLite with WAL mode)
    DATABASE_PATH: str = "payguard_synthetic.db"
    SQLITE_BUSY_TIMEOUT_MS: int = 5000
    
    # Network Isolation (Enforced locally)
    ENFORCE_NETWORK_ISOLATION: bool = True
    
    # API Security Tolerances
    TIMESTAMP_SKEW_TOLERANCE_SECONDS: int = 300  # 5 minutes
    NONCE_CACHE_TTL_SECONDS: int = 600           # 10 minutes
    SECRET_REDACTION_PATTERN: str = r"lab_tok_[a-zA-Z0-9_-]+"
    
    # Deterministic Fraud Detection Rules (Configurable Lab Values in INR)
    # DET-01: Micro-value probe followed by high-value transfer
    MICRO_VALUE_MAX_INR: float = 50.00         # Micro-value ceiling (₹50.00)
    HIGH_VALUE_MIN_INR: float = 5000.00        # High-value floor (₹5,000.00)
    MICRO_PROBE_WINDOW_SECONDS: int = 300      # 5 minutes escalation window
    
    # DET-02: New Beneficiary & Velocity Spike
    VELOCITY_WINDOW_SECONDS: int = 60          # 60-second velocity window
    VELOCITY_MAX_TX_COUNT: int = 3             # Max 3 transactions within window
    
    # DET-04: Token Misuse & Auth Brute Force
    AUTH_FAILURE_BURST_LIMIT: int = 3          # Max 3 failures
    AUTH_FAILURE_WINDOW_SECONDS: int = 60      # Within 60 seconds
    
    # Evidence & Audit Configuration
    EVIDENCE_DIR: str = "evidence"
    EVIDENCE_HMAC_SECRET: str = "synthetic-lab-evidence-hmac-key-2026-inr"


settings = Settings()
