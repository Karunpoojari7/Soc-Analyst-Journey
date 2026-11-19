# PAYGUARD SOC: Security Limitations & Prototype Boundaries

> **Mandatory Disclaimer**: PAYGUARD SOC is an educational, defensive prototype developed for Day 33 of the SOC Analyst Journey. It demonstrates key security architecture patterns, fraud detection workflows, and forensic auditing principles. It is **not** a production core banking platform.

---

## 1. Application-Level Triggers vs. Forensic Immutability

### Current Implementation
- PAYGUARD SOC utilizes SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers (`trg_audit_no_update`, `trg_audit_no_delete`) on the `audit_ledger` table.
- These triggers effectively prevent application-level ORM calls, SQL queries, and administrative SQL scripts from mutating or deleting audit history.

### Security Boundary & Limitation
- SQLite is a file-based embedded database. Anyone with root OS access or raw disk access can open the `.db` file using a binary editor or SQLite utility that disables triggers (`PRAGMA ignore_check_constraints = 1;` or custom builds) and alter rows directly on disk.
- **Why SHA-256 Hash Chaining is Essential**: Because disk-level mutation cannot be prevented by SQLite alone, PAYGUARD employs **SHA-256 hash chaining** ($H_n = \text{SHA-256}(H_{n-1} \,\|\, \text{record})$) and HMAC-signed manifests. Any disk-level bit flip immediately breaks the hash chain, enabling independent auditors to detect tampering.

### Production Alternative
- In a production financial institution, audit ledgers must be streamed to **Write-Once-Read-Many (WORM)** storage, cloud immutable storage (such as AWS S3 Object Lock in Compliance Mode or GCP Cloud Storage Bucket Lock), or hardware-secured HSM ledgers.

---

## 2. Deterministic Rules vs. Machine Learning

### Current Implementation
- All fraud rules in PAYGUARD (`DET-01`, `DET-02`, `DET-03`, `DET-04`) are **deterministic, explainable, and threshold-based**.
- They are designed to be 100% transparent: every alert identifies the exact mathematical threshold and historical record that triggered it.

### Clarification
- **Do not misrepresent these rules as AI or Machine Learning.**
- Deterministic rules are fast, auditable, and have zero inference latency. However, they can be subject to threshold evasion if an attacker knows the exact parameters (e.g. testing with ₹51 instead of ₹50).

### Future Machine Learning Roadmap
- True ML fraud detection would operate as a parallel asynchronous evaluation layer using supervised models (XGBoost, LightGBM) trained on historical fraud patterns, or unsupervised autoencoders for outlier anomaly detection.
- ML models require robust feature stores, continuous drift monitoring, and explainability frameworks (SHAP/LIME) before they can be used for automated transaction blocking.

---

## 3. Synthetic INR Currency & Network Isolation

### Current Implementation
- All financial balances, loan limits, and disbursements are modeled in synthetic Indian Rupees (`INR` / `₹`).
- A Python socket-level interceptor actively raises `RuntimeError` on any attempt to contact non-loopback addresses or resolve external DNS queries.

### Production Alternative
- Real-world disbursements require integration with authorized payment switch networks (e.g., NPCI UPI, IMPS, NEFT, or RTGS) via ISO 20022 or ISO 8583 message formats, secured via dedicated leased lines or Mutual TLS (mTLS) with Hardware Security Modules (HSMs).

---

## 4. In-Memory Nonce Cache & Single-Instance Concurrency

### Current Implementation
- Nonces are stored in SQLite and validated with an in-memory TTL mechanism.
- Concurrency control relies on SQLite's `BEGIN IMMEDIATE` write serialization.

### Production Alternative
- Distributed FinTech platforms operating across multiple API gateway nodes require a centralized, high-throughput in-memory key-value store (e.g., Redis Cluster or Dragonfly) with distributed locks (Redlock) to enforce global idempotency and single-use nonces across cloud regions.
