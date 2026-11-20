# PAYGUARD — Frontend Architecture

## 1. Overview

The PAYGUARD frontend provides a unified interface for financial security monitoring, transaction investigation, fraud detection and incident response.

The application is designed around a professional enterprise FinTech experience.

## 2. Technology Stack

| Technology | Responsibility |
|---|---|
| React | Component-based user interface |
| TypeScript | Type safety |
| Vite | Frontend development and build tooling |
| Tailwind CSS | Styling and responsive layouts |
| Recharts | Financial and security analytics |
| Framer Motion | UI and transaction-flow animations |
| Lucide React | Interface icons |

Verify the final dependency versions against package.json.

## 3. Application Structure

```text
frontend/
├── src/
│   ├── api/
│   ├── assets/
│   ├── components/
│   ├── context/
│   ├── features/
│   │   ├── authentication/
│   │   ├── dashboard/
│   │   ├── transactions/
│   │   ├── beneficiaries/
│   │   ├── analytics/
│   │   ├── detections/
│   │   ├── incidents/
│   │   ├── evidence/
│   │   └── simulator/
│   ├── hooks/
│   ├── layouts/
│   ├── routes/
│   ├── styles/
│   └── main.tsx
├── package.json
└── vite.config.ts
```

This is the intended logical structure. Document the actual source layout if it differs.

## 4. Design System

PAYGUARD uses a white-and-lime-green FinTech visual identity.

Primary colours:

- Lime Green: #8BE000
- Green: #65B900
- Deep Green: #247A18
- Forest Green: #174D16
- White: #FFFFFF
- Soft Background: #F7F9F5
- Primary Text: #17251A
- Secondary Text: #687568

Typography:
- Inter or Geist for application content.
- JetBrains Mono for technical identifiers and event metadata.

## 5. Application Navigation

The authenticated application includes:

- Command Center.
- Transaction Monitoring.
- Payment Flow.
- Beneficiary Monitoring.
- Financial Analytics.
- Detection Rules.
- Security Alerts.
- Authentication Monitoring.
- Incident Management.
- Investigation Workspace.
- Evidence Vault.
- Audit Trail.
- Evidence Verification.
- Attack Simulator.
- System Health.
- Platform Settings.

## 6. Frontend Engineering Principles

- Reusable components.
- Centralized API communication.
- Typed API models.
- Protected routes.
- Consistent error handling.
- Responsive layouts.
- Accessible controls.
- Loading and empty states.
- Backend-driven application data.
- Secure handling of authentication state.

## 7. Responsive Design

The interface should support:

- Desktop workstations.
- Laptop displays.
- Tablets.
- Mobile screens.

Navigation, charts, tables and investigation panels should adapt to smaller screens.

## 8. Data Integration

Operational metrics and transaction information must come from backend API responses.

The frontend must not independently manufacture transaction states, fraud alerts or security decisions.

## 9. Testing

Frontend validation should include:

- Production build.
- Type checking.
- Linting.
- Route protection.
- API error handling.
- Responsive behavior.
- Interactive component testing.

## 10. Implementation Status

Update this document to reflect the actual components, routes, libraries and tests present in the repository.