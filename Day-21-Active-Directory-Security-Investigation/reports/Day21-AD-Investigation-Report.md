# Day 21 — Active Directory Security Investigation Report

## 1. Objective
Study Active Directory architecture, Kerberos authentication,
SPN exposure, privileged group changes and account lifecycle correlation.

## 2. Environment
- Kali Linux Live with persistence.
- Python 3.
- Impacket installed.
- OpenLDAP client utilities.
- Local protocol inspection and simulated datasets.

## 3. Investigation activities
1. Inspected Impacket Kerberos protocol structures.
2. Studied AS-REP Roasting and Kerberoasting indicators.
3. Built a Python Kerberos event hunting script.
4. Built a Python SPN security audit.
5. Built a privileged group hunting script.
6. Built an account lifecycle correlation script.

## 4. Results

### Kerberos hunt
- Seven simulated events analysed.
- One AS-REP indicator.
- Three RC4 service-ticket indicators.
- One multiple-service request pattern.

### SPN audit
- Seven simulated accounts analysed.
- Five SPN-associated accounts.
- Three accounts requiring review.

### Privileged group investigation
- Six simulated events analysed.
- Five membership additions.
- One membership removal.
- Three sensitive group additions.

### Account correlation
- Eight simulated events analysed.
- Two sensitive group additions.
- One correlated account lifecycle sequence.
- One addition without matching lifecycle activity in the supplied dataset.

## 5. Priority findings

### newadmin
A simulated account creation, enablement, password-reset attempt
and Domain Admins membership addition occurred within six minutes.

### guest01
A simulated actor added an account to Enterprise Admins without
matching account lifecycle activity in the supplied dataset.

### svc_backup
The simulated service account had an SPN, privileged membership
and a password configured never to expire.

## 6. Limitations
- All event datasets were simulated.
- No live Active Directory Domain Controller was queried.
- No real account compromise was established.
- Detection patterns require baselines and contextual validation.
- Production investigations should correlate additional authentication,
  directory modification and endpoint evidence.

## 7. Conclusion
This exercise developed practical understanding of Kerberos protocol
structures, SPN exposure, privileged group monitoring and event correlation.

The Python scripts demonstrate basic detection logic against controlled
training data. They are learning tools and are not production-ready SIEM
detections.

## 8. Next steps
- Investigate directory modification events, including Event 5136.
- Study DCSync detection and Event 4662.
- Investigate delegation and service-account configurations.
- Practise with authorized real Active Directory telemetry.
