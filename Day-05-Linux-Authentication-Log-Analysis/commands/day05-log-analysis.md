# Day 5 — Linux Authentication Log Analysis Commands

## Objective
Practise searching, counting, filtering, sorting, and preserving Linux SSH authentication log evidence using synthetic training data.

**Scope:** This lab uses a fictional log file. No external systems were targeted.

## 1. Create the working directories

```bash
mkdir -p ~/cyber-lab/day05/evidence
mkdir -p ~/cyber-lab/day05/report
cd ~/cyber-lab/day05
```

## 2. Inspect the evidence

```bash
ls -lh evidence/authentication-sample.log
cat evidence/authentication-sample.log
cat -n evidence/authentication-sample.log
wc -l evidence/authentication-sample.log
```

- `ls -lh`: displays file details and size.
- `cat`: displays the file contents.
- `cat -n`: displays numbered lines.
- `wc -l`: counts log lines.

Expected line count: 10.

## 3. Find failed authentication attempts

```bash
grep -i "Failed password" evidence/authentication-sample.log
grep -ic "Failed password" evidence/authentication-sample.log
```

Expected count: 6 failed-password events.

## 4. Find successful authentication events

```bash
grep -E "Accepted password|Accepted publickey" \
evidence/authentication-sample.log
```

Expected: two accepted authentication events.

## 5. Count source IP addresses

```bash
grep -E "Failed password|Accepted password|Accepted publickey" \
evidence/authentication-sample.log |
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' |
sort |
uniq -c
```

Expected:
- `198.51.100.23`: 4 events
- `203.0.113.44`: 3 events
- `192.0.2.55`: 1 event

These addresses are reserved for documentation examples.

## 6. Build a timeline

```bash
LC_ALL=C sort -k1,3 evidence/authentication-sample.log
```

This sorts by the first three timestamp fields for this sample's consistent date and time format.

## 7. Filter account-related events

```bash
grep -E "(for|user) kali([ (]|$)" \
evidence/authentication-sample.log
```

Review the matches to ensure the filter is returning events about the account rather than simply matching the hostname.

## 8. Calculate and verify evidence integrity

```bash
sha256sum evidence/authentication-sample.log \
  > evidence/SHA256SUMS.txt

sha256sum -c evidence/SHA256SUMS.txt
```

Expected verification result:

`evidence/authentication-sample.log: OK`

A successful check confirms that the file matches the hash recorded in the checksum file. It does not prove the log is authentic or that the events are correct.

## 9. Open the incident report

```bash
mkdir -p report
mousepad report/day05-linux-authentication-investigation.md
```

Document the objective, findings, evidence, limitations, conclusion, and recommendations.

## 10. Optional: inspect local system authentication logs

Only inspect systems you own or are authorized to administer.

```bash
sudo test -r /var/log/auth.log \
  && echo "auth.log is readable" \
  || echo "auth.log is unavailable or not readable"

sudo journalctl -u ssh --since "24 hours ago" --no-pager
```

The actual log location and SSH service name depend on system configuration. Do not publish raw system logs without reviewing and sanitizing sensitive information.

## Key learning points

- A failed login is not automatically an attack.
- Repeated failures followed by a success warrant investigation, not an immediate conclusion of compromise.
- Correlate timestamps, usernames, source addresses, and post-login activity.
- Preserve evidence and record its hash.
- Clearly distinguish synthetic training data from real incident evidence.
