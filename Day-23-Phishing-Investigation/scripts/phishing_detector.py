#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from urllib.parse import urlsplit, unquote


SUSPICIOUS_WORDS = [
    "login", "verify", "account", "password",
    "secure", "update", "confirm", "banking"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd"
]

ATTACHMENT_INDICATORS = [
    ".exe", ".js", ".vbs", ".ps1", ".hta",
    ".docm", ".iso", ".zip"
]


def addresses(value):
    return [
        address.lower()
        for _, address in getaddresses([value or ""])
        if address
    ]


def hash_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def analyse_url(url):
    url = url.rstrip(".,;:!?)\"'")
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()

    findings = []

    if parsed.scheme != "https":
        findings.append("Non-HTTPS URL")

    if hostname in SHORTENERS:
        findings.append("URL shortener")

    if "%" in url:
        findings.append("Percent-encoded content")

    if any(word in unquote(url).lower()
           for word in SUSPICIOUS_WORDS):
        findings.append("Account-related keywords")

    return {
        "url": url,
        "hostname": hostname,
        "path": parsed.path,
        "indicators": findings,
    }


def analyse_email(email_path, attachment_dir):
    with email_path.open("rb") as f:
        message = BytesParser(policy=policy.default).parse(f)

    from_header = str(message.get("From", ""))
    reply_header = str(message.get("Reply-To", ""))

    from_addresses = addresses(from_header)
    reply_addresses = addresses(reply_header)

    mismatch = bool(
        from_addresses
        and reply_addresses
        and set(from_addresses).isdisjoint(reply_addresses)
    )

    auth_headers = message.get_all("Authentication-Results", [])
    auth_text = " ".join(str(h) for h in auth_headers).lower()

    authentication = {}

    for mechanism in ("spf", "dkim", "dmarc"):
        matches = re.findall(
            rf"\b{mechanism}\s*=\s*([a-z0-9_-]+)",
            auth_text,
        )
        authentication[mechanism.upper()] = matches

    body = message.get_body(preferencelist=("plain",))
    body_text = body.get_content() if body else ""

    urls = re.findall(
        r"https?://[^\s<>\"']+",
        body_text,
        re.IGNORECASE,
    )

    url_results = [analyse_url(url) for url in urls]

    attachments = []

    for part in message.iter_attachments():
        filename = part.get_filename() or "unnamed_attachment"
        data = part.get_payload(decode=True) or b""

        attachments.append({
            "filename": filename,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "extension": Path(filename).suffix.lower(),
            "potentially_sensitive_extension":
                Path(filename).suffix.lower() in ATTACHMENT_INDICATORS,
        })

    findings = []

    if mismatch:
        findings.append("From and Reply-To addresses differ")

    if any(
        result in ("fail", "none")
        for values in authentication.values()
        for result in values
    ):
        findings.append("Email authentication concern reported")

    if re.search(
        r"\burgent\b|\bimmediately\b|\bsuspended\b|\bexpire\b",
        str(message.get("Subject", "")) + " " + body_text,
        re.IGNORECASE,
    ):
        findings.append("Urgency or pressure language")

    for result in url_results:
        findings.extend(result["indicators"])

    for attachment in attachments:
        if attachment["potentially_sensitive_extension"]:
            findings.append(
                "Attachment has a potentially risky extension: "
                + attachment["filename"]
            )

    return {
        "source_email": email_path.name,
        "source_sha256": hash_file(email_path),
        "from": from_header,
        "reply_to": reply_header,
        "sender_reply_to_mismatch": mismatch,
        "authentication_results": authentication,
        "urls": url_results,
        "attachments": attachments,
        "investigation_indicators": sorted(set(findings)),
        "indicator_count": len(set(findings)),
        "assessment": (
            "REVIEW REQUIRED"
            if findings
            else "NO SELECTED INDICATORS"
        ),
        "limitations": [
            "This is a triage aid, not a definitive phishing classifier",
            "Authentication headers require trusted gateway validation",
            "URLs were not visited or reputation-checked",
            "Attachment content was not executed",
            "No mailbox or endpoint telemetry was correlated",
            "Missing attachments cannot be ruled out by this report",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Offline phishing email triage tool"
    )

    parser.add_argument("email_file")
    parser.add_argument(
        "--attachment-dir",
        default="evidence/attachments",
    )
    parser.add_argument(
        "--output",
        default="output/phishing-investigation.json",
    )

    args = parser.parse_args()

    email_path = Path(args.email_file).resolve()
    output_path = Path(args.output).resolve()
    attachment_dir = Path(args.attachment_dir)

    if not email_path.is_file():
        parser.error("Email evidence does not exist")

    if output_path == email_path:
        parser.error("Output cannot overwrite original evidence")

    report = analyse_email(email_path, attachment_dir)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(report, indent=4) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(report, indent=4))
    print(f"\nInvestigation saved to: {output_path}")


if __name__ == "__main__":
    main()
