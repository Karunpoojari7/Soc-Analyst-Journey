#!/usr/bin/env python3

import argparse
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path


def extract_addresses(value):
    if not value:
        return []

    return [
        address.lower()
        for _, address in getaddresses([value])
        if address
    ]


def extract_authentication_results(headers):
    results = []

    for header in headers:
        if not header:
            continue

        for mechanism in ("spf", "dkim", "dmarc"):
            matches = re.findall(
                rf"\b{mechanism}\s*=\s*([a-zA-Z0-9_-]+)",
                header,
                re.IGNORECASE,
            )

            for match in matches:
                results.append({
                    "mechanism": mechanism.upper(),
                    "result": match.lower(),
                })

    return results


def analyse_email(path):
    with path.open("rb") as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)

    from_header = message.get("From", "")
    reply_to = message.get("Reply-To", "")
    return_path = message.get("Return-Path", "")

    from_addresses = extract_addresses(from_header)
    reply_addresses = extract_addresses(reply_to)
    return_addresses = extract_addresses(return_path)

    received_headers = message.get_all("Received", [])
    auth_headers = message.get_all("Authentication-Results", [])

    body = message.get_body(preferencelist=("plain",))

    body_text = body.get_content() if body else ""

    urls = re.findall(
        r"https?://[^\s<>\"']+",
        body_text,
        re.IGNORECASE,
    )

    sender_mismatch = bool(
        from_addresses
        and reply_addresses
        and set(from_addresses).isdisjoint(reply_addresses)
    )

    return {
        "file_name": path.name,
        "message_id": str(message.get("Message-ID", "")),
        "date": str(message.get("Date", "")),
        "subject": str(message.get("Subject", "")),
        "from": from_header,
        "from_addresses": from_addresses,
        "reply_to": reply_to,
        "reply_to_addresses": reply_addresses,
        "return_path": return_path,
        "return_path_addresses": return_addresses,
        "sender_reply_to_mismatch": sender_mismatch,
        "received_headers": [str(item) for item in received_headers],
        "authentication_results": extract_authentication_results(
            auth_headers
        ),
        "urls": urls,
        "limitations": [
            "Header values in an untrusted email may be forged",
            "Authentication results require trusted gateway validation",
            "Missing Received headers do not establish the message route",
            "URL extraction does not establish URL reputation",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Basic email header investigation utility"
    )

    parser.add_argument("email_file", help="Path to an EML file")

    parser.add_argument(
        "--output",
        default="output/header-analysis.json",
        help="JSON output path",
    )

    args = parser.parse_args()

    email_path = Path(args.email_file).resolve()
    output_path = Path(args.output)

    if not email_path.is_file():
        parser.error("Email file does not exist")

    if output_path.resolve() == email_path:
        parser.error("Output cannot overwrite original evidence")

    report = analyse_email(email_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=4) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(report, indent=4))
    print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()
