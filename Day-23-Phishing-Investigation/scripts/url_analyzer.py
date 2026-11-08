#!/usr/bin/env python3

import argparse
import ipaddress
import json
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlsplit, unquote


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "account",
    "password",
    "secure",
    "update",
    "confirm",
    "banking",
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
]


def analyse_url(url):
    cleaned = url.rstrip(".,;:!?)\"'")

    parsed = urlsplit(cleaned)
    hostname = (parsed.hostname or "").lower()

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    decoded_url = unquote(cleaned)

    indicators = []

    if parsed.scheme != "https":
        indicators.append("URL does not use HTTPS")

    if is_ip_address:
        indicators.append("URL uses an IP address")

    if "@" in parsed.netloc:
        indicators.append("URL contains user-info syntax")

    if hostname in SHORTENERS:
        indicators.append("URL uses a known shortening domain")

    if any(word in decoded_url.lower() for word in SUSPICIOUS_WORDS):
        indicators.append("Contains account-related keywords")

    if "%" in cleaned:
        indicators.append("Contains percent-encoded characters")

    if parsed.port and parsed.port not in (80, 443):
        indicators.append("Uses a non-standard port")

    return {
        "url": cleaned,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "path": parsed.path,
        "query_present": bool(parsed.query),
        "is_ip_address": is_ip_address,
        "indicators": indicators,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Offline phishing URL structure analyser"
    )

    parser.add_argument("email_file", help="Path to EML file")
    parser.add_argument(
        "--output",
        default="output/url-analysis.json",
    )

    args = parser.parse_args()

    email_path = Path(args.email_file).resolve()
    output_path = Path(args.output)

    if not email_path.is_file():
        parser.error("Email file does not exist")

    if output_path.resolve() == email_path:
        parser.error("Output cannot overwrite original evidence")

    with email_path.open("rb") as f:
        message = BytesParser(policy=policy.default).parse(f)

    body = message.get_body(preferencelist=("plain",))
    body_text = body.get_content() if body else ""

    urls = re.findall(
        r"https?://[^\s<>\"']+",
        body_text,
        re.IGNORECASE,
    )

    results = [analyse_url(url) for url in urls]

    report = {
        "source_email": email_path.name,
        "analysis_type": "Offline URL structural analysis",
        "url_count": len(results),
        "results": results,
        "limitations": [
            "No external website was contacted",
            "No domain reputation lookup was performed",
            "Structural indicators do not prove maliciousness",
            "HTTPS does not guarantee a website is safe",
            "Domain ownership and registration were not verified",
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=4) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(report, indent=4))
    print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()
