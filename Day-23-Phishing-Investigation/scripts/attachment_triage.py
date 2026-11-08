#!/usr/bin/env python3

import argparse
import hashlib
import json
import mimetypes
import re
import subprocess
from pathlib import Path


INDICATORS = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "javascript:",
    "eval(",
    "base64",
    "createobject",
    "downloadstring",
]


def command_output(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return "Unavailable"


def analyse_attachment(path):
    data = path.read_bytes()

    detected_type = command_output(["file", "-b", str(path)])
    detected_mime = command_output(
        ["file", "--mime-type", "-b", str(path)]
    )

    declared_mime, _ = mimetypes.guess_type(path.name)

    text = data.decode("utf-8", errors="replace").lower()

    matches = [
        indicator
        for indicator in INDICATORS
        if indicator in text
    ]

    extension = path.suffix.lower()

    return {
        "file_name": path.name,
        "extension": extension,
        "size_bytes": len(data),
        "detected_file_type": detected_type,
        "detected_mime_type": detected_mime,
        "extension_mime_guess": declared_mime,
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "indicator_matches": matches,
        "potential_extension_mismatch": (
            declared_mime is not None
            and detected_mime != declared_mime
        ),
        "limitations": [
            "Static metadata and string inspection only",
            "No attachment was executed",
            "String matches do not prove malicious behaviour",
            "No macro or embedded-object analysis performed",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Offline attachment static triage"
    )

    parser.add_argument("attachment")
    parser.add_argument(
        "--output",
        default="output/attachment-analysis.json",
    )

    args = parser.parse_args()

    path = Path(args.attachment).resolve()
    output = Path(args.output)

    if not path.is_file():
        parser.error("Attachment file does not exist")

    if output.resolve() == path:
        parser.error("Output cannot overwrite original evidence")

    report = analyse_attachment(path)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=4) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(report, indent=4))
    print(f"\nReport saved to: {output}")


if __name__ == "__main__":
    main()
