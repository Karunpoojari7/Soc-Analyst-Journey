import csv
import hashlib
from pathlib import Path

DATASETS = {
    "evidence/vendor-logs/vendor-access.csv": 7,
    "evidence/identity-logs/identity-events.csv": 7,
    "evidence/vendor-logs/customer-data-access.csv": 6,
    "evidence/network-logs/network-events.csv": 5,
    "evidence/endpoint-logs/endpoint-events.csv": 5,
}

def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            digest.update(chunk)

    return digest.hexdigest()

def validate_csv(path, expected_records):
    with path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("CSV header is missing")

        records = list(reader)

        if any(None in record for record in records):
            raise ValueError("Unexpected extra CSV columns")

        if any(
            not value or not value.strip()
            for record in records
            for value in record.values()
        ):
            raise ValueError("Empty field detected")

        if len(records) != expected_records:
            raise ValueError(
                f"Expected {expected_records} records, found {len(records)}"
            )

        return len(records)

def main():
    total = 0
    hash_lines = []
    failures = 0

    for filename, expected in DATASETS.items():
        path = Path(filename)

        print(f"\nChecking: {filename}")

        try:
            count = validate_csv(path, expected)
            digest = sha256_file(path)

            print(f"PASS: {count} records")
            print(f"SHA-256: {digest}")

            hash_lines.append(f"{digest}  {filename}")
            total += count

        except (OSError, ValueError, csv.Error) as error:
            print(f"FAIL: {error}")
            failures += 1

    print(f"\nTotal valid records: {total}")
    print(f"Validation failures: {failures}")

    if failures == 0:
        Path("output/evidence-sha256.txt").write_text(
            "\n".join(hash_lines) + "\n",
            encoding="utf-8"
        )
        print("Evidence hash manifest created.")
    else:
        print("Hash manifest not updated.")
        raise SystemExit(1)

if __name__ == "__main__":
    main()
