import sys
from pathlib import Path
from cyberq.core.pii_guard import compute_verhoeff_check_digit

def gen_aadhaar(i):
    prefix = str(20000000000 + i * 137)[:11]
    cd = compute_verhoeff_check_digit(prefix)
    return prefix + str(cd)

def gen_luhn(i):
    prefix = str(400000000000000 + i * 17)[:15]
    digits = [int(c) for c in prefix]
    total = 0
    reverse_digits = digits[::-1]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 0:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d
    check = (10 - (total % 10)) % 10
    return prefix + str(check)

cases = []

# 35 Aadhaar TPs
for i in range(35):
    uid = gen_aadhaar(i)
    fmt = i % 4
    if fmt == 0:
        formatted = f"{uid[:4]} {uid[4:8]} {uid[8:]}"
    elif fmt == 1:
        formatted = f"{uid[:4]}-{uid[4:8]}-{uid[8:]}"
    elif fmt == 2:
        formatted = f"{uid[:4]}.{uid[4:8]}.{uid[8:]}"
    else:
        formatted = uid
    cases.append({
        "id": f"TP-AADHAAR-{i+1:03d}",
        "has_pii": True,
        "types": ["AADHAAR"],
        "text": f"Customer eKYC record UID: {formatted} verified against central authority.",
    })

# 35 PAN TPs
pan_prefixes = ["ABCDE", "BKZPK", "DFGTR", "PQRST", "ZXCVB", "MNBVC", "LKJHG"]
for i in range(35):
    pref = pan_prefixes[i % len(pan_prefixes)]
    pan = f"{pref}{1000 + i}F"
    cases.append({
        "id": f"TP-PAN-{i+1:03d}",
        "has_pii": True,
        "types": ["PAN"],
        "text": f"Tax filing dossier contains income tax PAN {pan} for account holder {i+1}.",
    })

# 35 Card TPs
for i in range(35):
    card = gen_luhn(i)
    fmt = i % 3
    if fmt == 0:
        formatted = f"{card[:4]} {card[4:8]} {card[8:12]} {card[12:]}"
    elif fmt == 1:
        formatted = f"{card[:4]}-{card[4:8]}-{card[8:12]}-{card[12:]}"
    else:
        formatted = card
    cases.append({
        "id": f"TP-CARD-{i+1:03d}",
        "has_pii": True,
        "types": ["CARD"],
        "text": f"Core payment settlement batch logs transaction on card {formatted} successfully.",
    })

# 25 IPv4 TNs
for i in range(25):
    cases.append({
        "id": f"TN-IPV4-{i+1:03d}",
        "has_pii": False,
        "types": [],
        "text": f"Gateway routing packet from 192.168.1.{i+1} to 10.0.0.{i+1} on switch SW-CORE-01.",
    })

# 20 IPv6 TNs
for i in range(20):
    cases.append({
        "id": f"TN-IPV6-{i+1:03d}",
        "has_pii": False,
        "types": [],
        "text": f"Firewall rule match for IPv6 traffic from 2001:0db8:85a3:0000:0000:8a2e:0370:{i+1:04d} port 443.",
    })

# 20 Timestamp TNs
for i in range(20):
    cases.append({
        "id": f"TN-TIME-{i+1:03d}",
        "has_pii": False,
        "types": [],
        "text": f"Statutory database lock acquired at 2026-10-11T14:{i:02d}:30.000Z by worker PID {1000+i}.",
    })

# 20 UUID TNs
for i in range(20):
    cases.append({
        "id": f"TN-UUID-{i+1:03d}",
        "has_pii": False,
        "types": [],
        "text": f"Correlation trace transaction ID c2c1e7a4-0b1a-4d3e-8c5e-{i:012d} committed.",
    })

# 20 Hash & Nonce TNs
for i in range(20):
    cases.append({
        "id": f"TN-HASH-{i+1:03d}",
        "has_pii": False,
        "types": [],
        "text": f"Artifact package digest e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8{i:02d} verified.",
    })

print(f"Total cases generated: {len(cases)}")
assert len(cases) == 210

test_file = Path(__file__).resolve().parent.parent / "backend" / "tests" / "test_pii_corpus.py"

content = '''"""Labelled corpus evaluation for PII Guard reporting True/False Positives and Negatives.

Corpus contains 210 independently generated test cases:
- 105 True Positives (Aadhaar with Verhoeff check, PAN, and Cards with Luhn check)
- 105 True Negatives (IPv4, IPv6, ISO timestamps, UUIDs, cryptographic hashes)
"""

import pytest

from cyberq.core.pii_guard import PIIGuard

LABELLED_CORPUS = ''' + repr(cases) + '''


def test_pii_labelled_corpus_evaluation():
    """Evaluate labelled corpus and report TP, FP, TN, FN metrics."""
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    for sample in LABELLED_CORPUS:
        findings = PIIGuard.scan(sample["text"])
        detected_has_pii = len(findings) > 0

        if sample["has_pii"] and detected_has_pii:
            true_positives += 1
            detected_types = {f["type"] for f in findings}
            for expected_type in sample["types"]:
                assert expected_type in detected_types, f"Missed {expected_type} in {sample['id']}"
        elif not sample["has_pii"] and not detected_has_pii:
            true_negatives += 1
        elif not sample["has_pii"] and detected_has_pii:
            false_positives += 1
            pytest.fail(f"False Positive on {sample['id']}: detected {findings} in text '{sample['text']}'")
        elif sample["has_pii"] and not detected_has_pii:
            false_negatives += 1
            pytest.fail(f"False Negative on {sample['id']}: expected {sample['types']} in text '{sample['text']}'")

    total_samples = len(LABELLED_CORPUS)
    accuracy = (true_positives + true_negatives) / total_samples
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0.0

    print(f"\\n[PII CORPUS EVALUATION RESULTS]")
    print(f"Total Samples: {total_samples}")
    print(f"True Positives:  {true_positives} (Expected: 105)")
    print(f"False Positives: {false_positives} (Expected: 0)")
    print(f"True Negatives:  {true_negatives} (Expected: 105)")
    print(f"False Negatives: {false_negatives} (Expected: 0)")
    print(f"Accuracy:        {accuracy * 100:.2f}%")
    print(f"Precision:       {precision * 100:.2f}%")
    print(f"Recall:          {recall * 100:.2f}%")

    assert false_positives == 0, f"Expected 0 False Positives, got {false_positives}"
    assert false_negatives == 0, f"Expected 0 False Negatives, got {false_negatives}"
    assert accuracy == 1.0, f"Accuracy must be 100%, got {accuracy}"
    assert precision == 1.0, f"Precision must be 1.0, got {precision}"
    assert recall == 1.0, f"Recall must be 1.0, got {recall}"
    assert true_positives == 105
    assert true_negatives == 105
'''

test_file.write_text(content, encoding="utf-8")
print(f"Successfully wrote {test_file}")
