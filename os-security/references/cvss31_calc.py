#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVSS 3.1 base-score calculator (no external dependencies).

Usage:
  python3 cvss31_calc.py 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H'
  python3 cvss31_calc.py AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H
  echo 'AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L' | python3 cvss31_calc.py

Why this exists: hand-computing CVSS base score is error-prone. Reports MUST
paste the score produced by this script (see report-template.md 「硬性规则」).

Scope: base score only (no temporal/environmental). Covers Scope Unchanged/Changed.
"""

import math
import re
import sys

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR = {  # PR weights depend on Scope
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_SEVERITY = [
    (9.0, "严重(Critical)"),
    (7.0, "高危(High)"),
    (4.0, "中危(Medium)"),
    (0.1, "低危(Low)"),
    (0.0, "无(None)"),
]


def _roundup(x: float) -> float:
    # CVSS 3.1 roundup: ceil to 1 decimal using the " roundup(x*10^i)" definition.
    return math.ceil(x * 10) / 10.0


def base_score(av, ac, pr, ui, s, c, i, a) -> float:
    if any(k not in _AV for k in (av,)) or ac not in _AC or pr not in _PR[s] \
            or ui not in _UI or c not in _CIA or i not in _CIA or a not in _CIA:
        raise ValueError("invalid metric value")
    pr_w = _PR[s][pr]
    exploitability = 8.22 * _AV[av] * _AC[ac] * pr_w * _UI[ui]
    isc = 1 - ((1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a]))
    if s == "U":
        impact = 6.42 * isc
        base = min(impact + exploitability, 10.0)
    else:  # Scope Changed
        impact = 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15
        base = min(1.08 * (impact + exploitability), 10.0)
    if impact <= 0:
        return 0.0
    return _roundup(base)


def severity(score: float) -> str:
    for thr, name in _SEVERITY:
        if score >= thr:
            return name
    return "无(None)"


def parse_vector(text: str):
    text = text.strip()
    text = re.sub(r"^CVSS:3\.1/", "", text)
    parts = {}
    for tok in text.split("/"):
        if ":" not in tok:
            continue
        k, v = tok.split(":", 1)
        parts[k.strip().upper()] = v.strip().upper()
    return parts


def main(argv) -> int:
    raw = " ".join(argv[1:]) if len(argv) > 1 else sys.stdin.read()
    if not raw.strip():
        print("usage: cvss31_calc.py 'AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H'", file=sys.stderr)
        return 2
    p = parse_vector(raw)
    order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [k for k in order if k not in p]
    if missing:
        print(f"missing metrics: {missing}", file=sys.stderr)
        return 2
    try:
        score = base_score(p["AV"], p["AC"], p["PR"], p["UI"], p["S"], p["C"], p["I"], p["A"])
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    vec = "CVSS:3.1/" + "/".join(f"{k}:{p[k]}" for k in order)
    print(f"vector : {vec}")
    print(f"score  : {score:.1f}")
    print(f"level  : {severity(score)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))