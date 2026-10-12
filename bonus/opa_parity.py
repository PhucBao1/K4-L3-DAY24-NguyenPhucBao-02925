"""Bonus — so khớp bonus/policy.rego (OPA) với agent/policy.py:check().

    python -m bonus.opa_parity        # in bảng so sánh, exit 1 nếu lệch

Mỗi case gọi `opa eval` với input = PolicyContext, data.principals =
data/principals.json, rồi so `allow` với policy.check().
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import asdict, replace
from pathlib import Path

from agent.policy import PRINCIPALS_FILE, PolicyContext, check

REGO = Path(__file__).resolve().parent / "policy.rego"
FUTURE = "2099-01-01T00:00:00+00:00"

_BASE = PolicyContext(
    data_classification="restricted", request_purpose="support-reply",
    agent_owner="lab24-agent/run-b", delegation_depth=0, egress_enabled=False,
    principal_id="dpo", requested_tool="read_customer",
    agent_scopes=("search_docs", "read_customer"), expires_at=FUTURE)

# (tên, context) — lấy từ test_policy/test_obo và thêm case biên.
CASES = [
    ("dpo read_customer hợp lệ", _BASE),
    ("support_l1 read_customer", replace(_BASE, principal_id="support_l1")),
    ("restricted + egress, dpo đủ quyền", replace(_BASE, egress_enabled=True)),
    ("restricted + egress, không principal",
     PolicyContext("restricted", "reconciliation", "run-b", 1, True)),
    ("internal search_docs support_l1",
     replace(_BASE, data_classification="internal", request_purpose="summarize-tickets",
             principal_id="support_l1", requested_tool="search_docs")),
    ("public + egress search_docs",
     replace(_BASE, data_classification="public", request_purpose="summarize-tickets",
             principal_id="support_l1", requested_tool="search_docs", egress_enabled=True,
             agent_scopes=("search_docs", "read_customer", "http_post"))),
    ("delegation vượt parent_scopes",
     replace(_BASE, delegation_depth=1, parent_scopes=("search_docs",))),
    ("delegation trong parent_scopes",
     replace(_BASE, delegation_depth=1, parent_scopes=("search_docs", "read_customer"))),
    ("hết hạn", replace(_BASE, expires_at="2000-01-01T00:00:00+00:00")),
    ("expires_at thiếu múi giờ", replace(_BASE, expires_at="2099-01-01T00:00:00")),
    ("expires_at rỗng", replace(_BASE, expires_at="")),
    ("unknown principal", replace(_BASE, principal_id="nobody")),
    ("sai purpose", replace(_BASE, request_purpose="marketing")),
    ("billing không có purpose support-reply", replace(_BASE, principal_id="billing")),
    ("tool ngoài agent_scopes", replace(_BASE, agent_scopes=("search_docs",))),
    ("http_post không egress, dpo", replace(_BASE, requested_tool="http_post",
                                           agent_scopes=("read_customer", "http_post"))),
]


def opa_decide(context: PolicyContext) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        data_file = Path(tmp) / "principals.json"
        data_file.write_text(json.dumps(
            {"principals": json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))}), encoding="utf-8")
        input_file = Path(tmp) / "input.json"
        input_file.write_text(json.dumps(asdict(context)), encoding="utf-8")
        out = subprocess.run(
            ["opa", "eval", "--format", "json", "-d", str(REGO), "-d", str(data_file),
             "-i", str(input_file), "data.lab24.authz.decision"],
            capture_output=True, text=True, check=True)
    decision = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
    return decision["allow"], decision["reason"]


def main() -> None:
    mismatches = 0
    for name, ctx in CASES:
        py_allow, py_reason = check(ctx)
        opa_allow, opa_reason = opa_decide(ctx)
        same = py_allow == opa_allow
        mismatches += not same
        print(f"{'OK ' if same else 'LỆCH'} {name:<40} python={py_allow!s:<5} opa={opa_allow!s:<5} | {opa_reason}")
    print(f"\n{len(CASES) - mismatches}/{len(CASES)} case khớp")
    raise SystemExit(1 if mismatches else 0)


if __name__ == "__main__":
    main()
