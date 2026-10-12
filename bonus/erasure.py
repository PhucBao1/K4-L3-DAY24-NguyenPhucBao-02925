"""Bonus — delete cascade (quyền xoá dữ liệu) mà ledger vẫn verify.

    python -m bonus.erasure            # demo trên bản copy tạm, in log

Xoá một khách hàng khỏi private store và các bản sao phái sinh (sink log),
đi qua cùng PEP với runner. Ledger KHÔNG bị sửa: nó không chứa PII thô
(chỉ args_hash), nên xoá khách chỉ cần append một dòng `delete_customer`
và hash chain cũ vẫn nguyên.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy

AGENT_ID = "lab24-agent/erasure"


def delete_customer(customer_id: str, principal_id: str, customers_file: Path,
                    ledger_path: Path, sink_log: Path | None = None) -> bool:
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    allowed, reason = policy.check(policy.PolicyContext(
        data_classification="restricted", request_purpose="privacy-audit",
        agent_owner=AGENT_ID, delegation_depth=0, egress_enabled=False,
        principal_id=principal_id, requested_tool="delete_customer",
        agent_scopes=("delete_customer",), expires_at=expires_at))

    removed = {"customer_records": 0, "sink_lines": 0}
    if allowed:
        customers = json.loads(customers_file.read_text(encoding="utf-8"))
        kept = [c for c in customers if c["customer_id"] != customer_id]
        removed["customer_records"] = len(customers) - len(kept)
        customers_file.write_text(json.dumps(kept, ensure_ascii=False, indent=2) + "\n",
                                  encoding="utf-8")
        if sink_log and sink_log.exists():
            lines = sink_log.read_text(encoding="utf-8").splitlines()
            kept_lines = [line for line in lines if customer_id not in line]
            removed["sink_lines"] = len(lines) - len(kept_lines)
            sink_log.write_text("".join(f"{line}\n" for line in kept_lines), encoding="utf-8")
        reason += f"; cascade removed {removed}"

    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": AGENT_ID,
        "run_id": uuid.uuid4().hex,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
        "tool": "delete_customer",
        "purpose": "privacy-audit",
        "args_hash": hashlib.sha256(
            json.dumps({"customer_id": customer_id}, sort_keys=True).encode("utf-8")).hexdigest(),
        "classification": "restricted",
        "decision": "allow" if allowed else "deny",
        "reason": reason,
    }, ledger_path)
    return allowed


def demo() -> None:
    """Chạy trên bản copy tạm: không đụng data/ hay reports/ thật."""
    import shutil
    import tempfile

    from agent.loop import run_once
    from agent.tools import CUSTOMERS_FILE

    work = Path(tempfile.mkdtemp())
    customers = work / "customers.json"
    shutil.copy(CUSTOMERS_FILE, customers)
    ledger_path = work / "ledger.jsonl"
    sink_log = work / "sink.log"
    victim = next(c for c in json.loads(customers.read_text(encoding="utf-8"))
                  if c["customer_id"] == "KH-000999")
    sink_log.write_text(json.dumps({"path": "/reconcile", "body": {"records": [victim]}},
                                   ensure_ascii=False) + "\n", encoding="utf-8")

    run_once("Tổng hợp các ticket còn mở tuần này", mock=True, log_dir=work, principal_id="dpo")
    before = len(ledger_path.read_text(encoding="utf-8").splitlines())
    print(f"ledger trước khi xoá: {before} dòng, verify={ledger.verify(ledger_path)}")

    for who in ("support_l1", "dpo"):
        ok = delete_customer("KH-000999", who, customers, ledger_path, sink_log)
        last = json.loads(ledger_path.read_text(encoding="utf-8").splitlines()[-1])
        print(f"delete_customer as {who}: {last['decision']} | {last['reason']}")

    store = customers.read_text(encoding="utf-8")
    ledger_text = ledger_path.read_text(encoding="utf-8")
    print(f"ledger sau khi xoá: {len(ledger_text.splitlines())} dòng, verify={ledger.verify(ledger_path)}")
    for field in ("cccd", "phone", "bank_account", "email"):
        print(f"  {field}: còn trong store={victim[field] in store}, "
              f"ledger={victim[field] in ledger_text}, sink={victim[field] in sink_log.read_text(encoding='utf-8')}")


if __name__ == "__main__":
    demo()
