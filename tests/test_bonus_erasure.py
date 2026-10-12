"""Bonus: delete cascade giữ ledger verify, chỉ dpo được xoá."""
from __future__ import annotations

import json
import shutil

from agent import ledger
from agent.loop import run_once
from agent.tools import CUSTOMERS_FILE
from bonus.erasure import delete_customer

VICTIM = "KH-000999"


def _setup(tmp_path):
    customers = tmp_path / "customers.json"
    shutil.copy(CUSTOMERS_FILE, customers)
    victim = next(c for c in json.loads(customers.read_text(encoding="utf-8"))
                  if c["customer_id"] == VICTIM)
    sink_log = tmp_path / "sink.log"
    sink_log.write_text(json.dumps({"records": [victim]}, ensure_ascii=False) + "\n"
                        + json.dumps({"records": [{"customer_id": "KH-000001"}]}) + "\n",
                        encoding="utf-8")
    return customers, sink_log, victim


def test_dpo_delete_cascades_and_ledger_still_verifies(tmp_path, clean_sink):
    customers, sink_log, victim = _setup(tmp_path)
    run_once("Tổng hợp các ticket còn mở tuần này", mock=True, log_dir=tmp_path, principal_id="dpo")
    ledger_path = tmp_path / "ledger.jsonl"
    old_lines = ledger_path.read_text(encoding="utf-8").splitlines()
    assert ledger.verify(ledger_path)

    assert delete_customer(VICTIM, "dpo", customers, ledger_path, sink_log) is True

    new_lines = ledger_path.read_text(encoding="utf-8").splitlines()
    assert new_lines[:len(old_lines)] == old_lines, "dòng ledger cũ không được sửa"
    assert len(new_lines) == len(old_lines) + 1
    last = json.loads(new_lines[-1])
    assert last["tool"] == "delete_customer" and last["decision"] == "allow" and last["reason"]
    assert ledger.verify(ledger_path)

    store = customers.read_text(encoding="utf-8")
    sink = sink_log.read_text(encoding="utf-8")
    ledger_text = ledger_path.read_text(encoding="utf-8")
    assert VICTIM not in store and VICTIM not in sink
    assert "KH-000001" in sink, "chỉ xoá bản sao của đúng khách"
    for field in ("cccd", "phone", "bank_account", "email"):
        assert victim[field] not in store
        assert victim[field] not in sink
        assert victim[field] not in ledger_text


def test_support_l1_cannot_delete(tmp_path):
    customers, sink_log, _ = _setup(tmp_path)
    before = customers.read_text(encoding="utf-8")
    ledger_path = tmp_path / "ledger.jsonl"

    assert delete_customer(VICTIM, "support_l1", customers, ledger_path, sink_log) is False

    assert customers.read_text(encoding="utf-8") == before
    last = json.loads(ledger_path.read_text(encoding="utf-8").splitlines()[-1])
    assert last["decision"] == "deny" and last["reason"]
    assert ledger.verify(ledger_path)
