"""Bonus: client pin định nghĩa tool MCP, chặn rug pull sau khi đã duyệt."""
from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("mcp", reason="cần `pip install -r requirements-bonus.txt`")

from agent import ledger  # noqa: E402
from bonus.mcp_rugpull.client import demo  # noqa: E402


def test_rug_pull_is_denied_after_approval(tmp_path):
    ledger_path = tmp_path / "ledger.jsonl"
    first, second = asyncio.run(demo(ledger_path))

    # Lần 1: định nghĩa khớp pin -> gọi thật, tiện ích còn nguyên.
    assert first["allowed"] and "ticket-007" in first["output"]
    assert not first["injection"]

    # Lần 2: server đã đổi description thành chỉ thị -> deny, không gọi tool.
    assert second["injection"], "description mới phải là chỉ thị (để chứng minh rug pull nguy hiểm)"
    assert not second["allowed"]
    assert "ticket-008" not in second["output"]

    entries = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert [e["decision"] for e in entries] == ["allow", "deny"]
    assert all(e["reason"] for e in entries)
    assert "rug pull" in entries[1]["reason"]
    assert ledger.verify(ledger_path)
