"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _expired(expires_at: str) -> bool:
    try:
        deadline = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    if deadline.tzinfo is None:
        return True  # không rõ múi giờ thì không tin
    return deadline <= datetime.now(timezone.utc)


def check(context: PolicyContext) -> tuple[bool, str]:
    c = context
    tool = c.requested_tool or "<unknown tool>"

    # Rule tối thiểu, đứng trước mọi quyền: không principal nào mở được nó.
    if c.data_classification == "restricted" and c.egress_enabled:
        return False, f"deny {tool}: restricted data with egress enabled (owner={c.agent_owner})"

    # Đọc lại mỗi lần: file nhỏ, và sửa fixture là có hiệu lực ngay.
    principals = json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    principal = principals.get(c.principal_id)
    if principal is None:
        return False, f"deny {tool}: unknown principal {c.principal_id!r}"

    if _expired(c.expires_at):
        return False, f"deny {tool}: delegation expired or invalid expires_at {c.expires_at!r}"

    if c.request_purpose not in principal["purposes"]:
        return False, (f"deny {tool}: purpose {c.request_purpose!r} not allowed "
                       f"for principal {c.principal_id}")

    effective = set(principal["allowed_tools"]) & set(c.agent_scopes)
    if c.delegation_depth > 0:
        effective &= set(c.parent_scopes)
    if c.requested_tool not in effective:
        return False, (f"deny {tool}: not in effective scope {sorted(effective)} "
                       f"(principal={c.principal_id}, depth={c.delegation_depth})")

    return True, (f"allow {tool}: principal={c.principal_id} purpose={c.request_purpose} "
                  f"classification={c.data_classification} egress={c.egress_enabled}")
