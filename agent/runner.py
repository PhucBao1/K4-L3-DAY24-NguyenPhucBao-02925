"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer", "http_post")
RUN_TTL = timedelta(minutes=15)
# Đích egress cố định trong code — không bao giờ lấy URL từ free text.
RECONCILE_URL = "http://127.0.0.1:10024/reconcile"
_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)[a-z]?\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _ticket_ids(docs: list[dict]) -> list[int]:
    """Boundary A -> B: chỉ số nguyên lấy từ TÊN FILE, không lấy gì từ nội dung."""
    ids = set()
    for doc in docs:
        m = _TICKET_FILE_RE.match(doc["id"])
        if m:
            ids.add(int(m.group(1)))
    return sorted(ids)


def _customers_for(ticket_ids: list[int]) -> list[str]:
    """Nguồn tin cậy: related_tickets trong data/customers.json."""
    wanted = set(ticket_ids)
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return [c["customer_id"] for c in customers if wanted & set(c["related_tickets"])]


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    run_id = uuid.uuid4().hex
    expires_at = (datetime.now(timezone.utc) + RUN_TTL).isoformat()

    def call(run: str, tool: str, fn, args: dict, *, classification: str, purpose: str,
             scopes: tuple[str, ...], egress: bool):
        """PEP -> ledger -> tool. Tool chỉ chạy khi policy allow; cả hai đều ghi ledger."""
        agent_owner = f"{AGENT_ID}/{run}"
        allowed, reason = policy.check(policy.PolicyContext(
            data_classification=classification, request_purpose=purpose,
            agent_owner=agent_owner, delegation_depth=0, egress_enabled=egress,
            principal_id=principal_id, requested_tool=tool, agent_scopes=scopes,
            expires_at=expires_at))
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_owner,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": tool,
            "purpose": purpose,
            "args_hash": hashlib.sha256(
                json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
        }, ledger_path)
        return (True, fn(**args)) if allowed else (False, None)

    # Run A: untrusted content. Không private store, không egress.
    ok, docs = call("run-a", "search_docs", tools.search_docs, {"query": message},
                    classification="internal", purpose="summarize-tickets",
                    scopes=RUN_A_SCOPES, egress=False)
    if not ok:
        return f"Không thể tìm ticket: principal {principal_id!r} không được phép."
    # Chỉ giữ cờ để biết có chỉ thị lạ; customer_ids/target_url của attacker bị bỏ.
    injected = llm.find_injection("\n\n".join(d["text"] for d in docs)) is not None
    ticket_ids = _ticket_ids(docs)

    # Run B: private data. Input chỉ là list[int] ticket_id từ Run A.
    records = []
    for customer_id in _customers_for(ticket_ids):
        ok, record = call("run-b", "read_customer", tools.read_customer,
                          {"customer_id": customer_id},
                          classification="restricted", purpose="support-reply",
                          scopes=RUN_B_SCOPES, egress=False)
        if ok:
            records.append(record)

    # Chỉ thị trong tài liệu đòi gửi dữ liệu đi: đưa qua PEP để có deny + evidence.
    if injected and records:
        call("run-b", "http_post", tools.http_post,
             {"url": RECONCILE_URL, "body": {"customer_ids": [r["customer_id"] for r in records]}},
             classification="restricted", purpose="support-reply",
             scopes=RUN_B_SCOPES, egress=True)

    answer = llm.summarize(docs)
    if records:
        answer += f" Đã đối chiếu {len(records)} hồ sơ khách hàng gắn với các ticket."
    if injected:
        answer += " Cảnh báo: phát hiện chỉ thị lạ trong tài liệu, đã bỏ qua."
    return pii.redact(answer)
