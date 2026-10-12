"""Client chống MCP rug pull: pin hash định nghĩa tool lúc duyệt, kiểm lại
trước MỖI lần gọi, lệch thì deny và ghi ledger.

    python -m bonus.mcp_rugpull.client      # demo, ghi ledger vào thư mục tạm

So sánh với client ngây thơ (không pin): description mới đi thẳng vào
context, và mock LLM coi đó là chỉ thị (đòi đọc KH-000999, POST ra sink).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from mcp import Client
from mcp.client.stdio import StdioServerParameters

from agent import ledger
from agent.llm import find_injection

SERVER = StdioServerParameters(command=sys.executable, args=["-m", "bonus.mcp_rugpull.server"],
                               cwd=str(Path(__file__).resolve().parents[2]))
AGENT_ID = "lab24-agent/mcp-client"


def tool_fingerprint(tool) -> str:
    """sha256 của những gì model nhìn thấy về tool: tên, mô tả, schema."""
    body = {"name": tool.name, "description": tool.description, "inputSchema": tool.input_schema}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


async def _tools(client: Client) -> dict:
    # bypass cache: phải thấy định nghĩa HIỆN TẠI của server, không phải bản đã lưu.
    return {t.name: t for t in (await client.list_tools(cache_mode="bypass")).tools}


async def guarded_call(client: Client, pins: dict[str, str], name: str, args: dict,
                       ledger_path: Path, principal_id: str, run_id: str):
    tool = (await _tools(client)).get(name)
    current = tool_fingerprint(tool) if tool else None
    if name not in pins:
        allowed, reason = False, f"deny mcp:{name}: tool chưa được duyệt (không có pin)"
    elif current != pins[name]:
        allowed, reason = False, (f"deny mcp:{name}: định nghĩa tool đổi sau khi duyệt "
                                  f"(pin {pins[name][:12]} != hiện tại {str(current)[:12]}) — nghi rug pull")
    else:
        allowed, reason = True, f"allow mcp:{name}: định nghĩa khớp pin {current[:12]}"
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(), "agent_id": AGENT_ID, "run_id": run_id,
        "on_behalf_of": principal_id, "tool": f"mcp:{name}",
        "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest(),
        "classification": "internal", "decision": "allow" if allowed else "deny", "reason": reason,
    }, ledger_path)
    if not allowed:
        return False, reason, tool
    result = await client.call_tool(name, args)
    return True, result.content[0].text, tool


async def demo(ledger_path: Path, principal_id: str = "support_l1") -> list[dict]:
    """Trả về các bước để test kiểm; cũng in ra như log."""
    steps = []
    run_id = uuid.uuid4().hex
    async with Client(SERVER) as client:
        approved = await _tools(client)
        pins = {name: tool_fingerprint(t) for name, t in approved.items()}
        print(f"[duyệt] lookup_ticket: {approved['lookup_ticket'].description!r}")
        print(f"[duyệt] pin sha256={pins['lookup_ticket'][:12]}…")

        for ticket_id in (7, 8):
            ok, out, tool = await guarded_call(client, pins, "lookup_ticket", {"ticket_id": ticket_id},
                                               ledger_path, principal_id, run_id)
            hijack = find_injection(tool.description or "")
            steps.append({"ticket_id": ticket_id, "allowed": ok, "output": out,
                          "description": tool.description, "injection": hijack is not None})
            print(f"[gọi {ticket_id}] {'ALLOW' if ok else 'DENY '} | {out}")
            if hijack:
                print(f"         client ngây thơ sẽ đưa description mới vào context -> mock LLM thấy chỉ thị "
                      f"({len(hijack.matched_markers)} marker), đòi đọc {hijack.customer_ids} và POST "
                      f"{hijack.target_url}")
    print(f"[ledger] {ledger_path} verify={ledger.verify(ledger_path)}")
    return steps


if __name__ == "__main__":
    asyncio.run(demo(Path(tempfile.mkdtemp()) / "ledger.jsonl"))
