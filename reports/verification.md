# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
  Windows 11 + WSL2 Ubuntu 26.04.1 LTS (kernel 6.6.87.2-microsoft-standard-WSL2) / Python 3.14.4 (venv `.venv`) / Gitleaks 8.30.1 (linux_x64, checksum khớp release) / pre-commit 4.6.2.

- `python -m pytest tests/ -q`:
  Phần bắt buộc: `33 passed` (trước khi thêm bonus); toàn bộ sau bonus: `52 passed` (33 bắt buộc + 19 bonus). Phần bắt buộc gồm `test_injection.py` 8/8 (4 biến thể × `support_l1`, `dpo`), `test_split.py`, `test_obo.py` 5/5, `test_policy.py` 4/4, `test_ledger.py` 3/3, `test_pii.py` 2/2, `test_supply_chain.py` 3/3, `test_scaffold_dispatch.py`, `test_check_lure_cli.py`.
  PII (`pytest tests/test_pii.py -s`): `gold=118 pred=118 tp=118`, **precision=1.000 recall=1.000**.
  Lure: `python -m agent.check_lure corpus/ticket-90*.md` → `4/4 lure sẵn sàng`.

- `pre-commit run --all-files`:
  `Detect hardcoded secrets ... Passed`. `gitleaks dir --config .gitleaks.toml .` → `no leaks found` (exit 0). `gitleaks git --config .gitleaks.toml --redact .` → 1 finding `lab24-synthetic-token` ở `1bdd849` (exit 1, dự kiến — xem `secrets-incident.md`). `pip install --require-hashes -r requirements.lock` → exit 0.

- Ledger verify:
  `verify(Path('reports/ledger.jsonl'))` → `True` (45 dòng, mọi dòng có `reason`; dòng 23 `http_post` deny `on_behalf_of=dpo`). `reports/attack-after.log` = 0 byte; `reports/attack-before.log` có record synthetic `KH-000999`.
  Thử tamper trên bản copy: sửa 1 ký tự dòng giữa → `False`; xoá dòng giữa → `False`; cắt dòng cuối → `True` (giới hạn đã biết).

- Bonus (log/test riêng, dependency bonus nằm trong `requirements-bonus.txt`, không vào `requirements.lock`):
  - Delete cascade (3đ): `bonus/erasure.py`, `tests/test_bonus_erasure.py` 2/2, `reports/bonus-erasure.log` — `dpo` xoá `KH-000999` khỏi store + sink log, ledger chỉ append 1 dòng `delete_customer`, `verify=True`; `support_l1` bị deny. Thêm `delete_customer` vào `allowed_tools` của `dpo` trong `data/principals.json`.
  - OPA (4đ): OPA v1.21.1 (checksum khớp release), `bonus/policy.rego`, `bonus/opa_parity.py`, `tests/test_bonus_opa.py` 16/16, `reports/bonus-opa.log` — Rego và `policy.check` khớp allow/deny trên 16 case.
  - MCP rug pull (4đ): `mcp==2.2.0`, `bonus/mcp_rugpull/`, `tests/test_bonus_mcp_rugpull.py` 1/1, `reports/bonus-mcp-rugpull.log` — tool đổi description sau lần gọi đầu bị client pin-hash deny, ledger `[allow, deny]`, `verify=True`.
  - GLiNER vs regex: không làm (3 bonus trên đã đạt mức trần 10đ).

- Các lỗi còn lại:
  - README khuyến nghị Python 3.11+; đã chạy trên 3.14.4, không gặp lỗi. Ubuntu 26.04 cần `sudo apt install python3.14-venv` trước khi tạo venv (lỗi `ensurepip is not available` nếu thiếu).
  - Repo nằm trên ổ Windows (`/mnt/d`) với `core.autocrlf=true`: git trong WSL báo mọi file "modified" do CRLF, nội dung không đổi. Thao tác git chạy bằng git của Windows; Python/gitleaks chạy trong WSL.
  - Lệnh `gitleaks git` trả exit 1 khi gặp token giả — đúng thiết kế đề bài, không phải lỗi.
  - Hook pre-commit đã cấu hình và chạy được qua `pre-commit run`, nhưng chưa `pre-commit install` vào `.git/hooks` của repo (commit thực hiện từ Windows, nơi chưa có gitleaks). Đã thử hook trên bản clone tạm trong WSL: commit chứa token giả bị chặn.
  - Điều khoản pháp luật trong `compliance-mapping.md` chưa đối chiếu văn bản gốc (ghi `chưa xác minh`).
  - Bonus: `args_hash` là sha256 của `customer_id` — không gian ID nhỏ nên dò ngược được (pseudonymous, không ẩn danh); production nên dùng HMAC có khoá. OPA dùng `time.parse_rfc3339_ns`, chặt hơn `datetime.fromisoformat` của Python (ví dụ `2099-01-01 00:00:00+00:00` có dấu cách: Python chấp nhận, OPA deny) — lệch về phía an toàn, không case nào trong lab gặp. Test MCP mất ~35 giây do khởi động/tắt server stdio trên `/mnt/d`; tự skip nếu chưa cài `mcp`, test OPA tự skip nếu không có binary `opa`.
