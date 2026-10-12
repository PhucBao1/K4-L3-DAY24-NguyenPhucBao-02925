# DPIA-lite — điền trong checkpoint 5

Phạm vi: agent hỗ trợ khách hàng trong lab Day 24, chạy `--mock`, dữ liệu **synthetic** (`corpus/`, `data/customers.json`). Không có dữ liệu cá nhân thật.

1. Loại dữ liệu và phân loại:
   - `corpus/*.md` (ticket): **internal** — nội dung không tin cậy (attacker có thể chèn chỉ thị), có thể lẫn SĐT/STK trong lời khách.
   - `data/customers.json`: **restricted** — họ tên, CCCD (12 số), SĐT, STK, email, `related_tickets`. CCCD và STK được coi là dữ liệu nhạy cảm cần bảo vệ cao nhất trong lab.
   - `data/principals.json`: cấu hình quyền (fixture mô phỏng), không chứa PII.
   - `reports/ledger.jsonl`: metadata tool call; chỉ có `customer_id` dạng hash trong `args_hash`, không có PII thô.

2. Mục đích xử lý và principal:
   - `summarize-tickets`: tổng hợp ticket — mọi principal được phép, chỉ dùng `search_docs`.
   - `support-reply`: đối chiếu hồ sơ khách gắn với ticket — chỉ `dpo` được `read_customer` (`billing` có tool nhưng không có purpose `support-reply` nên cũng bị deny); `support_l1` không đọc record restricted.
   - Không mục đích nào cho phép gửi dữ liệu restricted ra ngoài (egress).

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
   - **Run A** (`lab24-agent/run-a`): `search_docs` đọc `corpus/`. Ra khỏi Run A chỉ có `list[int]` số ticket lấy từ tên file (`agent/runner.py:87`) và một cờ "có chỉ thị lạ".
   - **Run B** (`lab24-agent/run-b`): map số ticket → `customer_id` qua `related_tickets` (`agent/runner.py:97-101`), rồi `read_customer` sau khi PEP allow (`agent/runner.py:148`). Record chỉ dùng trong bộ nhớ để đếm/đối chiếu; câu trả lời cuối được `pii.redact()` (`agent/runner.py:167`).
   - **Egress**: endpoint duy nhất có thể là `http://127.0.0.1:10024/reconcile` (sink local, hằng số trong code, `agent/runner.py:79`; allowlist cứng ở `agent/tools.py:77-78`). Với dữ liệu restricted, PEP luôn deny (`agent/policy.py:74`), nên trong lần prove không có request nào tới sink.

4. Bằng chứng deny/allow và giới hạn của mock:
   - Trước containment: `reports/attack-before.log` chứa record synthetic của `KH-000999` (CCCD, SĐT, STK, email).
   - Sau containment: `reports/attack-after.log` rỗng (0 byte) với cùng query, chạy `--as dpo` và `--as support_l1`.
   - `reports/ledger.jsonl` (45 dòng, `verify()` = True, mọi dòng có `reason`): dòng 1 `search_docs` allow (dpo); dòng 23 `http_post` **deny** `restricted data with egress enabled`, `on_behalf_of=dpo`; dòng 25 `read_customer` **deny** `not in effective scope []`, `on_behalf_of=support_l1`; `dpo` đọc 21 hồ sơ gắn ticket, `support_l1` bị deny 21 lần.
   - Giới hạn:
     - Mock LLM phát hiện chỉ thị bằng marker cố định; model thật có thể hiểu lure theo cách khác. Containment (split + PEP) không dựa vào việc phát hiện đúng.
     - `--as` chỉ chọn principal mô phỏng; không có xác thực danh tính, không có token thật. Production cần IdP và token có chữ ký, có scope và hạn.
     - `dpo` vẫn đọc hợp lệ hồ sơ `KH-000999` vì lure được gắn vào chính ticket của khách đó; chỉ PEP egress ngăn rò rỉ.
     - Ledger hash-chain trong một file không phát hiện được xoá dòng cuối hoặc viết lại toàn bộ chuỗi; cần mốc tin cậy bên ngoài (WORM storage, anchor hash).
     - Regex PII đạt precision/recall 1.0 trên 120 câu test set synthetic; dữ liệu thật đa dạng hơn (định dạng khác, tên người) sẽ thấp hơn.
     - Điều khoản pháp luật trong `compliance-mapping.md` chưa được đối chiếu với văn bản gốc.
