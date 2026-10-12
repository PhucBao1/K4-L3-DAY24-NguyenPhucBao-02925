# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
   **Chưa.** `agent/loop.py:27` `_naive_loop(message, llm)` không nhận principal, không tạo `run_id`/`agent_id`, không có `expires_at`. `run_once()` (`agent/loop.py:57-58`) có tham số `principal_id` nhưng khi rơi về baseline (`agent/loop.py:74`) nó bị bỏ qua — mọi tool call chạy dưới cùng một danh tính ngầm, không phân biệt `support_l1` hay `dpo`.

2. Ai cho phép `http_post`? Dẫn file/hàm:
   **Không ai cả — chính nội dung attacker quyết định.** `agent/loop.py:34` gọi `llm.find_injection(combined_text)` trên toàn văn ticket; nếu thấy chỉ thị thì `agent/loop.py:39` đọc `tools.read_customer(customer_id)` với ID lấy từ free text, rồi `agent/loop.py:44` gọi `tools.http_post(injected.target_url, ...)` với URL cũng lấy từ free text. Không có PEP (`policy.check`) trước tool call. Kiểm tra duy nhất là allowlist cứng ở `agent/tools.py:77-78` (`127.0.0.1:10024`) — đó là rào an toàn của lab, không phải quyết định cấp quyền, và sink chính là địa chỉ được allow.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
   **Chỉ có ở phía nhận.** Sink ghi body POST vào `reports/sink.log` (`sink/sink.py:37`, `sink/sink.py:47`). Phía agent không có audit ledger: `_naive_loop` không ghi ai gọi tool nào, cho ai, với lý do gì, allow hay deny. Nếu sink không thuộc quyền mình (attacker thật), sẽ không có bằng chứng nào trong hệ thống của mình. Bằng chứng tái hiện: `reports/attack-before.log` (checkpoint 2).
