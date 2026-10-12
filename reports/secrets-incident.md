# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản:
  Gitleaks **8.30.1** (`gitleaks version`), binary linux_x64 tải từ release chính thức, checksum khớp `gitleaks_8.30.1_checksums.txt`. Config: `.gitleaks.toml` (rule mặc định + rule `lab24-synthetic-token`). Chạy trong WSL2 Ubuntu 26.04.

- Commit chứa token giả:
  `1bdd849922156c868a5ee9293d68f5b72e242d2c` ("chore: seed student lab with synthetic secret exercise", 2026-10-09). File bị xoá ở commit kế tiếp `ece6ca4` nhưng blob vẫn nằm trong lịch sử.

- File, rule và kết quả quét lịch sử:
  `gitleaks git --config .gitleaks.toml --redact --verbose .` → 11 commit, **1 finding**, exit code 1 (dự kiến):

  ```text
  Finding:     REDACTED
  Secret:      REDACTED
  RuleID:      lab24-synthetic-token
  Entropy:     4.600922
  File:        lab-fake-secret.txt
  Line:        1
  Commit:      1bdd849922156c868a5ee9293d68f5b72e242d2c
  Fingerprint: 1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1
  WRN leaks found: 1
  ```

  Đây là token **giả, vô hiệu** dạng `LAB24-DEMO-…` do đề bài cài sẵn — bằng chứng cho checkpoint, không phải sự cố bảo mật thật.

- Kết quả quét file hiện tại:
  `gitleaks dir --config .gitleaks.toml .` → `no leaks found`, exit code 0. `pre-commit run --all-files` → `Detect hardcoded secrets ... Passed`.
  Hook `.pre-commit-config.yaml`: repo `https://github.com/gitleaks/gitleaks`, `rev: v8.30.1`, `id: gitleaks-system`, `args: ["--config", ".gitleaks.toml"]`, `pass_filenames: false` (entry của hook là `gitleaks git --pre-commit --redact --staged --verbose`, chỉ nhận một repo path).
  Thử hook trên bản clone tạm (`/tmp/hookdemo`): stage một file chứa `LAB24_FAKE_TOKEN=LAB24-DEMO-…` → commit bị chặn (`Detect hardcoded secrets ... Failed`, `RuleID: lab24-synthetic-token`, exit 1), HEAD không đổi.

- Nếu đây là credential thật, cần xử lý thế nào:
  1. **Thu hồi / rotate ngay** tại hệ thống phát hành credential (coi như đã lộ từ thời điểm push `1bdd849`), cấp credential mới qua secret manager / biến môi trường, không đưa vào repo.
  2. Rà log truy cập của hệ thống đó trong khoảng từ 2026-10-09 tới lúc thu hồi để tìm sử dụng trái phép.
  3. Sau khi đã rotate mới xem xét xoá khỏi lịch sử (`git filter-repo`), force-push, yêu cầu các bản fork/clone đồng bộ lại, và nhờ nền tảng (GitHub) xoá cache/PR ref. Ghi lại incident và thêm rule/hook để chặn tái diễn.

- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  Xoá file ở commit sau chỉ đổi snapshot mới nhất; blob vẫn còn trong `1bdd849`, trong mọi clone/fork đã tải và có thể trong cache của nền tảng — ai có lịch sử đều đọc được. Kể cả viết lại lịch sử cũng không thu hồi được bản sao đã lộ. Chỉ **rotate/thu hồi** mới làm credential cũ vô dụng.
  Pin dependency (`requirements.lock` với `--hash=sha256`, cài bằng `pip install --require-hashes`) và pin hook (`rev: v8.30.1`) chống thay thế gói/công cụ ở lần cài **sau** — chúng phòng ngừa, không xử lý một secret **đã** lộ. Hook pre-commit cũng chỉ quét thay đổi được stage từ nay về sau (và có thể bị bỏ qua bằng `--no-verify` hoặc trên máy chưa cài hook), nên vẫn cần quét lịch sử/CI và quy trình rotate.
