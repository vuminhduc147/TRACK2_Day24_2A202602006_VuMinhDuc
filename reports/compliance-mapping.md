# Compliance mapping

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement delete cascade; xem stretch goal #3 trong `Guide.md`. | Chưa có evidence triển khai (`Guide.md:182-185`). |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory ghi rõ đường đi qua local mock, local sink và model provider nếu bật `--model`. | `reports/dpia-lite.md` §3. |
| ASI03 — privilege abuse | Mỗi run có agent identity, run ID và TTL; mọi tool call qua policy trước khi execute. | `agent/runner.py:77-105`, `agent/runner.py:90-99`, `reports/ledger.jsonl`. |
| ASI01 — goal hijack | Trifecta split chỉ truyền ticket ID typed từ tên file; restricted data không được egress. | `agent/runner.py:108-150`, `agent/runner.py:175-195`, `reports/attack-after.log`, `tests/test_split.py`. |
| ISO 42001 Clause 5-6 | Policy-as-code được review/test và commit riêng. | `agent/policy.py:39-59`, commit `37622cf`, `tests/test_policy.py`. |
