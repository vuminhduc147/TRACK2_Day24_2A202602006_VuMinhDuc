# Bước 1 - Baseline

## Luồng gọi tool

```text
Yêu cầu người dùng
        |
        v
search_docs(message)                 agent/loop.py:31
        |
        v
Toàn văn ticket không tin cậy
        |
        v
llm.find_injection(combined_text)    agent/loop.py:34
        |
        +-- customer_ids ----------> read_customer(customer_id)  agent/loop.py:37-40
        |
        +-- target_url + dữ liệu ---> http_post(url, records)     agent/loop.py:42-44
        |
        v
llm.summarize(docs)                  agent/loop.py:54
```

Quyền của baseline gồm cả ba chân của lethal trifecta trong cùng một run:

- Đọc nội dung không tin cậy trong `corpus/` qua `search_docs` (`agent/tools.py:34-52`).
- Đọc dữ liệu khách hàng riêng tư qua `read_customer` (`agent/tools.py:55-65`).
- Gửi dữ liệu tới sink qua `http_post` (`agent/tools.py:68-84`).

## Ba câu trả lời

### 1. Agent có identity riêng không?

Không. `_naive_loop` chỉ nhận `message` và `llm` (`agent/loop.py:27`), không tạo hoặc truyền `run_id`, `agent_id`, chủ sở hữu hay TTL. `run_once` cũng chỉ khởi tạo LLM rồi gọi loop/runner (`agent/loop.py:57-80`). Vì vậy baseline không có identity riêng theo run hoặc theo agent.

### 2. Ai quyết định agent được gọi `http_post`?

Nội dung ticket không tin cậy tác động trực tiếp đến quyết định. Toàn văn kết quả tìm kiếm được ghép ở `agent/loop.py:31-32`, sau đó `llm.find_injection` đọc nội dung này ở dòng 34. Nếu model tìm thấy chỉ thị và đọc được ít nhất một khách hàng, code gọi thẳng `tools.http_post` ở dòng 44. Không có Policy Enforcement Point hay bước phê duyệt độc lập trước tool call. Allowlist trong `agent/tools.py:76-82` chỉ giới hạn đích đến `localhost:9999`, không quyết định dữ liệu nào được phép gửi.

### 3. Nếu agent gửi sai dữ liệu ra ngoài, biết bằng cách nào?

Baseline không có audit ledger. `_naive_loop` gọi `http_post` tại `agent/loop.py:44` nhưng không ghi identity, tool call, quyết định hoặc lý do. Bằng chứng duy nhất trong lab là log phía nhận do sink ghi vào `reports/sink.log`; đó là dấu vết sau khi dữ liệu đã bị gửi, không phải audit log đầy đủ của agent. Nếu sink không lưu log thì baseline không cung cấp cách truy vết đáng tin cậy.
