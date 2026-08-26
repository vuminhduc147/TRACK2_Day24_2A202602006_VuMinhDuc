# DPIA-lite (1 trang)

## 1. Dữ liệu gì

Hệ thống xử lý dữ liệu synthetic trong phạm vi lab, không dùng dữ liệu cá
nhân thật. `search_docs` đọc toàn văn ticket trong `corpus/`; nội dung có thể
chứa tên, CCCD, số điện thoại và số tài khoản do khách cung cấp, đồng thời là
nguồn không tin cậy có thể chứa prompt injection. `read_customer` đọc kho riêng
`data/customers.json`, gồm customer ID, họ tên, CCCD, số điện thoại, số tài
khoản, email và danh sách ticket liên quan. Các trường CCCD, SĐT, STK và email
được phân loại là `restricted`; nội dung ticket thông thường là `internal`.

## 2. Mục đích gì

Mục đích là tìm và tóm tắt ticket hỗ trợ, sau đó tra đúng hồ sơ khách hàng có
quan hệ tin cậy với ticket để phục vụ xử lý yêu cầu. Run A chỉ tìm tài liệu và
trích ticket ID từ tên file. Run B dùng ticket ID đó để tra quan hệ
`related_tickets`; customer ID viết trong free text không được dùng để quyết
định truy cập dữ liệu. PII gate hỗ trợ phát hiện và redact trước khi nội dung
được đưa sang context hoặc store khác.

## 3. Chảy đi đâu

Ở đường chấm mặc định `--mock`, dữ liệu chỉ ở máy local: `corpus/`,
`data/customers.json`, output CLI và audit `reports/ledger.jsonl`. Sink thử
nghiệm chỉ nghe tại `localhost:9999`; trước containment nó nhận PII như ghi ở
`reports/attack-before.log`, còn sau containment `reports/attack-after.log`
rỗng. Ledger chỉ lưu metadata và hash của tham số, không lưu raw PII.

Nếu dùng `--model claude-...`, nội dung gửi để tóm tắt có thể đi tới API của
model provider và phải được xem xét như luồng chuyển dữ liệu ra ngoài hệ thống,
có khả năng xuyên biên giới. Lab không dùng đường này để chấm. Trước mọi tool
call, PEP đánh giá classification, purpose, owner, delegation depth và egress;
rule bắt buộc từ chối `restricted` khi egress được bật. Egress do injection yêu
cầu vì vậy không thực thi và được ghi `decision=deny` kèm reason trong ledger.

Rủi ro còn lại: quyền yêu cầu xóa/delete cascade chưa được triển khai; ledger
được giữ bất biến để phục vụ audit. Việc dùng model thật cần quy trình phê duyệt,
thời hạn lưu giữ và hồ sơ chuyển dữ liệu riêng trước khi bật trong production.
