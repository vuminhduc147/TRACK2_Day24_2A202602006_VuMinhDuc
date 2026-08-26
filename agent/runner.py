"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

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

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
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

from agent import ledger, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)(?:b)?\.md$", re.IGNORECASE)
_AGENT_TTL = timedelta(minutes=15)


def _args_hash(args: dict) -> str:
    encoded = json.dumps(args, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _policy_tool_call(
    *,
    tool_name: str,
    args: dict,
    context: PolicyContext,
    run_id: str,
    ledger_path: Path,
    execute,
):
    allow, reason = check(context)
    now = datetime.now(timezone.utc)
    ledger.append(
        {
            "ts": now.isoformat(),
            "agent_id": context.agent_owner,
            "agent_owner": context.agent_owner,
            "run_id": run_id,
            "expires_at": (now + _AGENT_TTL).isoformat(),
            "tool": tool_name,
            "args_hash": _args_hash(args),
            "classification": context.data_classification,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        },
        ledger_path,
    )
    if not allow:
        return None
    return execute()


def _ticket_ids_from_docs(docs: list[dict]) -> tuple[int, ...]:
    """Return only typed IDs derived from trusted filename metadata."""
    ticket_ids = set()
    for doc in docs:
        match = _TICKET_FILE_RE.fullmatch(str(doc.get("id", "")))
        if match:
            ticket_ids.add(int(match.group(1)))
    return tuple(sorted(ticket_ids))


def _customer_ids_for_tickets(ticket_ids: tuple[int, ...]) -> tuple[str, ...]:
    """Map typed ticket IDs to customers using the trusted relationship store."""
    requested = set(ticket_ids)
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return tuple(
        str(customer["customer_id"])
        for customer in customers
        if requested.intersection(int(value) for value in customer.get("related_tickets", []))
    )


def _run_private(ticket_ids: tuple[int, ...], ledger_path: Path, request_id: str) -> list[dict]:
    """Run B receives typed IDs only; document free text cannot cross this boundary."""
    run_id = f"{request_id}:private"
    context = PolicyContext(
        data_classification="restricted",
        request_purpose="support-ticket-resolution",
        agent_owner="lab24-private-agent",
        delegation_depth=1,
        egress_enabled=False,
    )
    records = []
    for customer_id in _customer_ids_for_tickets(ticket_ids):
        record = _policy_tool_call(
            tool_name="read_customer",
            args={"customer_id": customer_id},
            context=context,
            run_id=run_id,
            ledger_path=ledger_path,
            execute=lambda customer_id=customer_id: tools.read_customer(customer_id),
        )
        if record is not None:
            records.append(record)
    return records


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir is not None else DEFAULT_LEDGER_PATH
    request_id = uuid.uuid4().hex
    search_context = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-search-agent",
        delegation_depth=0,
        egress_enabled=False,
    )
    docs = _policy_tool_call(
        tool_name="search_docs",
        args={"query": message},
        context=search_context,
        run_id=f"{request_id}:search",
        ledger_path=ledger_path,
        execute=lambda: tools.search_docs(message),
    )
    if docs is None:
        return "Yêu cầu tìm kiếm bị policy từ chối."

    combined_text = "\n\n".join(doc["text"] for doc in docs)
    injected = llm.find_injection(combined_text)
    ticket_ids = _ticket_ids_from_docs(docs)
    _run_private(ticket_ids, ledger_path, request_id)

    if injected is not None:
        egress_context = PolicyContext(
            data_classification="restricted",
            request_purpose="instruction-from-untrusted-document",
            agent_owner="lab24-egress-agent",
            delegation_depth=1,
            egress_enabled=True,
        )
        _policy_tool_call(
            tool_name="http_post",
            args={"url": injected.target_url, "record_count": 0},
            context=egress_context,
            run_id=f"{request_id}:egress",
            ledger_path=ledger_path,
            execute=lambda: tools.http_post(injected.target_url, {"records": []}),
        )

    return llm.summarize(docs)
