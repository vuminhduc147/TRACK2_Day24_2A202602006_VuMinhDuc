"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_PATTERNS = (
    (
        "EMAIL",
        re.compile(
            r"(?<![\w.+-])[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}(?![\w-])",
            re.IGNORECASE,
        ),
        None,
    ),
    (
        "VN_CCCD",
        re.compile(
            r"\b(?:CCCD|CMND|căn\s+cước(?:\s+công\s+dân)?)\b[^\d\r\n]{0,24}"
            r"(?P<value>\d{12})(?!\d)",
            re.IGNORECASE,
        ),
        "value",
    ),
    (
        "VN_PHONE",
        re.compile(
            r"\b(?:SĐT|SDT|số\s+điện\s+thoại|so\s+dien\s+thoai|điện\s+thoại|phone)\b"
            r"[^\d\r\n]{0,32}(?P<value>0\d(?:[ .-]?\d){8,9})(?!\d)",
            re.IGNORECASE,
        ),
        "value",
    ),
    (
        "VN_BANK_ACCOUNT",
        re.compile(
            r"\b(?:STK|số\s+tài\s+khoản|so\s+tai\s+khoan|tài\s+khoản|tai\s+khoan)\b"
            r"[^\d\r\n]{0,32}(?P<value>\d(?:[ .-]?\d){7,15})(?!\d)",
            re.IGNORECASE,
        ),
        "value",
    ),
)


def detect(text: str) -> list[dict]:
    """Detect supported Vietnamese PII and return stable source offsets."""
    entities: list[dict] = []
    seen: set[tuple[str, int, int]] = set()

    for entity_type, pattern, value_group in _PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span(value_group) if value_group else match.span()
            key = (entity_type, start, end)
            if key not in seen:
                seen.add(key)
                entities.append({"type": entity_type, "start": start, "end": end})

    return sorted(entities, key=lambda entity: (entity["start"], entity["end"], entity["type"]))


def redact(text: str) -> str:
    """Replace detected PII without invalidating offsets of earlier matches."""
    entities = detect(text)
    accepted: list[dict] = []
    last_end = -1
    for entity in entities:
        if entity["start"] >= last_end:
            accepted.append(entity)
            last_end = entity["end"]

    redacted = text
    for entity in reversed(accepted):
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = redacted[: entity["start"]] + replacement + redacted[entity["end"] :]
    return redacted
