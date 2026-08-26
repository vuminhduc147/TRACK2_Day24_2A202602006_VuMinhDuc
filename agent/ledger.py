"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


_GENESIS_HASH = "0" * 64
_REQUIRED_FIELDS = {
    "ts",
    "agent_id",
    "run_id",
    "tool",
    "args_hash",
    "classification",
    "decision",
    "reason",
}


def _canonical(entry: dict) -> str:
    return json.dumps(entry, ensure_ascii=False, sort_keys=True)


def _entry_hash(entry: dict) -> str:
    return hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.exists():
        return _GENESIS_HASH

    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return _GENESIS_HASH
    try:
        last_entry = json.loads(lines[-1])
        value = last_entry["hash"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("cannot append to a malformed ledger") from exc
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("cannot append to a ledger with an invalid tail hash")
    return value


def append(entry: dict, path: Path) -> dict:
    """Append one hash-chained JSON record without mutating the caller's dict."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    record = dict(entry)
    record.pop("hash", None)
    record.pop("prev_hash", None)
    record["prev_hash"] = _last_hash(path)
    record["hash"] = _entry_hash(record)

    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return record


def verify(path: Path) -> bool:
    """Verify required audit data and every link in the ledger hash chain."""
    path = Path(path)
    if not path.exists():
        return False

    expected_prev = _GENESIS_HASH
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return False

    for line in lines:
        if not line.strip():
            return False
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return False
        if not isinstance(record, dict) or not _REQUIRED_FIELDS.issubset(record):
            return False
        if not isinstance(record.get("reason"), str) or not record["reason"].strip():
            return False
        if record.get("prev_hash") != expected_prev:
            return False

        stored_hash = record.get("hash")
        if not isinstance(stored_hash, str):
            return False
        unhashed = dict(record)
        unhashed.pop("hash", None)
        if stored_hash != _entry_hash(unhashed):
            return False
        expected_prev = stored_hash

    return True
