"""A tamper-evident audit log.

An incident review needs to know what the agent was told and what it tried. A
plain log file answers that only if you trust it. This one chains each record to
the hash of the one before, so changing any earlier line breaks every line after
it, and the break is reported at the exact sequence number.

Honest limits, stated up front:

  * Deleting the last line cannot be detected, because nothing follows it. Anchor
    the final hash somewhere else, such as a ticket or a git commit, if that
    matters to you.
  * Rewriting the whole file is detectable only against such an anchor.
  * This is tamper *evidence*, not tamper proofing. It makes silent edits loud.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

GENESIS = "0" * 64


def canonical(record: Dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(record: Dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "hash"}
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only JSONL where every record chains to the previous one."""

    def __init__(self, path: Optional[str] = None, stream=None):
        self.path = path
        self.stream = stream
        self.sequence, self.head = self._load_tail()

    def _load_tail(self) -> Tuple[int, str]:
        if not self.path or not os.path.exists(self.path):
            return 0, GENESIS
        last = None
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line
        if not last:
            return 0, GENESIS
        try:
            record = json.loads(last)
        except ValueError:
            return 0, GENESIS
        return int(record.get("seq", 0)) + 1, str(record.get("hash", GENESIS))

    def append(self, event: str, **fields: Any) -> Dict[str, Any]:
        record = {
            "seq": self.sequence,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "prev": self.head,
        }
        record.update(fields)
        record["hash"] = digest(record)
        line = canonical(record)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        elif self.stream is not None:
            self.stream.write(line + "\n")
            self.stream.flush()
        self.sequence += 1
        self.head = record["hash"]
        return record


def verify(path: str) -> Tuple[bool, Optional[int], int, str]:
    """Walk the chain. Returns (ok, first_bad_seq, count, message)."""
    if not os.path.exists(path):
        return False, None, 0, "no such log: %s" % path
    expected_prev = GENESIS
    expected_seq = 0
    count = 0
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                return False, expected_seq, count, "line %d is not valid JSON" % number
            if record.get("prev") != expected_prev:
                return False, int(record.get("seq", expected_seq)), count, "chain break at line %d: prev hash does not match" % number
            if digest(record) != record.get("hash"):
                return False, int(record.get("seq", expected_seq)), count, "record at line %d was modified after it was written" % number
            if int(record.get("seq", -1)) != expected_seq:
                return False, int(record.get("seq", expected_seq)), count, "sequence gap at line %d" % number
            expected_prev = record["hash"]
            expected_seq += 1
            count += 1
    return True, None, count, "chain intact across %d record(s)" % count


def read_records(path: str) -> List[Dict[str, Any]]:
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records
