import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from socdetect.engine import Rule  # noqa: E402
from socdetect.parsers import Event  # noqa: E402

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)


def make_event(seconds: int = 0, source: str = "linux", **fields) -> Event:
    fields.setdefault("source", source)
    return Event(T0 + timedelta(seconds=seconds), source, {k.lower(): v for k, v in fields.items()}, raw=str(fields))


def make_rule(detection: dict, logsource: str = "linux", rid: str = "test_rule") -> Rule:
    return Rule(id=rid, title="Test rule", description="", severity="high", logsource=logsource,
                tactic="Credential Access", technique_id="T1110", technique_name="Brute Force",
                detection=detection)


@pytest.fixture
def root() -> Path:
    return ROOT
