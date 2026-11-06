from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        return cls[name.strip().upper()]


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    file: str
    line: int
    snippet: str
    source: str = "static"  # "static" or "llm"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.name,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "source": self.source,
        }


@dataclass
class SkillReport:
    path: str
    name: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    llm_verdict: Optional[str] = None  # "malicious" | "suspicious" | "benign" | None

    @property
    def max_severity(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict:
        ms = self.max_severity
        return {
            "path": self.path,
            "name": self.name,
            "files_scanned": self.files_scanned,
            "max_severity": ms.name if ms is not None else None,
            "llm_verdict": self.llm_verdict,
            "findings": [f.to_dict() for f in self.findings],
        }
