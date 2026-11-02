from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    TOOL_POISONING = "tool_poisoning"
    RETURN_CHANNEL = "return_channel"
    CROSS_SERVER_SHADOW = "cross_server_shadow"
    INSECURE_CONFIG = "insecure_config"


class Finding(BaseModel):
    id: str
    vuln_type: VulnType
    severity: Severity
    title: str
    description: str
    tool_name: str | None = None
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_vector: str | None = None
    remediation: str
    references: list[str] = Field(default_factory=list)


class ScanTarget(BaseModel):
    name: str
    config_path: str | None = None
    server_url: str | None = None
    tools: list[dict] = Field(default_factory=list)


class ScanResult(BaseModel):
    target: ScanTarget
    findings: list[Finding] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    scanner_version: str

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def passed(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0
