"""Pydantic v2 schemas for the ZeroDay-Guard AI API.

These are the contract between the FastAPI backend and the Next.js
dashboard, so every field carries a description the frontend can rely on.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EventLevel(str, Enum):
    info = "info"
    success = "success"
    warn = "warn"
    error = "error"
    agent = "agent"


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    """A scan target. Either a live URL or a repository/issue URL."""

    target_url: str = Field(
        ...,
        description="URL of the target: a web app, a GitHub repository, a release page, or a CVE page.",
        min_length=3,
        max_length=2048,
    )
    cve_id: str | None = Field(
        default=None,
        description="Optional CVE identifier to anchor the assessment, e.g. CVE-2024-3094.",
        max_length=64,
    )
    focus: str | None = Field(
        default=None,
        description="Optional analyst hint, e.g. 'authentication bypass' or 'RCE in parser'.",
        max_length=256,
    )

    @field_validator("target_url")
    @classmethod
    def _normalise_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target_url cannot be empty")
        # Bare hostnames are a common paste; assume https.
        if "://" not in v:
            v = f"https://{v}"
        return v


# ---------------------------------------------------------------------------
# Core domain objects
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    """A single vulnerability observation."""

    title: str
    severity: Severity = Severity.MEDIUM
    cwe: str | None = None
    description: str = ""
    location: str | None = None
    code_snippet: str | None = None
    language: str | None = None
    source_url: str | None = None
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    evidence: str | None = Field(
        default=None,
        description="Verbatim text lifted from the target page or advisory.",
    )
    occurrences: int = Field(
        default=1,
        ge=1,
        description=(
            "How many harvested artefacts showed this weakness class. The same "
            "vulnerability usually appears in several proof-of-concept files."
        ),
    )


class RiskScore(BaseModel):
    """ML-assisted vulnerability rating."""

    risk_score: int = Field(..., ge=0, le=100, description="Normalised 0-100 risk.")
    severity_label: Severity
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    engine: str = Field(default="ast", description="Which engines contributed: 'codebert+ast' or 'ast'.")
    factors: list[str] = Field(default_factory=list, description="Human-readable drivers of the score.")
    vector: dict[str, float] = Field(
        default_factory=dict,
        description="Per-dimension contribution, used by the radar chart.",
    )
    signals: dict[str, Any] = Field(default_factory=dict)


class PatchFix(BaseModel):
    """A generated remediation for the top finding."""

    title: str
    description: str
    diff: str = Field(default="", description="Unified-diff style patch.")
    language: str = "python"
    cwe: str | None = None
    steps: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class RiskVector(BaseModel):
    """Attack-surface breakdown shown in the radar chart."""

    attack_surface: float = Field(default=0, ge=0, le=100)
    exploit_maturity: float = Field(default=0, ge=0, le=100)
    patch_availability: float = Field(default=0, ge=0, le=100)
    code_injection: float = Field(default=0, ge=0, le=100)
    authentication_bypass: float = Field(default=0, ge=0, le=100)
    data_exposure: float = Field(default=0, ge=0, le=100)


class Assessment(BaseModel):
    """The full Zero-Day Security Assessment."""

    executive_summary: str
    vulnerability_breakdown: list[Finding] = Field(default_factory=list)
    risk_vector: RiskVector
    patch: PatchFix | None = None
    risk: RiskScore
    target: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reasoning_engine: str = Field(
        default="deterministic",
        description="Which reasoning backend produced the narrative: openai | anthropic | tinyfish-research | deterministic.",
    )
    agent_trace: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------
class AgentEvent(BaseModel):
    """One step in the live agent trace."""

    type: Literal["stage", "finding", "progress", "intel", "complete", "error"] = "stage"
    step: str
    message: str
    level: EventLevel = EventLevel.info
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] | None = None


class ScanResponse(BaseModel):
    """Non-streaming scan result."""

    assessment: Assessment
    events: list[AgentEvent] = Field(default_factory=list)
    elapsed_seconds: float = 0.0


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str
    version: str
    config: dict[str, Any]
