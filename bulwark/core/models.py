"""Core Pydantic models for the Bulwark evaluation pipeline.

Every data structure that flows through Bulwark -- from the adversarial
prompt definition, through detector verdicts, to the final evaluation
report -- is defined here as a strict Pydantic v2 model.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from bulwark.core.categories import ASICode


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class Severity(str, Enum):
    """Impact severity of a finding or prompt."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Verdict(str, Enum):
    """Outcome of an individual detection or overall evaluation."""

    PASS = "PASS"
    FAIL = "FAIL"
    VULNERABLE = "VULNERABLE"
    UNCERTAIN = "UNCERTAIN"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


class Sophistication(str, Enum):
    """Attack complexity tier for an adversarial prompt."""

    BASIC = "BASIC"
    INTERMEDIATE = "INTERMEDIATE"
    ADVANCED = "ADVANCED"


# --------------------------------------------------------------------------- #
# Adversarial prompt definition
# --------------------------------------------------------------------------- #


class AdversarialPrompt(BaseModel):
    """A single adversarial test prompt used during evaluation."""

    model_config = {"frozen": True, "str_strip_whitespace": True}

    id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:12],
        description="Unique identifier for this prompt.",
    )
    category: ASICode = Field(
        ...,
        description="OWASP ASI category this prompt targets (e.g. ASI01).",
    )
    severity: Severity = Field(
        default=Severity.MEDIUM,
        description="Severity rating if the attack succeeds.",
    )
    prompt_text: str = Field(
        ...,
        min_length=1,
        description="The adversarial prompt content sent to the agent.",
    )
    description: str = Field(
        default="",
        description="Human-readable explanation of the attack vector.",
    )
    expected_behavior: str = Field(
        default="",
        description="What a secure agent should do when presented with this prompt.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Free-form labels for filtering and grouping.",
    )
    sophistication: Sophistication = Field(
        default=Sophistication.BASIC,
        description="Complexity tier of the attack.",
    )


# --------------------------------------------------------------------------- #
# Detector output
# --------------------------------------------------------------------------- #


class DetectorResult(BaseModel):
    """Result produced by a single detector examining one agent response."""

    model_config = {"str_strip_whitespace": True}

    detector_name: str = Field(
        ...,
        min_length=1,
        description="Identifier of the detector that produced this result.",
    )
    verdict: Verdict = Field(
        ...,
        description="Whether the detector judged the response as safe or not.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Detector confidence in the verdict (0.0 to 1.0).",
    )
    reasoning: str = Field(
        default="",
        description="Free-text explanation of why this verdict was reached.",
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Observable signals that contributed to the verdict.",
    )
    severity: Severity = Field(
        default=Severity.MEDIUM,
        description="Severity assigned by the detector to this finding.",
    )
    remediation_hint: str = Field(
        default="",
        description="Suggested mitigation or fix if the verdict is negative.",
    )


# --------------------------------------------------------------------------- #
# Single evaluation record (one prompt -> one response -> N detectors)
# --------------------------------------------------------------------------- #


class EvalRecord(BaseModel):
    """Complete record for one prompt/response evaluation cycle."""

    model_config = {"str_strip_whitespace": True}

    prompt: AdversarialPrompt = Field(
        ...,
        description="The adversarial prompt that was sent.",
    )
    response_text: str = Field(
        ...,
        description="Raw text response returned by the agent under test.",
    )
    response_time_ms: float = Field(
        ...,
        ge=0.0,
        description="Wall-clock response latency in milliseconds.",
    )
    detector_results: list[DetectorResult] = Field(
        default_factory=list,
        description="Verdicts from each detector that analyzed this response.",
    )
    overall_verdict: Verdict = Field(
        default=Verdict.UNCERTAIN,
        description="Aggregated verdict across all detectors.",
    )
    overall_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Aggregated confidence score.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this evaluation was recorded (UTC).",
    )


# --------------------------------------------------------------------------- #
# Report summary
# --------------------------------------------------------------------------- #


class EvalSummary(BaseModel):
    """Aggregate statistics for a completed evaluation run."""

    model_config = {"frozen": True}

    total: int = Field(..., ge=0, description="Total prompts evaluated.")
    passed: int = Field(default=0, ge=0, description="Prompts that passed.")
    failed: int = Field(default=0, ge=0, description="Prompts that failed.")
    vulnerable: int = Field(
        default=0, ge=0, description="Prompts flagged as vulnerable."
    )
    uncertain: int = Field(
        default=0, ge=0, description="Prompts with uncertain verdicts."
    )
    errors: int = Field(
        default=0, ge=0, description="Prompts that produced errors."
    )
    timeouts: int = Field(
        default=0, ge=0, description="Prompts that timed out."
    )
    pass_rate: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Fraction of prompts that passed (0.0 to 1.0).",
    )
    categories_tested: list[ASICode] = Field(
        default_factory=list,
        description="ASI categories covered by this evaluation.",
    )
    worst_category: Optional[ASICode] = Field(
        default=None,
        description="Category with the lowest pass rate, if any.",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Overall risk score from 0 (safe) to 100 (critical).",
    )

    @field_validator("pass_rate")
    @classmethod
    def _validate_pass_rate(cls, v: float) -> float:
        return round(v, 4)

    @model_validator(mode="after")
    def _check_counts(self) -> "EvalSummary":
        counted = (
            self.passed
            + self.failed
            + self.vulnerable
            + self.uncertain
            + self.errors
            + self.timeouts
        )
        if counted > self.total:
            raise ValueError(
                f"Sum of verdict counts ({counted}) exceeds total ({self.total})."
            )
        return self


# --------------------------------------------------------------------------- #
# Top-level evaluation report
# --------------------------------------------------------------------------- #


class EvalReport(BaseModel):
    """Full evaluation report for a single agent assessment run."""

    model_config = {"str_strip_whitespace": True}

    agent_name: str = Field(
        ...,
        min_length=1,
        description="Name or identifier of the agent under test.",
    )
    target: str = Field(
        default="",
        description="Endpoint, model name, or other target descriptor.",
    )
    started_at: datetime = Field(
        ...,
        description="When the evaluation run started (UTC).",
    )
    completed_at: datetime = Field(
        ...,
        description="When the evaluation run completed (UTC).",
    )
    records: list[EvalRecord] = Field(
        default_factory=list,
        description="Individual evaluation records for each prompt.",
    )
    summary: EvalSummary = Field(
        ...,
        description="Aggregate summary statistics for this report.",
    )

    @model_validator(mode="after")
    def _check_timing(self) -> "EvalReport":
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at.")
        return self
