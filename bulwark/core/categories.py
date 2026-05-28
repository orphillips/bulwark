"""OWASP ASI (AI Agent Security Initiative) threat categories.

Defines the 10 core risk categories used by Bulwark to classify
adversarial prompts and security findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ASICode(str, Enum):
    """OWASP ASI category identifiers."""

    ASI01 = "ASI01"
    ASI02 = "ASI02"
    ASI03 = "ASI03"
    ASI04 = "ASI04"
    ASI05 = "ASI05"
    ASI06 = "ASI06"
    ASI07 = "ASI07"
    ASI08 = "ASI08"
    ASI09 = "ASI09"
    ASI10 = "ASI10"


@dataclass(frozen=True)
class ASICategory:
    """Metadata for a single OWASP ASI threat category."""

    id: ASICode
    name: str
    description: str
    severity_default: str  # one of CRITICAL / HIGH / MEDIUM / LOW


# --------------------------------------------------------------------------- #
# Canonical category registry
# --------------------------------------------------------------------------- #

ASI_CATEGORIES: dict[ASICode, ASICategory] = {
    ASICode.ASI01: ASICategory(
        id=ASICode.ASI01,
        name="Prompt Injection",
        description=(
            "Direct or indirect manipulation of agent instructions through "
            "crafted input, causing the agent to deviate from its intended "
            "behavior or execute unauthorized actions."
        ),
        severity_default="CRITICAL",
    ),
    ASICode.ASI02: ASICategory(
        id=ASICode.ASI02,
        name="Insecure Output Handling",
        description=(
            "Failure to validate, sanitize, or constrain agent outputs before "
            "they reach downstream systems or end users, enabling injection "
            "attacks, data leakage, or unintended side effects."
        ),
        severity_default="HIGH",
    ),
    ASICode.ASI03: ASICategory(
        id=ASICode.ASI03,
        name="Excessive Agency",
        description=(
            "The agent possesses or exercises more authority than required for "
            "its task, including unnecessary tool access, overly broad "
            "permissions, or autonomous decision-making without human oversight."
        ),
        severity_default="HIGH",
    ),
    ASICode.ASI04: ASICategory(
        id=ASICode.ASI04,
        name="Resource Management",
        description=(
            "Improper control of computational resources such as tokens, API "
            "calls, memory, or time, leading to denial of service, cost "
            "explosion, or resource exhaustion attacks."
        ),
        severity_default="MEDIUM",
    ),
    ASICode.ASI05: ASICategory(
        id=ASICode.ASI05,
        name="Tool Use Safety",
        description=(
            "Unsafe invocation of external tools, APIs, or plugins by the "
            "agent, including passing unsanitized parameters, invoking "
            "unintended tools, or failing to verify tool outputs."
        ),
        severity_default="CRITICAL",
    ),
    ASICode.ASI06: ASICategory(
        id=ASICode.ASI06,
        name="Data Privacy",
        description=(
            "Unauthorized access, retention, or disclosure of sensitive data "
            "by the agent, including PII leakage, training-data extraction, "
            "or failure to respect data-handling policies."
        ),
        severity_default="HIGH",
    ),
    ASICode.ASI07: ASICategory(
        id=ASICode.ASI07,
        name="Trust Boundaries",
        description=(
            "Failure to enforce proper trust boundaries between the agent, "
            "its tools, users, and external systems, allowing privilege "
            "escalation or cross-boundary data flows."
        ),
        severity_default="HIGH",
    ),
    ASICode.ASI08: ASICategory(
        id=ASICode.ASI08,
        name="Behavioral Drift",
        description=(
            "Gradual or sudden changes in agent behavior over extended "
            "interactions, including persona manipulation, goal hijacking, "
            "or erosion of safety constraints through multi-turn attacks."
        ),
        severity_default="MEDIUM",
    ),
    ASICode.ASI09: ASICategory(
        id=ASICode.ASI09,
        name="Scope Violations",
        description=(
            "The agent operates outside its defined operational scope, "
            "performing actions or accessing information beyond its intended "
            "domain, role, or authorization level."
        ),
        severity_default="HIGH",
    ),
    ASICode.ASI10: ASICategory(
        id=ASICode.ASI10,
        name="Hallucination",
        description=(
            "Generation of fabricated, misleading, or ungrounded information "
            "presented as factual, including false tool outputs, invented "
            "citations, or confabulated reasoning chains."
        ),
        severity_default="MEDIUM",
    ),
}


def get_category(code: ASICode | str) -> ASICategory:
    """Look up an ASI category by code string or enum member."""
    if isinstance(code, str):
        code = ASICode(code)
    return ASI_CATEGORIES[code]
