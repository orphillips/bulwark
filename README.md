# Bulwark

**AI Agent Security Evaluation Framework — red-team your agents against OWASP ASI Top 10.**

[![PyPI version](https://img.shields.io/pypi/v/bulwark-eval)](https://pypi.org/project/bulwark-eval/)
[![Python versions](https://img.shields.io/pypi/pyversions/bulwark-eval)](https://pypi.org/project/bulwark-eval/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Bulwark is an automated red-teaming and evaluation framework for AI agents. It ships 50 adversarial prompts mapped to the [OWASP Agentic Security Initiative (ASI) Top 10](https://owasp.org/www-project-agentic-security-initiative/) threat categories and runs them against your agent to produce a structured security scorecard. Use it to find prompt-injection vulnerabilities, data leakage risks, jailbreak susceptibility, and other agent-specific attack surfaces before your users do.

## Origin & Relationship to safelabs-eval

Bulwark was inspired by [**safelabs-eval**](https://github.com/AgentSafeLabs/safelabs-eval) by AgentSafeLabs (Waqar Javed), an Apache 2.0 licensed framework for evaluating AI agents against OWASP ASI vulnerabilities.

**Key differences from safelabs-eval:**

| | safelabs-eval | Bulwark |
|---|---|---|
| **Prompts** | 30 adversarial prompts | 50 prompts across 3 sophistication levels (Basic/Intermediate/Advanced) |
| **Detectors** | 5 regex-based detectors | 8 pattern detectors + optional LLM-powered semantic analysis |
| **Adapters** | HTTP, LangChain | HTTP, OpenAI-compatible, LangChain, arbitrary callables |
| **Output** | Text, JSON | Text (Rich), JSON, HTML reports |
| **Architecture** | Monolithic scoring | Modular detector registry with per-category routing |
| **Semantic analysis** | None | Optional LLM judge for deeper vulnerability assessment |
| **CLI** | Basic | Rich-formatted tables, progress bars, color-coded verdicts |
| **Dashboard** | None | Companion web dashboard available ([bulwark-dashboard](https://github.com/orphillips/bulwark-dashboard)) |

No source code was copied from safelabs-eval — Bulwark was built from scratch. Both projects reference the same public OWASP ASI standard. See [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for full attribution.

---

## Quick Install

```bash
pip install bulwark-eval
```

Optional extras:

```bash
pip install "bulwark-eval[langchain]"   # LangChain adapter
pip install "bulwark-eval[dev]"         # pytest + ruff
```

## Quick Start

### CLI

```bash
# Evaluate all OWASP ASI categories against an HTTP agent
bulwark run --target http://localhost:8000/chat

# Test specific categories
bulwark run --target http://localhost:8000/chat --category ASI01 --category ASI06

# Filter by sophistication level
bulwark run --target http://localhost:8000/chat --sophistication ADVANCED

# JSON output
bulwark run --target http://localhost:8000/chat --format json --output results.json

# List all categories
bulwark list

# Browse the prompt library
bulwark prompts --category ASI01
```

### Python SDK

```python
from bulwark import evaluate

# Evaluate an HTTP endpoint
report = await evaluate("http://localhost:8000/chat")

# Evaluate specific categories
report = await evaluate(
    "http://localhost:8000/chat",
    categories=["ASI01", "ASI06"],
    timeout=30,
)

# Evaluate a callable
async def my_agent(prompt: str) -> str:
    return "I cannot comply with that request."

report = await evaluate(my_agent, agent_name="my-agent")

# Access results
print(f"Risk score: {report.summary.risk_score}/100")
print(f"Pass rate:  {report.summary.pass_rate:.0%}")
for record in report.records:
    if record.overall_verdict.value == "VULNERABLE":
        print(f"  {record.prompt.id}: {record.prompt.description}")
```

Synchronous wrapper:

```python
from bulwark import evaluate_sync

report = evaluate_sync("http://localhost:8000/chat")
```

## OWASP ASI Top 10 Categories

| Code  | Category                 | Default Severity | Description |
|-------|--------------------------|------------------|-------------|
| ASI01 | Prompt Injection         | CRITICAL | Direct or indirect manipulation of agent instructions through crafted input |
| ASI02 | Insecure Output Handling | HIGH     | Failure to sanitize agent outputs before they reach downstream systems |
| ASI03 | Excessive Agency         | HIGH     | Agent exercises more authority than required, including autonomous actions without oversight |
| ASI04 | Resource Management      | MEDIUM   | Improper control of tokens, API calls, memory, or compute leading to exhaustion |
| ASI05 | Tool Use Safety          | CRITICAL | Unsafe invocation of tools, APIs, or plugins including unsanitized parameters |
| ASI06 | Data Privacy             | HIGH     | Unauthorized access, retention, or disclosure of sensitive data or PII |
| ASI07 | Trust Boundaries         | HIGH     | Failure to enforce trust boundaries allowing privilege escalation or cross-boundary data flows |
| ASI08 | Behavioral Drift         | MEDIUM   | Persona manipulation, jailbreaks, or erosion of safety constraints through multi-turn attacks |
| ASI09 | Scope Violations         | HIGH     | Agent operates outside its defined domain, providing unauthorized advice or actions |
| ASI10 | Hallucination            | MEDIUM   | Fabricated citations, fake references, or confabulated information presented as fact |

## Features

- **50 Adversarial Prompts** — 5 per category at Basic, Intermediate, and Advanced sophistication levels
- **8 Pattern Detectors** — Prompt injection, data leakage, jailbreak, excessive agency, scope violation, hallucination, output safety, plus optional LLM-powered semantic analysis
- **4 Agent Adapters** — HTTP, OpenAI-compatible, LangChain, and arbitrary sync/async callables
- **Scoring Engine** — Worst-verdict-wins aggregation with confidence scoring and risk score (0-100)
- **Rich CLI** — Color-coded verdict tables, progress bars, category listings
- **Python SDK** — Async-first `evaluate()` and sync `evaluate_sync()` for CI pipelines
- **HTML Reports** — Self-contained dark-theme reports with summary cards and per-finding details
- **Extensible** — Register custom detectors, add domain-specific prompts

## Configuration

```bash
cp .env.example .env
```

| Variable                 | Description                                        | Required |
|--------------------------|----------------------------------------------------|----------|
| `BULWARK_LLM_ENDPOINT`  | OpenAI-compatible endpoint for semantic detection   | No       |
| `BULWARK_LLM_API_KEY`   | API key for the LLM endpoint                       | No       |
| `BULWARK_DEFAULT_TARGET` | Default agent URL for CLI                          | No       |
| `BULWARK_REPORT_DIR`    | Directory for saved reports                         | No       |

## Architecture

```
bulwark/
  adapters/        — Agent connectors (HTTP, OpenAI, LangChain, callable)
  core/
    categories.py  — OWASP ASI category definitions
    models.py      — Pydantic v2 data models (prompts, results, verdicts, reports)
  detectors/       — One detector per threat type + registry + semantic LLM judge
  prompts/         — Adversarial prompt library (50 prompts, 10 categories)
  reports/         — Report renderers (HTML)
  scoring/         — Scoring engine with verdict aggregation
  cli.py           — Click CLI entry point
  sdk.py           — Public API (evaluate / evaluate_sync)
```

**Flow:** Adapter wraps target agent → Prompts selected by category/sophistication → Each prompt sent to agent via adapter → Response analyzed by registered detectors → Scoring engine aggregates detector results → Report rendered.

## Extending Bulwark

### Custom Detectors

```python
from bulwark.detectors.base import BaseDetector
from bulwark.core.models import AdversarialPrompt, DetectorResult, Verdict, Severity

class MyDetector(BaseDetector):
    name = "my_detector"

    async def detect(self, prompt: AdversarialPrompt, response: str) -> DetectorResult:
        is_bad = "PWNED" in response
        return DetectorResult(
            detector_name=self.name,
            verdict=Verdict.VULNERABLE if is_bad else Verdict.PASS,
            confidence=0.95 if is_bad else 0.1,
            reasoning="Agent followed injection" if is_bad else "Agent refused",
            severity=Severity.CRITICAL,
        )

# Register it
from bulwark.detectors.registry import DetectorRegistry
from bulwark.core.categories import ASICode

registry = DetectorRegistry.get_default()
registry.register(ASICode.ASI01, MyDetector())
```

### Custom Prompts

```python
from bulwark.core.models import AdversarialPrompt, Severity, Sophistication
from bulwark.core.categories import ASICode

my_prompt = AdversarialPrompt(
    id="CUSTOM-001",
    category=ASICode.ASI01,
    severity=Severity.CRITICAL,
    sophistication=Sophistication.ADVANCED,
    prompt_text="Your custom adversarial prompt here",
    description="What this prompt tests",
    expected_behavior="What a safe agent should do",
    tags=["custom", "injection"],
)
```

## Contributing

Contributions welcome:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-detector`)
3. Write tests for new detectors or prompts
4. Run `ruff check bulwark/ tests/` and `pytest -v`
5. Open a pull request

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

## Acknowledgments

- [**safelabs-eval**](https://github.com/AgentSafeLabs/safelabs-eval) by AgentSafeLabs — conceptual inspiration for this project (Apache 2.0)
- [**OWASP Agentic Security Initiative**](https://owasp.org/www-project-agentic-security-initiative/) — threat taxonomy (CC BY-SA 4.0)
