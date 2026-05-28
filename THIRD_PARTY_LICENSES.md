# Third-Party Licenses

Bulwark uses the following open-source dependencies. All licenses are
permissive and compatible with the Apache License 2.0 under which
Bulwark is distributed.

## Runtime Dependencies

### pydantic (>=2.0)
- **License:** MIT
- **Copyright:** Samuel Colvin and contributors
- **Source:** https://github.com/pydantic/pydantic
- **Usage:** Data validation and serialization for all core models

### httpx (>=0.25)
- **License:** BSD 3-Clause
- **Copyright:** Encode OSS Ltd.
- **Source:** https://github.com/encode/httpx
- **Usage:** Async HTTP client for agent adapters and LLM calls

### click (>=8.0)
- **License:** BSD 3-Clause
- **Copyright:** Pallets Projects
- **Source:** https://github.com/pallets/click
- **Usage:** CLI framework

### rich (>=13.0)
- **License:** MIT
- **Copyright:** Will McGugan
- **Source:** https://github.com/Textualize/rich
- **Usage:** Terminal output formatting and progress display

## Optional Dependencies

### langchain-core
- **License:** MIT
- **Copyright:** LangChain, Inc.
- **Source:** https://github.com/langchain-ai/langchain
- **Usage:** Optional adapter for evaluating LangChain agents

## Development Dependencies

### pytest
- **License:** MIT
- **Copyright:** Holger Krekel and contributors
- **Source:** https://github.com/pytest-dev/pytest

### pytest-asyncio
- **License:** Apache 2.0
- **Copyright:** pytest-asyncio contributors
- **Source:** https://github.com/pytest-dev/pytest-asyncio

### ruff
- **License:** MIT
- **Copyright:** Astral Software Inc.
- **Source:** https://github.com/astral-sh/ruff

## Standards Referenced

### OWASP Agentic Security Initiative (ASI) Top 10
- **License:** Creative Commons Attribution-ShareAlike 4.0
- **Source:** https://owasp.org/
- **Usage:** Category taxonomy for adversarial prompts. The ASI Top 10
  category names and descriptions are used under CC BY-SA 4.0 terms.

## Conceptual Inspiration

### safelabs-eval
- **License:** Apache 2.0
- **Copyright:** 2026 AgentSafeLabs (Waqar Javed)
- **Source:** https://github.com/AgentSafeLabs/safelabs-eval
- **Note:** No source code was copied. Bulwark was built from scratch
  with original code, drawing on the same OWASP ASI public standard.
