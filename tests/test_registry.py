"""Tests for the DetectorRegistry."""

import pytest

from bulwark.core.categories import ASICode
from bulwark.core.models import (
    AdversarialPrompt,
    DetectorResult,
    Severity,
    Verdict,
)
from bulwark.detectors.base import BaseDetector
from bulwark.detectors.registry import DetectorRegistry


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


class DummyDetector(BaseDetector):
    def __init__(self, name: str):
        self.name = name

    async def detect(self, prompt, response):
        return DetectorResult(
            detector_name=self.name,
            verdict=Verdict.PASS,
            confidence=0.5,
        )


class ExplodingDetector(BaseDetector):
    name = "exploding"

    async def detect(self, prompt, response):
        raise ValueError("Boom!")


@pytest.fixture
def sample_prompt():
    return AdversarialPrompt(
        id="reg-test",
        category=ASICode.ASI01,
        severity=Severity.CRITICAL,
        prompt_text="Test prompt.",
    )


# =========================================================================== #
# Basic registry operations
# =========================================================================== #


class TestRegistryBasics:
    def test_empty_registry(self):
        registry = DetectorRegistry()
        assert registry.categories == []
        assert registry.all_detectors == []

    def test_register_and_get(self):
        registry = DetectorRegistry()
        d = DummyDetector("d1")
        registry.register(ASICode.ASI01, d)
        detectors = registry.get(ASICode.ASI01)
        assert len(detectors) == 1
        assert detectors[0].name == "d1"

    def test_get_detectors_alias(self):
        registry = DetectorRegistry()
        d = DummyDetector("d1")
        registry.register(ASICode.ASI01, d)
        assert registry.get(ASICode.ASI01) == registry.get_detectors(ASICode.ASI01)

    def test_get_empty_category(self):
        registry = DetectorRegistry()
        assert registry.get(ASICode.ASI01) == []

    def test_register_same_detector_twice_ignored(self):
        registry = DetectorRegistry()
        d = DummyDetector("d1")
        registry.register(ASICode.ASI01, d)
        registry.register(ASICode.ASI01, d)
        assert len(registry.get(ASICode.ASI01)) == 1

    def test_register_different_detectors_same_category(self):
        registry = DetectorRegistry()
        d1 = DummyDetector("d1")
        d2 = DummyDetector("d2")
        registry.register(ASICode.ASI01, d1)
        registry.register(ASICode.ASI01, d2)
        detectors = registry.get(ASICode.ASI01)
        assert len(detectors) == 2

    def test_register_same_detector_multiple_categories(self):
        registry = DetectorRegistry()
        d = DummyDetector("shared")
        registry.register(ASICode.ASI01, d)
        registry.register(ASICode.ASI02, d)
        assert len(registry.get(ASICode.ASI01)) == 1
        assert len(registry.get(ASICode.ASI02)) == 1

    def test_categories_sorted(self):
        registry = DetectorRegistry()
        registry.register(ASICode.ASI05, DummyDetector("d5"))
        registry.register(ASICode.ASI01, DummyDetector("d1"))
        registry.register(ASICode.ASI03, DummyDetector("d3"))
        assert registry.categories == [ASICode.ASI01, ASICode.ASI03, ASICode.ASI05]

    def test_all_detectors_deduplicated(self):
        registry = DetectorRegistry()
        d = DummyDetector("shared")
        registry.register(ASICode.ASI01, d)
        registry.register(ASICode.ASI02, d)
        registry.register(ASICode.ASI03, d)
        assert len(registry.all_detectors) == 1

    def test_all_detectors_unique(self):
        registry = DetectorRegistry()
        d1 = DummyDetector("d1")
        d2 = DummyDetector("d2")
        d3 = DummyDetector("d3")
        registry.register(ASICode.ASI01, d1)
        registry.register(ASICode.ASI02, d2)
        registry.register(ASICode.ASI03, d3)
        all_d = registry.all_detectors
        assert len(all_d) == 3
        names = {d.name for d in all_d}
        assert names == {"d1", "d2", "d3"}

    def test_get_returns_copy(self):
        """Mutating the returned list should not affect the registry."""
        registry = DetectorRegistry()
        d = DummyDetector("d1")
        registry.register(ASICode.ASI01, d)
        detectors = registry.get(ASICode.ASI01)
        detectors.clear()
        assert len(registry.get(ASICode.ASI01)) == 1


# =========================================================================== #
# detect_all
# =========================================================================== #


class TestDetectAll:
    async def test_detect_all_no_detectors(self, sample_prompt):
        registry = DetectorRegistry()
        results = await registry.detect_all(sample_prompt, "response")
        assert len(results) == 1
        assert results[0].verdict == Verdict.UNCERTAIN
        assert results[0].detector_name == "registry"
        assert "No detectors" in results[0].reasoning

    async def test_detect_all_single_detector(self, sample_prompt):
        registry = DetectorRegistry()
        registry.register(ASICode.ASI01, DummyDetector("d1"))
        results = await registry.detect_all(sample_prompt, "response")
        assert len(results) == 1
        assert results[0].verdict == Verdict.PASS

    async def test_detect_all_multiple_detectors(self, sample_prompt):
        registry = DetectorRegistry()
        registry.register(ASICode.ASI01, DummyDetector("d1"))
        registry.register(ASICode.ASI01, DummyDetector("d2"))
        results = await registry.detect_all(sample_prompt, "response")
        assert len(results) == 2

    async def test_detect_all_error_handling(self, sample_prompt):
        registry = DetectorRegistry()
        registry.register(ASICode.ASI01, ExplodingDetector())
        results = await registry.detect_all(sample_prompt, "response")
        assert len(results) == 1
        assert results[0].verdict == Verdict.ERROR
        assert "ValueError" in results[0].reasoning

    async def test_detect_all_mixed_success_and_error(self, sample_prompt):
        registry = DetectorRegistry()
        registry.register(ASICode.ASI01, DummyDetector("good"))
        registry.register(ASICode.ASI01, ExplodingDetector())
        results = await registry.detect_all(sample_prompt, "response")
        assert len(results) == 2
        verdicts = {r.verdict for r in results}
        assert Verdict.PASS in verdicts
        assert Verdict.ERROR in verdicts


# =========================================================================== #
# Default registry coverage
# =========================================================================== #


class TestDefaultRegistry:
    def test_default_registry_covers_all_categories(self):
        registry = DetectorRegistry.get_default()
        for code in ASICode:
            detectors = registry.get(code)
            assert len(detectors) >= 1, f"No detectors for {code.value}"

    def test_default_registry_category_mapping(self):
        registry = DetectorRegistry.get_default()
        # ASI01 -> prompt_injection
        names = [d.name for d in registry.get(ASICode.ASI01)]
        assert "prompt_injection" in names

        # ASI02 -> output_safety
        names = [d.name for d in registry.get(ASICode.ASI02)]
        assert "output_safety" in names

        # ASI03 -> excessive_agency
        names = [d.name for d in registry.get(ASICode.ASI03)]
        assert "excessive_agency" in names

        # ASI06 -> data_leakage
        names = [d.name for d in registry.get(ASICode.ASI06)]
        assert "data_leakage" in names

        # ASI08 -> jailbreak
        names = [d.name for d in registry.get(ASICode.ASI08)]
        assert "jailbreak" in names

        # ASI09 -> scope_violation
        names = [d.name for d in registry.get(ASICode.ASI09)]
        assert "scope_violation" in names

        # ASI10 -> hallucination
        names = [d.name for d in registry.get(ASICode.ASI10)]
        assert "hallucination" in names

    def test_default_registry_multi_detector_categories(self):
        registry = DetectorRegistry.get_default()

        # ASI05 has both excessive_agency and output_safety
        names = [d.name for d in registry.get(ASICode.ASI05)]
        assert "excessive_agency" in names
        assert "output_safety" in names

        # ASI07 has data_leakage and prompt_injection
        names = [d.name for d in registry.get(ASICode.ASI07)]
        assert "data_leakage" in names
        assert "prompt_injection" in names

    def test_default_registry_no_semantic_without_endpoint(self):
        registry = DetectorRegistry.get_default()
        for code in ASICode:
            names = [d.name for d in registry.get(code)]
            assert "semantic" not in names

    def test_default_registry_semantic_with_endpoint(self):
        registry = DetectorRegistry.get_default(
            llm_endpoint="https://api.example.com/v1/chat/completions",
            llm_api_key="test-key",
        )
        # Semantic should be on every category when endpoint is set
        for code in ASICode:
            names = [d.name for d in registry.get(code)]
            assert "semantic" in names, f"semantic missing from {code.value}"

    def test_default_registry_detector_count(self):
        registry = DetectorRegistry.get_default()
        all_d = registry.all_detectors
        # 8 unique built-in detectors (no semantic without endpoint)
        assert len(all_d) == 7  # prompt_injection, output_safety, excessive_agency,
        # data_leakage, jailbreak, scope_violation, hallucination
        # (semantic is created but not registered without llm_endpoint)

    def test_default_registry_with_semantic_adds_one_more(self):
        registry = DetectorRegistry.get_default(
            llm_endpoint="https://api.example.com",
            llm_api_key="key",
        )
        all_d = registry.all_detectors
        assert len(all_d) == 8
