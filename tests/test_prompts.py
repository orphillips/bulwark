"""Tests for the PromptLibrary."""

import pytest

from bulwark.core.categories import ASICode
from bulwark.core.models import AdversarialPrompt, Severity, Sophistication
from bulwark.prompts.library import PromptLibrary


class TestPromptLibraryAll:
    def test_returns_50_prompts(self):
        prompts = PromptLibrary.all()
        assert len(prompts) == 50

    def test_returns_list_of_adversarial_prompts(self):
        prompts = PromptLibrary.all()
        assert all(isinstance(p, AdversarialPrompt) for p in prompts)

    def test_returns_fresh_copy(self):
        """Mutating returned list should not affect internal state."""
        p1 = PromptLibrary.all()
        p1.clear()
        p2 = PromptLibrary.all()
        assert len(p2) == 50

    def test_all_prompts_have_nonempty_text(self):
        for p in PromptLibrary.all():
            assert p.prompt_text.strip(), f"Prompt {p.id} has empty text"

    def test_all_prompts_have_valid_category(self):
        for p in PromptLibrary.all():
            assert isinstance(p.category, ASICode), f"Prompt {p.id} has invalid category"

    def test_all_prompts_have_valid_severity(self):
        for p in PromptLibrary.all():
            assert isinstance(p.severity, Severity), f"Prompt {p.id} has invalid severity"

    def test_all_prompts_have_valid_sophistication(self):
        for p in PromptLibrary.all():
            assert isinstance(p.sophistication, Sophistication), (
                f"Prompt {p.id} has invalid sophistication"
            )

    def test_all_prompts_have_unique_ids(self):
        ids = [p.id for p in PromptLibrary.all()]
        assert len(ids) == len(set(ids)), "Duplicate prompt IDs found"

    def test_all_prompts_have_description(self):
        for p in PromptLibrary.all():
            assert p.description, f"Prompt {p.id} has empty description"

    def test_all_prompts_have_expected_behavior(self):
        for p in PromptLibrary.all():
            assert p.expected_behavior, f"Prompt {p.id} has empty expected_behavior"

    def test_all_prompts_have_tags(self):
        for p in PromptLibrary.all():
            assert len(p.tags) > 0, f"Prompt {p.id} has no tags"


class TestPromptLibraryByCategory:
    def test_all_10_categories_have_prompts(self):
        for code in ASICode:
            prompts = PromptLibrary.by_category(code)
            assert len(prompts) > 0, f"No prompts for category {code.value}"

    def test_5_prompts_per_category(self):
        for code in ASICode:
            prompts = PromptLibrary.by_category(code)
            assert len(prompts) == 5, (
                f"Expected 5 prompts for {code.value}, got {len(prompts)}"
            )

    def test_category_filter_correctness(self):
        for code in ASICode:
            prompts = PromptLibrary.by_category(code)
            assert all(p.category == code for p in prompts)

    def test_by_category_string(self):
        prompts = PromptLibrary.by_category("ASI01")
        assert len(prompts) == 5
        assert all(p.category == ASICode.ASI01 for p in prompts)

    def test_by_category_enum(self):
        prompts = PromptLibrary.by_category(ASICode.ASI06)
        assert len(prompts) == 5
        assert all(p.category == ASICode.ASI06 for p in prompts)

    def test_invalid_category_raises(self):
        with pytest.raises(ValueError):
            PromptLibrary.by_category("ASI99")

    def test_category_counts_sum_to_total(self):
        total = sum(len(PromptLibrary.by_category(c)) for c in ASICode)
        assert total == 50


class TestPromptLibraryBySophistication:
    def test_basic_prompts(self):
        prompts = PromptLibrary.by_sophistication(Sophistication.BASIC)
        assert len(prompts) > 0
        assert all(p.sophistication == Sophistication.BASIC for p in prompts)

    def test_intermediate_prompts(self):
        prompts = PromptLibrary.by_sophistication(Sophistication.INTERMEDIATE)
        assert len(prompts) > 0
        assert all(p.sophistication == Sophistication.INTERMEDIATE for p in prompts)

    def test_advanced_prompts(self):
        prompts = PromptLibrary.by_sophistication(Sophistication.ADVANCED)
        assert len(prompts) > 0
        assert all(p.sophistication == Sophistication.ADVANCED for p in prompts)

    def test_by_sophistication_string(self):
        prompts = PromptLibrary.by_sophistication("BASIC")
        assert len(prompts) > 0
        assert all(p.sophistication == Sophistication.BASIC for p in prompts)

    def test_by_sophistication_string_lowercase(self):
        prompts = PromptLibrary.by_sophistication("basic")
        assert len(prompts) > 0

    def test_invalid_sophistication_raises(self):
        with pytest.raises(ValueError):
            PromptLibrary.by_sophistication("EXPERT")

    def test_all_sophistication_levels_present(self):
        for level in Sophistication:
            prompts = PromptLibrary.by_sophistication(level)
            assert len(prompts) > 0, f"No prompts at {level.value} level"

    def test_sophistication_counts_sum_to_total(self):
        total = sum(
            len(PromptLibrary.by_sophistication(s)) for s in Sophistication
        )
        assert total == 50

    def test_distribution_per_category(self):
        """Each category should have prompts at each sophistication level."""
        for code in ASICode:
            cat_prompts = PromptLibrary.by_category(code)
            levels = {p.sophistication for p in cat_prompts}
            assert Sophistication.BASIC in levels, (
                f"{code.value} missing BASIC prompts"
            )
            assert Sophistication.INTERMEDIATE in levels, (
                f"{code.value} missing INTERMEDIATE prompts"
            )
            assert Sophistication.ADVANCED in levels, (
                f"{code.value} missing ADVANCED prompts"
            )


class TestPromptStructure:
    def test_id_format(self):
        """IDs should follow the ASIXX-L## pattern."""
        for p in PromptLibrary.all():
            assert p.id.startswith("ASI"), f"Prompt {p.id} has non-ASI prefix"
            parts = p.id.split("-")
            assert len(parts) == 2, f"Prompt {p.id} has unexpected format"
            assert parts[1][0] in ("B", "I", "A"), (
                f"Prompt {p.id} sophistication code not B/I/A"
            )

    def test_severity_matches_expectations(self):
        """CRITICAL-severity prompts should be in high-risk categories."""
        for p in PromptLibrary.all():
            if p.severity == Severity.CRITICAL:
                # CRITICAL prompts belong in categories typically rated high
                assert p.category in (
                    ASICode.ASI01,
                    ASICode.ASI03,
                    ASICode.ASI05,
                    ASICode.ASI06,
                    ASICode.ASI07,
                    ASICode.ASI08,
                    ASICode.ASI09,
                ), f"Prompt {p.id} is CRITICAL in unexpected category {p.category.value}"
