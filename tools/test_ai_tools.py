#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import codex_analyzer


class AnalyzerTests(unittest.TestCase):
    def test_deterministic_filters_are_adaptive_signature_rules(self) -> None:
        events = [
            {"signature": "abc", "path": "/x", "user_agent": "bench", "reason": "per_ip_rate_limited"},
            {"signature": "abc", "path": "/x", "user_agent": "bench", "reason": "per_ip_rate_limited"},
        ]
        filters = codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45)
        self.assertEqual(len(filters), 1)
        clean = codex_analyzer.sanitize_filter(filters[0], ttl_seconds=45)
        self.assertTrue(clean["adaptive"])
        self.assertEqual(clean["ttl_seconds"], 45)
        self.assertEqual(clean["condition"]["signature"], "abc")
        self.assertEqual(clean["action"]["status"], 403)

    def test_observed_only_events_do_not_learn_by_default(self) -> None:
        events = [
            {"signature": "abc", "path": "/x", "user_agent": "bench", "reason": "observed"},
            {"signature": "abc", "path": "/x", "user_agent": "bench", "reason": "observed"},
        ]
        self.assertEqual(codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45), [])
        self.assertEqual(
            len(codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45, learn_observed=True)),
            1,
        )

    def test_merge_strong_coverage_adds_missing_signatures(self) -> None:
        events = [
            {"signature": "covered", "path": "/a", "user_agent": "bench", "reason": "per_ip_rate_limited"},
            {"signature": "missing", "path": "/b", "user_agent": "bench", "reason": "per_ip_rate_limited"},
        ]
        provider_filters = [
            {
                "id": "provider-covered",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "covered"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        merged = codex_analyzer.merge_strong_coverage(provider_filters, events, min_count=1, ttl_seconds=20)
        signatures = {item["condition"]["signature"] for item in merged}
        self.assertEqual(signatures, {"covered", "missing"})

    def test_merge_existing_filters_preserves_dormant_rules(self) -> None:
        existing = [
            {
                "id": "old",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "oldsig"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        new = [
            {
                "id": "new",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "newsig"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        merged = codex_analyzer.merge_existing_filters(existing, new, ttl_seconds=20, max_filters=10)
        self.assertEqual({item["condition"]["signature"] for item in merged}, {"oldsig", "newsig"})

    def test_merge_existing_filters_replaces_same_signature(self) -> None:
        existing = [
            {
                "id": "old",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "same"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        new = [
            {
                "id": "new",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "same"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        merged = codex_analyzer.merge_existing_filters(existing, new, ttl_seconds=20, max_filters=10)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["id"], "new")

    def test_merge_existing_filters_cap_prefers_new_rules(self) -> None:
        existing = [
            {
                "id": f"old-{idx}",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": f"old-{idx}"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
            for idx in range(3)
        ]
        new = [
            {
                "id": "new",
                "enabled": True,
                "adaptive": True,
                "condition": {"signature": "new"},
                "action": {"kind": "block", "status": 403, "body": "blocked by adaptive filter\n"},
            }
        ]
        merged = codex_analyzer.merge_existing_filters(existing, new, ttl_seconds=20, max_filters=3)
        self.assertEqual(len(merged), 3)
        self.assertIn("new", {item["condition"]["signature"] for item in merged})

    def test_provider_config_merges_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "providers.json"
            path.write_text(json.dumps({"selected_provider": "openrouter", "providers": {"openrouter": {"model": "x/y"}}}))
            cfg = codex_analyzer.load_provider_config(path)
            provider = codex_analyzer.provider_config(cfg, "openrouter")
            self.assertEqual(cfg["selected_provider"], "openrouter")
            self.assertEqual(provider["model"], "x/y")
            self.assertEqual(provider["base_url"], "https://openrouter.ai/api/v1")

    def test_codex_defaults_are_gpt55_high_fast(self) -> None:
        cfg = codex_analyzer.load_provider_config(Path("/tmp/nonexistent-altura-provider-config.json"))
        provider = codex_analyzer.provider_config(cfg, "codex")
        self.assertEqual(provider["model"], "gpt-5.5")
        self.assertEqual(provider["reasoning_effort"], "high")
        self.assertEqual(provider["service_tier"], "fast")

    def test_api_key_prefers_environment(self) -> None:
        old = os.environ.get("ALTURA_TEST_KEY")
        os.environ["ALTURA_TEST_KEY"] = "from-env"
        try:
            self.assertEqual(
                codex_analyzer.provider_api_key("openai", {"api_key_env": "ALTURA_TEST_KEY"}),
                "from-env",
            )
        finally:
            if old is None:
                os.environ.pop("ALTURA_TEST_KEY", None)
            else:
                os.environ["ALTURA_TEST_KEY"] = old


if __name__ == "__main__":
    unittest.main()
