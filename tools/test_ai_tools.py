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
            {"signature": "abc", "path": "/x", "user_agent": "bench"},
            {"signature": "abc", "path": "/x", "user_agent": "bench"},
        ]
        filters = codex_analyzer.deterministic_filters(events, min_count=2, ttl_seconds=45)
        self.assertEqual(len(filters), 1)
        clean = codex_analyzer.sanitize_filter(filters[0], ttl_seconds=45)
        self.assertTrue(clean["adaptive"])
        self.assertEqual(clean["ttl_seconds"], 45)
        self.assertEqual(clean["condition"]["signature"], "abc")
        self.assertEqual(clean["action"]["status"], 403)

    def test_provider_config_merges_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "providers.json"
            path.write_text(json.dumps({"selected_provider": "openrouter", "providers": {"openrouter": {"model": "x/y"}}}))
            cfg = codex_analyzer.load_provider_config(path)
            provider = codex_analyzer.provider_config(cfg, "openrouter")
            self.assertEqual(cfg["selected_provider"], "openrouter")
            self.assertEqual(provider["model"], "x/y")
            self.assertEqual(provider["base_url"], "https://openrouter.ai/api/v1")

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
