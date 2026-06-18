#!/usr/bin/env python3
"""Generate constrained adaptive filters from AlturaProt attack events.

The preferred path uses the OpenAI Codex SDK. If the SDK or local Codex runtime
is unavailable, this script falls back to deterministic signature grouping.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SAFE_ID = re.compile(r"[^a-zA-Z0-9_.:-]+")

DEFAULT_PROVIDER_CONFIG = {
    "selected_provider": "codex",
    "providers": {
        "codex": {"model": "gpt-5.4"},
        "openai": {
            "model": "gpt-5.5",
            "api_key_env": "OPENAI_API_KEY",
            "base_url": "https://api.openai.com/v1",
        },
        "anthropic": {
            "model": "claude-sonnet-4-6",
            "api_key_env": "ANTHROPIC_API_KEY",
            "base_url": "https://api.anthropic.com/v1",
            "anthropic_version": "2023-06-01",
        },
        "openrouter": {
            "model": "~openai/gpt-latest",
            "api_key_env": "OPENROUTER_API_KEY",
            "base_url": "https://openrouter.ai/api/v1",
            "app_title": "AlturaProt",
        },
    },
}

SYSTEM_PROMPT = """You convert defensive HTTP flood telemetry into safe AlturaProt filter rules.
Return JSON only. Prefer narrow signature-based adaptive filters. Do not generate commands,
code execution, network instructions, broad IP blocks, or always-on catch-all filters."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", default="runtime/attack_events.jsonl")
    parser.add_argument("--filters", default="runtime/filters.json")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--min-count", type=int, default=1)
    parser.add_argument("--ttl-seconds", type=int, default=60)
    parser.add_argument("--max-events", type=int, default=200)
    parser.add_argument("--no-codex", action="store_true")
    parser.add_argument("--provider", choices=["auto", "codex", "openai", "anthropic", "openrouter"], default="auto")
    parser.add_argument("--provider-config", default=str(default_provider_config_path()))
    parser.add_argument("--model", default=None)
    return parser.parse_args()


def read_events(path: Path, max_events: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    events: list[dict[str, Any]] = []
    for line in lines[-max_events:]:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and isinstance(event.get("signature"), str):
            events.append(event)
    return events


def deterministic_filters(events: list[dict[str, Any]], min_count: int, ttl_seconds: int) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for event in events:
        grouped[event["signature"]].append(event)

    filters = []
    for signature, group in sorted(grouped.items(), key=lambda item: len(item[1]), reverse=True):
        if len(group) < min_count:
            continue
        sample = group[-1]
        filters.append(
            {
                "id": safe_id(f"codex-learned-{signature}"),
                "enabled": True,
                "adaptive": True,
                "priority": 100,
                "ttl_seconds": ttl_seconds,
                "condition": {
                    "signature": signature,
                },
                "action": {
                    "kind": "block",
                    "status": 403,
                    "body": "blocked by adaptive filter\n",
                },
                "metadata": {
                    "source": "deterministic-fallback",
                    "sample_path": sample.get("path"),
                    "sample_user_agent": sample.get("user_agent"),
                    "event_count": len(group),
                },
            }
        )
    return filters


def build_prompt(events: list[dict[str, Any]], min_count: int, ttl_seconds: int) -> dict[str, Any]:
    return {
        "task": "Analyze these AlturaProt HTTP attack events and propose defensive adaptive filters.",
        "rules": [
            "Output JSON only.",
            "Use only this schema: {\"filters\":[FilterRule...]}",
            "FilterRule fields: id, enabled, adaptive, priority, ttl_seconds, condition, action.",
            "condition may only contain signature, methods, path_exact, path_prefix, path_contains, query_contains, user_agent_contains, headers.",
            "action must be {\"kind\":\"block\",\"status\":403,\"body\":\"blocked by adaptive filter\\n\"}.",
            "Prefer signature conditions. Add path/user-agent conditions only when they are obvious and reduce false positives.",
            "Do not suggest shell commands, code execution, network calls, broad always-on blocks, or always-active rules.",
        ],
        "min_count": min_count,
        "ttl_seconds": ttl_seconds,
        "events": events,
    }


def codex_filters(prompt: dict[str, Any], provider_cfg: dict[str, Any], ttl_seconds: int) -> list[dict[str, Any]]:
    from openai_codex import Codex, Sandbox  # type: ignore

    with Codex() as codex:
        thread = codex.thread_start(model=provider_cfg.get("model"), sandbox=Sandbox.read_only)
        result = thread.run(json.dumps(prompt, separators=(",", ":")))
    parsed = extract_json(result.final_response)
    filters = parsed.get("filters", []) if isinstance(parsed, dict) else []
    return [sanitize_filter(item, ttl_seconds) for item in filters if isinstance(item, dict)]


def openai_filters(prompt: dict[str, Any], provider_cfg: dict[str, Any], ttl_seconds: int) -> list[dict[str, Any]]:
    api_key = provider_api_key("openai", provider_cfg)
    base_url = provider_cfg.get("base_url", DEFAULT_PROVIDER_CONFIG["providers"]["openai"]["base_url"]).rstrip("/")
    payload = {
        "model": provider_cfg.get("model", DEFAULT_PROVIDER_CONFIG["providers"]["openai"]["model"]),
        "input": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(prompt, separators=(",", ":"))},
        ],
        "store": False,
    }
    data = post_json(
        f"{base_url}/responses",
        {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        payload,
    )
    parsed = extract_json(response_text_from_openai(data))
    filters = parsed.get("filters", []) if isinstance(parsed, dict) else []
    return [sanitize_filter(item, ttl_seconds) for item in filters if isinstance(item, dict)]


def anthropic_filters(prompt: dict[str, Any], provider_cfg: dict[str, Any], ttl_seconds: int) -> list[dict[str, Any]]:
    api_key = provider_api_key("anthropic", provider_cfg)
    base_url = provider_cfg.get("base_url", DEFAULT_PROVIDER_CONFIG["providers"]["anthropic"]["base_url"]).rstrip("/")
    payload = {
        "model": provider_cfg.get("model", DEFAULT_PROVIDER_CONFIG["providers"]["anthropic"]["model"]),
        "max_tokens": int(provider_cfg.get("max_tokens", 2048)),
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": json.dumps(prompt, separators=(",", ":"))}],
    }
    data = post_json(
        f"{base_url}/messages",
        {
            "x-api-key": api_key,
            "anthropic-version": provider_cfg.get("anthropic_version", "2023-06-01"),
            "Content-Type": "application/json",
        },
        payload,
    )
    parsed = extract_json(response_text_from_anthropic(data))
    filters = parsed.get("filters", []) if isinstance(parsed, dict) else []
    return [sanitize_filter(item, ttl_seconds) for item in filters if isinstance(item, dict)]


def openrouter_filters(prompt: dict[str, Any], provider_cfg: dict[str, Any], ttl_seconds: int) -> list[dict[str, Any]]:
    api_key = provider_api_key("openrouter", provider_cfg)
    base_url = provider_cfg.get("base_url", DEFAULT_PROVIDER_CONFIG["providers"]["openrouter"]["base_url"]).rstrip("/")
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    if app_title := provider_cfg.get("app_title"):
        headers["X-OpenRouter-Title"] = str(app_title)
    if referer := provider_cfg.get("http_referer"):
        headers["HTTP-Referer"] = str(referer)
    payload = {
        "model": provider_cfg.get("model", DEFAULT_PROVIDER_CONFIG["providers"]["openrouter"]["model"]),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(prompt, separators=(",", ":"))},
        ],
    }
    data = post_json(f"{base_url}/chat/completions", headers, payload)
    parsed = extract_json(response_text_from_chat_completion(data))
    filters = parsed.get("filters", []) if isinstance(parsed, dict) else []
    return [sanitize_filter(item, ttl_seconds) for item in filters if isinstance(item, dict)]


def run_provider(provider: str, prompt: dict[str, Any], provider_cfg: dict[str, Any], ttl_seconds: int) -> list[dict[str, Any]]:
    if provider == "codex":
        return codex_filters(prompt, provider_cfg, ttl_seconds)
    if provider == "openai":
        return openai_filters(prompt, provider_cfg, ttl_seconds)
    if provider == "anthropic":
        return anthropic_filters(prompt, provider_cfg, ttl_seconds)
    if provider == "openrouter":
        return openrouter_filters(prompt, provider_cfg, ttl_seconds)
    raise ValueError(f"unsupported provider: {provider}")


def post_json(url: str, headers: dict[str, str], payload: dict[str, Any], timeout: float = 60.0) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{url} returned HTTP {exc.code}: {body[:500]}") from exc


def response_text_from_openai(data: dict[str, Any]) -> str:
    if isinstance(data.get("output_text"), str):
        return data["output_text"]
    texts: list[str] = []
    for item in data.get("output", []) if isinstance(data.get("output"), list) else []:
        for content in item.get("content", []) if isinstance(item, dict) else []:
            if isinstance(content, dict):
                text = content.get("text") or content.get("content")
                if isinstance(text, str):
                    texts.append(text)
    return "\n".join(texts)


def response_text_from_anthropic(data: dict[str, Any]) -> str:
    texts: list[str] = []
    for item in data.get("content", []) if isinstance(data.get("content"), list) else []:
        if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
            texts.append(item["text"])
    return "\n".join(texts)


def response_text_from_chat_completion(data: dict[str, Any]) -> str:
    choices = data.get("choices", [])
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
    content = message.get("content") if isinstance(message, dict) else ""
    return content if isinstance(content, str) else ""


def default_provider_config_path() -> Path:
    return Path(os.environ.get("ALTURA_PROT_PROVIDER_CONFIG", Path.home() / ".config" / "altura-prot" / "providers.json"))


def default_provider_secrets_path() -> Path:
    return Path(os.environ.get("ALTURA_PROT_PROVIDER_SECRETS", Path.home() / ".config" / "altura-prot" / "secrets.json"))


def load_provider_config(path: Path | str | None = None) -> dict[str, Any]:
    path = Path(path) if path else default_provider_config_path()
    config = json.loads(json.dumps(DEFAULT_PROVIDER_CONFIG))
    if path.exists():
        user_config = json.loads(path.read_text(encoding="utf-8"))
        deep_merge(config, user_config)
    return config


def write_provider_config(config: dict[str, Any], path: Path | str | None = None) -> None:
    path = Path(path) if path else default_provider_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def load_provider_secrets(path: Path | str | None = None) -> dict[str, Any]:
    path = Path(path) if path else default_provider_secrets_path()
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_provider_secrets(secrets: dict[str, Any], path: Path | str | None = None) -> None:
    path = Path(path) if path else default_provider_secrets_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(secrets, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value


def resolve_provider(args: argparse.Namespace, config: dict[str, Any]) -> str:
    provider = args.provider
    if provider == "auto":
        provider = str(config.get("selected_provider") or "codex")
    if provider not in DEFAULT_PROVIDER_CONFIG["providers"]:
        raise ValueError(f"unsupported provider: {provider}")
    return provider


def provider_config(config: dict[str, Any], provider: str, model_override: str | None = None) -> dict[str, Any]:
    providers = config.setdefault("providers", {})
    merged = json.loads(json.dumps(DEFAULT_PROVIDER_CONFIG["providers"][provider]))
    if isinstance(providers.get(provider), dict):
        deep_merge(merged, providers[provider])
    if model_override:
        merged["model"] = model_override
    return merged


def provider_api_key(provider: str, provider_cfg: dict[str, Any]) -> str:
    env_name = str(provider_cfg.get("api_key_env") or "").strip()
    if env_name and os.environ.get(env_name):
        return os.environ[env_name]
    secrets = load_provider_secrets()
    value = secrets.get(provider, {}).get("api_key") if isinstance(secrets.get(provider), dict) else None
    if isinstance(value, str) and value:
        return value
    raise RuntimeError(
        f"missing API key for {provider}; set {env_name or provider.upper() + '_API_KEY'} or run tools/ai_provider_cli.py login"
    )


def extract_json(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).strip()
        text = re.sub(r"```$", "", text).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        text = text[start : end + 1]
    return json.loads(text)


def sanitize_filter(item: dict[str, Any], ttl_seconds: int) -> dict[str, Any]:
    condition = item.get("condition") if isinstance(item.get("condition"), dict) else {}
    clean_condition: dict[str, Any] = {}
    for key in [
        "signature",
        "path_exact",
        "path_prefix",
        "path_contains",
        "query_contains",
        "user_agent_contains",
    ]:
        value = condition.get(key)
        if isinstance(value, str) and len(value) <= 512:
            clean_condition[key] = value
    methods = condition.get("methods")
    if isinstance(methods, list):
        clean_condition["methods"] = [
            str(method).upper() for method in methods if str(method).upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        ][:8]
    headers = condition.get("headers")
    if isinstance(headers, list):
        clean_headers = []
        for header in headers[:8]:
            if not isinstance(header, dict):
                continue
            name = str(header.get("name", ""))[:64]
            contains = str(header.get("contains", ""))[:256]
            if name and contains:
                clean_headers.append({"name": name, "contains": contains})
        if clean_headers:
            clean_condition["headers"] = clean_headers

    signature = clean_condition.get("signature", "custom")
    return {
        "id": safe_id(str(item.get("id") or f"codex-learned-{signature}")),
        "enabled": bool(item.get("enabled", True)),
        "adaptive": True,
        "priority": int(item.get("priority", 100)),
        "ttl_seconds": int(item.get("ttl_seconds", ttl_seconds)) or ttl_seconds,
        "condition": clean_condition,
        "action": {
            "kind": "block",
            "status": 403,
            "body": "blocked by adaptive filter\n",
        },
    }


def safe_id(value: str) -> str:
    return SAFE_ID.sub("-", value)[:96].strip("-") or "codex-learned-filter"


def write_filters(path: Path, filters: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"filters": filters}
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
        json.dump(payload, tmp, indent=2, sort_keys=True)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def analyze_once(args: argparse.Namespace) -> None:
    events = read_events(Path(args.events), args.max_events)
    if not events:
        write_filters(Path(args.filters), [])
        print("no attack events found")
        return
    filters: list[dict[str, Any]]
    prompt = build_prompt(events, args.min_count, args.ttl_seconds)
    config = load_provider_config(args.provider_config)
    provider = resolve_provider(args, config)
    cfg = provider_config(config, provider, args.model)
    used_provider = provider
    if args.no_codex:
        filters = deterministic_filters(events, args.min_count, args.ttl_seconds)
        used_provider = "deterministic"
    else:
        try:
            filters = run_provider(provider, prompt, cfg, args.ttl_seconds)
        except Exception as exc:
            print(f"{provider} analyzer unavailable, using deterministic fallback: {exc}")
            filters = deterministic_filters(events, args.min_count, args.ttl_seconds)
            used_provider = "deterministic-fallback"
    filters = [sanitize_filter(item, args.ttl_seconds) for item in filters]
    write_filters(Path(args.filters), filters)
    print(f"wrote {len(filters)} filters to {args.filters} via {used_provider}")


def main() -> None:
    args = parse_args()
    while True:
        analyze_once(args)
        if args.once:
            return
        time.sleep(max(1.0, args.interval))


if __name__ == "__main__":
    main()
