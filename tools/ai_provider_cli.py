#!/usr/bin/env python3
"""Interactive CLI provider setup for AlturaProt/CodexSDGate."""

from __future__ import annotations

import argparse
import getpass
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from codex_analyzer import (
    DEFAULT_PROVIDER_CONFIG,
    default_provider_config_path,
    default_provider_secrets_path,
    load_provider_config,
    load_provider_secrets,
    provider_config,
    write_provider_config,
    write_provider_secrets,
)


PROVIDERS = ["codex", "openai", "anthropic", "openrouter"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Configure AI providers for AlturaProt CodexSDGate.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Show selected provider and redacted credential status.")
    login = sub.add_parser("login", help="Interactively configure a provider.")
    login.add_argument("provider", nargs="?", choices=PROVIDERS)
    select = sub.add_parser("select", help="Select active provider.")
    select.add_argument("provider", choices=PROVIDERS)
    sub.add_parser("init", help="Create default provider config if missing.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "init":
        init_config()
    elif args.command == "status":
        show_status()
    elif args.command == "select":
        select_provider(args.provider)
    elif args.command == "login":
        login_provider(args.provider or choose_provider())


def init_config() -> None:
    path = default_provider_config_path()
    if path.exists():
        print(f"provider config already exists: {path}")
        return
    write_provider_config(json.loads(json.dumps(DEFAULT_PROVIDER_CONFIG)), path)
    print(f"created provider config: {path}")


def show_status() -> None:
    config = load_provider_config()
    secrets = load_provider_secrets()
    selected = config.get("selected_provider", "codex")
    print(f"config:  {default_provider_config_path()}")
    print(f"secrets: {default_provider_secrets_path()}")
    print(f"selected provider: {selected}")
    print()
    for provider in PROVIDERS:
        cfg = provider_config(config, provider)
        env_name = cfg.get("api_key_env")
        has_secret = bool(isinstance(secrets.get(provider), dict) and secrets[provider].get("api_key"))
        env_status = "set" if env_name and env_name in __import__("os").environ else "unset"
        secret_status = "stored" if has_secret else "not stored"
        model = cfg.get("model", "")
        extra = ""
        if provider == "codex":
            extra = codex_status()
        else:
            extra = f"env {env_name}={env_status}, secret={secret_status}"
        marker = "*" if provider == selected else " "
        print(f"{marker} {provider:10s} model={model} {extra}")


def choose_provider() -> str:
    print("Choose provider:")
    for idx, provider in enumerate(PROVIDERS, start=1):
        print(f"  {idx}. {provider}")
    while True:
        raw = input("provider number: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(PROVIDERS):
            return PROVIDERS[int(raw) - 1]
        print("invalid provider")


def select_provider(provider: str) -> None:
    config = load_provider_config()
    config["selected_provider"] = provider
    write_provider_config(config)
    print(f"selected provider: {provider}")


def login_provider(provider: str) -> None:
    config = load_provider_config()
    providers = config.setdefault("providers", {})
    cfg = provider_config(config, provider)

    print(f"Configuring {provider}. Press Enter to keep the current value.")
    if provider == "codex":
        model = prompt_default("Codex model", str(cfg.get("model", "gpt-5.4")))
        providers.setdefault(provider, {})["model"] = model
        config["selected_provider"] = provider
        write_provider_config(config)
        print(codex_status())
        print("Codex uses your local Codex login/app-server; no API key was stored.")
        return

    model = prompt_required("Model", str(cfg.get("model", "")))
    env_name = prompt_required("API key environment variable", str(cfg.get("api_key_env", "")))
    base_url = prompt_default("Base URL", str(cfg.get("base_url", "")))
    providers.setdefault(provider, {})["model"] = model
    providers[provider]["api_key_env"] = env_name
    providers[provider]["base_url"] = base_url
    if provider == "anthropic":
        providers[provider]["anthropic_version"] = prompt_default(
            "Anthropic version header",
            str(cfg.get("anthropic_version", "2023-06-01")),
        )
    if provider == "openrouter":
        providers[provider]["app_title"] = prompt_default("OpenRouter app title", str(cfg.get("app_title", "AlturaProt")))
        referer = prompt_default("OpenRouter HTTP referer (optional)", str(cfg.get("http_referer", "")))
        if referer:
            providers[provider]["http_referer"] = referer

    save_secret = input("Store API key in local 0600 secrets file? [y/N]: ").strip().lower() == "y"
    if save_secret:
        key = getpass.getpass("API key: ").strip()
        if key:
            secrets = load_provider_secrets()
            secrets.setdefault(provider, {})["api_key"] = key
            write_provider_secrets(secrets)
            print(f"stored secret in {default_provider_secrets_path()}")
    else:
        print(f"Set {env_name}=... in your shell before using this provider.")

    config["selected_provider"] = provider
    write_provider_config(config)
    print(f"configured and selected provider: {provider}")


def prompt_default(label: str, current: str) -> str:
    suffix = f" [{current}]" if current else ""
    raw = input(f"{label}{suffix}: ").strip()
    return raw or current


def prompt_required(label: str, current: str) -> str:
    while True:
        value = prompt_default(label, current).strip()
        if value:
            return value
        print(f"{label} is required.")


def codex_status() -> str:
    codex = shutil.which("codex")
    if not codex:
        return "codex CLI not found"
    try:
        version = subprocess.check_output([codex, "--version"], text=True, stderr=subprocess.STDOUT, timeout=5).strip()
    except Exception as exc:
        version = f"codex check failed: {exc}"
    try:
        __import__("openai_codex")
        sdk = "openai-codex import ok"
    except Exception:
        sdk = "openai-codex not installed"
    return f"{version}, {sdk}"


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130)
