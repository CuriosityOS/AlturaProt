#!/usr/bin/env python3
"""Interactive + scriptable AI provider setup for AlturaProt/CodexSDGate.

Two provider families, mirroring how T3 Code wires models:

* Subscription "agent CLI" providers (codex, claude, opencode, cursor, grok):
  AlturaProt shells out to the official CLI you already logged into. No API key
  is stored; authentication is whatever the vendor CLI manages.
* API-key providers (openai, anthropic, gemini, openrouter): a key + model are
  stored (env var or 0600 secrets file) and called over HTTPS.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
from typing import Any

from codex_analyzer import (
    DEFAULT_PROVIDER_CONFIG,
    default_provider_config_path,
    default_provider_secrets_path,
    detect_cli_agent,
    load_provider_config,
    load_provider_secrets,
    provider_config,
    write_provider_config,
    write_provider_secrets,
)

# codex is a CLI/subscription login too, but goes through the openai_codex SDK
# rather than a wrapped subprocess, so it keeps its bespoke prompts below.
CLI_AGENTS = ["codex", "claude", "opencode", "cursor", "grok"]
API_PROVIDERS = ["openai", "anthropic", "gemini", "openrouter"]
PROVIDERS = CLI_AGENTS + API_PROVIDERS


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Configure AI providers for AlturaProt CodexSDGate.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Show selected provider and redacted credential/CLI status.")
    login = sub.add_parser("login", help="Interactively configure a provider.")
    login.add_argument("provider", nargs="?", choices=PROVIDERS)
    select = sub.add_parser("select", help="Select active provider.")
    select.add_argument("provider", choices=PROVIDERS)
    sub.add_parser("init", help="Create default provider config if missing.")
    detect = sub.add_parser("detect", help="Report which agent CLIs are installed.")
    detect.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    setp = sub.add_parser("set", help="Non-interactively configure a provider (used by the installer).")
    setp.add_argument("provider", choices=PROVIDERS)
    setp.add_argument("--model", default=None)
    setp.add_argument("--base-url", default=None)
    setp.add_argument("--command", dest="cli_command", default=None, help="Override the agent CLI binary name.")
    setp.add_argument("--api-key-env", default=None)
    setp.add_argument("--api-key", default=None, help="Store this key in the 0600 secrets file.")
    setp.add_argument("--select", dest="select", action="store_true", default=True)
    setp.add_argument("--no-select", dest="select", action="store_false")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "init":
        init_config()
    elif args.command == "status":
        show_status()
    elif args.command == "select":
        select_provider(args.provider)
    elif args.command == "detect":
        detect_command(args.json)
    elif args.command == "set":
        set_provider(args)
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
    print("subscription CLIs (use the CLI's own login):")
    for provider in CLI_AGENTS:
        cfg = provider_config(config, provider)
        marker = "*" if provider == selected else " "
        if provider == "codex":
            print(f"{marker} {provider:10s} model={cfg.get('model','')} {codex_status()}")
            continue
        info = detect_cli_agent(provider, cfg)
        state = "installed" if info["installed"] else "not installed"
        version = f" {info['version']}" if info["version"] else ""
        print(f"{marker} {provider:10s} model={cfg.get('model','') or '(cli default)'} {state}{version} (login: {info['login_cmd']})")
    print()
    print("API-key providers:")
    for provider in API_PROVIDERS:
        cfg = provider_config(config, provider)
        env_name = cfg.get("api_key_env")
        has_secret = bool(isinstance(secrets.get(provider), dict) and secrets[provider].get("api_key"))
        env_status = "set" if env_name and env_name in os.environ else "unset"
        secret_status = "stored" if has_secret else "not stored"
        marker = "*" if provider == selected else " "
        print(f"{marker} {provider:10s} model={cfg.get('model','')} env {env_name}={env_status}, secret={secret_status}")


def detect_command(as_json: bool) -> None:
    config = load_provider_config()
    results = [detect_cli_agent(p, provider_config(config, p)) for p in CLI_AGENTS if p != "codex"]
    if as_json:
        print(json.dumps(results))
        return
    for info in results:
        state = "installed" if info["installed"] else "not installed"
        version = f" ({info['version']})" if info["version"] else ""
        print(f"{info['provider']:10s} {state}{version}; login: {info['login_cmd']}")


def choose_provider() -> str:
    print("Choose provider:")
    for idx, provider in enumerate(PROVIDERS, start=1):
        kind = "subscription CLI" if provider in CLI_AGENTS else "API key"
        print(f"  {idx}. {provider} ({kind})")
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


def set_provider(args: argparse.Namespace) -> None:
    """Non-interactive configuration used by install.sh."""
    config = load_provider_config()
    providers = config.setdefault("providers", {})
    entry = providers.setdefault(args.provider, {})
    if args.model is not None:
        entry["model"] = args.model
    if args.cli_command is not None:
        entry["command"] = args.cli_command
    if args.base_url is not None:
        entry["base_url"] = args.base_url
    if args.api_key_env is not None:
        entry["api_key_env"] = args.api_key_env
    if args.select:
        config["selected_provider"] = args.provider
    write_provider_config(config)
    if args.api_key:
        secrets = load_provider_secrets()
        secrets.setdefault(args.provider, {})["api_key"] = args.api_key
        write_provider_secrets(secrets)
        print(f"stored API key for {args.provider} in {default_provider_secrets_path()}")
    print(f"configured provider: {args.provider}{' (selected)' if args.select else ''}")
    if args.provider in CLI_AGENTS and args.provider != "codex":
        info = detect_cli_agent(args.provider, provider_config(config, args.provider))
        if not info["installed"]:
            print(f"note: {info['command']} is not installed yet ({info['install_url']})")
        print(f"log in with: {info['login_cmd']}")


def login_provider(provider: str) -> None:
    config = load_provider_config()
    providers = config.setdefault("providers", {})
    cfg = provider_config(config, provider)

    print(f"Configuring {provider}. Press Enter to keep the current value.")
    if provider == "codex":
        provider_entry = providers.setdefault(provider, {})
        provider_entry["model"] = prompt_required("Codex model", str(cfg.get("model", "gpt-5.5")))
        provider_entry["reasoning_effort"] = prompt_choice(
            "Reasoning effort",
            str(cfg.get("reasoning_effort", "high")),
            {"none", "minimal", "low", "medium", "high", "xhigh"},
        )
        provider_entry["service_tier"] = prompt_required(
            "Service tier / fast mode",
            str(cfg.get("service_tier", "fast")),
        )
        config["selected_provider"] = provider
        write_provider_config(config)
        print(codex_status())
        print("Codex uses your local Codex login/app-server; no API key was stored.")
        return

    if provider in CLI_AGENTS:
        login_cli_agent(provider, config, providers, cfg)
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


def login_cli_agent(provider: str, config: dict[str, Any], providers: dict[str, Any], cfg: dict[str, Any]) -> None:
    info = detect_cli_agent(provider, cfg)
    if info["installed"]:
        version = f" {info['version']}" if info["version"] else ""
        print(f"found {info['command']}{version} on PATH.")
        print(f"If you are not already logged in, run: {info['login_cmd']}")
    else:
        print(f"{info['command']} is not installed.")
        if info["install_url"]:
            print(f"  install it from: {info['install_url']}")
        print(f"  then log in with: {info['login_cmd']}")
    model = prompt_default("Model (blank = let the CLI choose)", str(cfg.get("model", "")))
    entry = providers.setdefault(provider, {})
    entry["model"] = model
    config["selected_provider"] = provider
    write_provider_config(config)
    print(f"selected provider: {provider}")
    print("AlturaProt will invoke this CLI for adaptive filtering using its own login.")


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


def prompt_choice(label: str, current: str, allowed: set[str]) -> str:
    allowed_hint = ", ".join(sorted(allowed))
    while True:
        value = prompt_required(f"{label} ({allowed_hint})", current).lower()
        if value in allowed:
            return value
        print(f"{label} must be one of: {allowed_hint}")


def codex_status() -> str:
    status = []
    codex = shutil.which("codex")
    if codex:
        try:
            status.append(subprocess.check_output([codex, "--version"], text=True, stderr=subprocess.STDOUT, timeout=5).strip())
        except Exception as exc:
            status.append(f"codex CLI check failed: {exc}")
    else:
        status.append("codex CLI not on PATH")
    try:
        __import__("openai_codex")
        status.append("openai-codex import ok")
    except Exception:
        status.append("openai-codex not installed")
    return ", ".join(status)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(130)
