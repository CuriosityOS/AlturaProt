# Security Policy

AlturaProt is defensive security software. We take the security of the proxy and
its tooling seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, report privately via one of:

- GitHub's [private vulnerability reporting](https://github.com/CuriosityOS/AlturaProt/security/advisories/new)
  (Security → Report a vulnerability), or
- email **admin@altura.ovh** with `[AlturaProt security]` in the subject.

Please include a description, affected version/commit, reproduction steps, and
impact. We aim to acknowledge reports within a few business days and will keep
you updated on remediation.

## Scope

In scope: the proxy hot path (rate limiting, filtering, request validation,
connection handling), config parsing/preflight, the CodexSDGate analyzer and its
provider handling, the installer, and the shipped systemd/nftables templates.

When reporting, target only systems you own or are authorized to test. Do not
use the bundled flood/benchmark tooling against third-party infrastructure — it
defaults to loopback and refuses public targets by design.

## Supported versions

This project is pre-1.0 and moves fast; security fixes land on `main`. Please
verify issues against the latest `main` before reporting.
