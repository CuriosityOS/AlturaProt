# Architecture

AlturaProt has two loops:

1. Hot path: Rust reverse proxy accepts HTTP/TCP traffic, applies limits and filters, proxies allowed requests, and emits compact telemetry.
2. Control path: CodexSDGate reads telemetry and writes constrained JSON filters that the proxy reloads.

The hot path must remain deterministic. AI providers never run inline with client requests because model latency, provider outages, and token cost would make availability worse during an attack.

## HTTP Path

- Accept HTTP/1 connections with Hyper.
- Build a stable request signature from method, normalized path, query shape, user-agent family, and accept header.
- Observe the signature in a one-second adaptive detector.
- Apply static and active adaptive filters.
- Apply global and per-IP token-bucket limits.
- Rewrite the request to the upstream and stream the response back.

## TCP Path

- Accept raw TCP connections with Tokio.
- Apply per-IP connection-rate and concurrent-connection limits.
- Connect to the configured upstream.
- Copy bytes bidirectionally with an idle timeout.

## Filter Safety

Filters are allowlisted JSON rules. Provider output is sanitized before it reaches `runtime/filters.json`, and the Rust proxy only implements the supported condition/action fields. Unsupported model output is ignored.

Adaptive rules are dormant until their learned signature crosses the configured threshold. They then activate for a TTL and expire automatically.

## False Positive Strategy

- Prefer signatures over broad path or user-agent blocks.
- Keep static rules only for known hostile probes.
- Keep adaptive filters dormant until a burst threshold is crossed.
- Use short TTLs and event logs for auditability.
- Treat blackholing as an upstream emergency control, not as normal L7 filtering.
