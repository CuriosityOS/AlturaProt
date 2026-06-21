# Smart Defense Benchmark 2026-06-18

Run target: `core`, loopback only. Spoof traffic is simulated with trusted-proxy `X-Forwarded-For` headers, not packet spoofing.

The Codex provider used the default Codex SDK settings from `tools/codex_analyzer.py`: `model=gpt-5.5`, `reasoning_effort=high`, and `service_tier=fast`.

## Why This Run Exists

The first benchmark proved simple repeated floods, but a smarter attacker can rotate source IP headers and request shapes. That exposed a real gap: per-signature detection saw no repeated signature, so CodexSDGate had too little useful telemetry.

Changes made before the final run:

- Event logs now include `path_shape`, `query_keys`, `x_forwarded_for`, and `header_names`.
- The adaptive detector emits bounded `global_observed` samples during high global request volume, even when individual signatures are unique.
- Filters now support a `path_shape` condition such as `/api/:token/:num`.
- Adaptive `path_shape` filters can activate during global-flood detection.

## Final Smart Spoof Result

Artifact: `benchmark_results/defense_bench_codex_xff_poly_pathshape_20260618.json`.

Scenario: `xff-polymorphic`, which rotates fake forwarded IPs, random high-entropy API path tokens, query keys, and user-agent families.

| Layer | Filters | Codex write | Replay blocked | Benign allowed | Meets 90% attacker block | Meets 95% benign allow |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| strict learned filter | 0 | n/a | 0.00% | n/a | no | yes |
| observed-learning learned filter | 5 | 16.778s | 99.69% | 100.00% | yes | yes |

## What Codex Wrote

Codex wrote a mix of a few exact sampled signatures plus the important generalized filter:

```json
{
  "id": "adaptive_shape_api_token_num_get",
  "adaptive": true,
  "condition": {
    "methods": ["GET"],
    "path_shape": "/api/:token/:num"
  },
  "action": {
    "kind": "block",
    "status": 403,
    "body": "blocked by adaptive filter\n"
  }
}
```

That is not an IP block and not a broad `/api/*` block. It targets high-entropy two-segment API paths shaped like `/api/<long-token>/<number>`, while the benchmark's benign probe `/api/catalog/<id>?page=...` remained allowed.

## Interpretation

- Strict mode remains conservative and does not learn from observed-only traffic.
- Observed-learning mode is needed for spoof/polymorphic floods because IP rate limits and repeated-signature detection are both intentionally weak against that attack shape.
- The useful mitigation was not “block all API.” It was a narrower behavior/pattern filter activated only during a matching global flood.
