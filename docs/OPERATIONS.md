# Operations

## Local Test

Start an upstream:

```bash
python3 -m http.server 9000 --bind 127.0.0.1
```

Start AlturaProt:

```bash
cargo run --release -- --config configs/example.json
```

Run a bounded loopback benchmark:

```bash
python3 tools/local_http_flood.py --url http://127.0.0.1:8080/ --duration 10 --workers 64
```

## Metrics

Health:

```bash
curl http://127.0.0.1:8080/__altura/health
```

Metrics:

```bash
curl -H 'x-altura-admin-token: change-me' http://127.0.0.1:8080/__altura/metrics
```

## Blackhole Guidance

Use application filters for L7 selectivity and uptime. Use upstream blackholing or scrubbing when traffic volume saturates the link or host before the proxy can make useful decisions.

Blackholing is cheaper than host firewall processing, but it drops all matched traffic. For public production use, pair AlturaProt with a provider-level control such as BGP blackhole, scrubbing center, anycast/CDN, or an upstream router ACL.

## Hardening Checklist

- Run behind TLS termination or add TLS support before internet exposure.
- Put metrics behind an admin token and private network.
- Keep default listeners bound to explicit addresses.
- Tune `per_ip_rps`, `global_rps`, and adaptive thresholds from real traffic.
- Keep static filters narrow.
- Review `runtime/attack_events.jsonl` and `runtime/filters.json` after incidents.
