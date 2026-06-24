# Result 02-tcp-edge: TCP + Edge

## Summary
TCP path is a thin L4 relay with solid post-accept controls. Main gaps: accept-then-reject burns resources, default min data-rate disabled (slow-trickle bypass), systemd TasksMax undercuts connection caps, edge connlimit looser than userspace.

## Evidence
- Accept before limit: `src/tcp_proxy.rs:97-134`
- Default min rate 0: `src/config.rs:1802-1804`
- TasksMax 4096: `ops/systemd/altura-prot.service:19`
- Edge connlimit 512 vs userspace 128 default

## Handoff
- Summary: Mandate ops/ edge deployment; align systemd/edge limits with config
- Risks: TasksMax mismatch (high), slow-trickle slot exhaustion (high)