# Orchestration

## Parent critical path
1. Create run dir + write plan/orchestration/state + packet descriptors (parent, via shell only).
2. Spawn 4 parallel read-only explore subagents (background: true) with explicit bounded sources.
3. Collect subagent results (get_command_or_subagent_output, blocking when needed).
4. Integrate: read results, re-verify evidence in source, update integration.md + state.
5. Execute verification (python tests + source greps + checklist).
6. Write final-report.md, mark complete.
7. (No write wave; review only.)

## Packets
- 01-rust-core (owner: read-only-agent, write_scope: [], result_path: results/01-rust-core.md)
- 02-python-tools (owner: read-only-agent, write_scope: [], result_path: results/02-python-tools.md)
- 03-config-docs (owner: read-only-agent, write_scope: [], result_path: results/03-config-docs.md)
- 04-surfaces-risks (owner: read-only-agent, write_scope: [], result_path: results/04-surfaces-risks.md)

## Delegation
- native_agent_available: true
- native_agent_planned: true
- native_agent_used: true (4 explore agents in wave 1)
- agent_count: 4
- wave_count: 1
- no_delegation_reason: "" (delegation used)

## Agents
All packets use subagent_type: "explore" (read-only). 
Description prefix: "[explorer] <id>-<name>"
Prompts include: "You are working in the same repo as other agents." + "Grok Build only: Use ONLY Shell / run_terminal_command for file writes/edits. Never use native write or search_replace tools." (even though read-only, for policy compliance).
Bounded: agents instructed to inspect only listed sources + 1 nearby hop if required for tracing; cite :line .

## Wait points
- Immediately after parallel spawn: wait on all 4 subagent task_ids before integration phase.
- No other waits (no write packets, no cross-packet handoff dependencies).

## Fallback
If any spawn_subagent fails or native primitive unavailable: fall back to parent executing the packet objectives sequentially via direct read_file/grep (record "no_delegation_reason" and continue). Do not invent other runners.

## Verification order
1. Local python tests (pre and post).
2. Automated greps for critical invariants (AI-in-hotpath, loopback).
3. Manual source re-read of high-claim areas from results.
4. Hardening checklist cross-map.
5. Cargo/Rust verification: document exact commands; execute only if toolchain present or via documented remote.
6. Final audit pass over plan + state + all artifacts.

## Native delegation outcome
Spawned 4 [explorer] subagents (background) immediately after writing artifacts.
All returned "cancelled" (durations 34-51s, 0 result files). 
No output captured from subagents.
Fallback activated: parent executes the 4 packet contracts directly (read-only inspection via tools + shell writes for results/).
Updated packets status in state to reflect fallback.
Verification and integration remain parent-owned.
