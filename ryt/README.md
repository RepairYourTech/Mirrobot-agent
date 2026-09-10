# RYT Mirrobot execution profile

This is an additive deployment profile for Mirrowel's Mirrobot agent, not a renamed
copy of its automation suite. Upstream files/history and MIT attribution are retained.
The fork's `ryt/` layer uses upstream review guidance and the actual pinned OpenCode
agent loop with read/search/probe tools, plus deterministic RYT delivery evidence.

## What runs

RYT's existing trusted dispatcher and dedicated review pool call `ReviewBackend`.
It provides complete diff chunks, immutable exact-head/base snapshots, and previous
bot findings to OpenCode. The bounded diff packet is verified in the actual initial model request; revisited
pages carry independent delivery receipts. The model must submit structured file
analysis/findings through the MCP interface. Mandatory reasoning is GLM-5.3-Flash/max.
The existing PR-Agent library is retained ONLY as the proven GitHub diff/formatting/
inline-publication adapter, not as the mandatory review's inference engine.

No upstream issue, contributor, cross-repository, or auto-merge bot is activated.
No GitHub credential enters OpenCode. The upstream broad token-aware shell profile
is deliberately not used on RYT's persistent hosts. Instead the agent has only
custom snapshot tools; scratch code runs under Bubblewrap/seccomp with no network,
no host home, read-only repository files and bounded CPU/time/files/output. The
provider bridge can call only the fixed Z.AI endpoint and retains the real API key
outside the agent. No public session sharing, external plugins, model fallback,
input compaction, system installation or runner-administration capability.

## Limits and guarantees

A disposition plus independently verified provider receipts proves input delivery
and a completed model response, not that an AI
understood every line or that the code has no defects. Per-request context is 128K,
output 32K, request timeout 600 seconds; sessions are allocated from an 80-minute total review budget, at most 30 minutes per
chunk (divided fairly when multiple chunks remain), with 64 model
calls/384 tool calls. RYT retains its six-chunk and total-job limits. Oversized or
failed work remains incomplete; it must not be relabeled clean. Large background
snapshot files (>2MiB) and non-regular entries are unavailable as full-file reads,
explicitly inventoried, while the changed-file diff still follows RYT policy.

Follow-ups retain full current-diff coverage; prior findings include resolution and
outdated state. Context bounds are disclosed. No model-controlled merge authority.
Run tests with `python3 -m unittest discover -s ryt/tests -v`. Set
`RYT_OPENCODE_BIN` to the checksum-verified pinned executable to include the actual
OpenCode/MCP/sandbox integration test; that test uses a synthetic provider, not an
API secret. The separate deployment canary verifies the real model endpoint.

See PLAN.md for promotion gates and rollback. RYT source, diffs, prompts containing
private context, API keys and raw model session logs must never be committed here.

Provider request receipts also verify that each diff tool response actually reached
the inference request unchanged. Tool pages are serialized below OpenCode truncation
limits; linked requirements, trusted repository guidance and prior findings are
paginated rather than silently omitted. Assistant-generated text cannot forge a
tool receipt. Prior finding count/body limits remain explicitly disclosed.

The provider output allowance is 32K, within the documented Flash128K maximum;
input+output remains within RYT128K policy. The previous16K cap could terminate
long maximum-reasoning responses. Truncation still fails; no partial response is
accepted, no weaker reasoning or automatic retry/fallback is introduced. Typed
stream-failure codes and final metadata distinguish limits from transport failures.
