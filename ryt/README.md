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
analysis/findings through the MCP interface. The primary is GLM-5.3-Flash/max;
the approved availability fallback is b.ai Qwen3.8-Flash with thinking disabled.
The existing PR-Agent library is retained ONLY as the proven GitHub diff/formatting/
inline-publication adapter, not as the mandatory review's inference engine.

No upstream issue, contributor, cross-repository, or auto-merge bot is activated.
No GitHub credential enters OpenCode. The upstream broad token-aware shell profile
is deliberately not used on RYT's persistent hosts. Instead the agent has only
custom snapshot tools; scratch code runs under Bubblewrap/seccomp with no network,
no host home, read-only repository files and bounded CPU/time/files/output. The
OpenCode engine itself also has a private Bubblewrap network namespace: it has no
host or Internet route. A trusted relay on sandbox-local loopback forwards only to
a mode-0600 Unix-domain socket owned by the host provider bridge; that bridge can
call only its selected profile's fixed Z.AI or b.ai endpoint, rejects redirects,
and retains the real API key outside the agent.
OpenCode permission rules are defense-in-depth, not the egress boundary. No public
session sharing, external plugins, model-controlled routing, input compaction, system
installation or runner-administration capability.

Persistent-host state is isolated under a mode-0700 `ryt-mirrobot-sessions` root.
Every review sweeps bounded stale `review-*` directories before creating a new
session, active sessions heartbeat their directory, and normal teardown removes the
current tree. The independent `ops/systemd/ryt-mirrobot-hygiene.timer` contract
covers SIGKILL/OOM/host-crash leftovers even when no later review starts. Sweeping
refuses symlinks, foreign ownership, permissive directories and ages shorter than
the maximum review wall time; it never broad-deletes arbitrary runner paths.

## Limits and guarantees

A disposition plus independently verified provider receipts proves input delivery
and a completed model response, not that an AI
understood every line or that the code has no defects. Per-request context is 128K,
output 32K, request timeout 600 seconds; sessions are allocated from an 85-minute total review budget, at most 30 minutes per
chunk (divided fairly when multiple chunks remain), with 64 model
calls/384 tool calls. RYT retains its eight-session and total-job limits. Oversized or
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
accepted. GLM keeps maximum reasoning; Qwen explicitly disables thinking. Typed
stream-failure codes and final metadata distinguish limits from transport failures.


## Bounded multi-file investigation sessions

A review is planned before inference into at most eight independent sessions. Each
normally contains at most four files and targets 8192 diff tokens, with the full
initial request estimated below 49152 tokens to leave room for investigation and
the unchanged 32K output reservation. An indivisible file above the diff target is
kept intact only when its full initial packet fits. Otherwise the job fails with
an explicit split-required error; nothing is silently omitted or clipped.

Every session starts with fresh OpenCode state and the same immutable head/base
snapshot. Cross-file reads remain available, including files assigned to other
sessions. Histories are not summarized into replacement context. All original
diffs, paths, order and bytes must match the plan before the existing publisher
can run. The final coverage verifier accounts for every successful session. The
eight-session, 85-minute reasoning and 90-minute job constraints
remain unchanged. Smaller fully paginated search/read replies reduce needless
context growth; the bridge discloses remaining headroom and still rejects an
oversized request rather than fabricating a completed review.

## Inference availability pool

The host reads `OPENAI_KEY` (GLM primary), followed by `PR_REVIEW_BAI_01`,
`PR_REVIEW_BAI_02`, and `PR_REVIEW_BAI_03`. Empty credentials are skipped and
duplicate values are used once. Route aliases, never credentials, appear in evidence.
One key is sufficient for b.ai; the other slots are reserves. Only HTTP 429,
500/502/503/504 and transport timeouts/errors advance the pool. A failed route is
retired for the current review, including subsequent chunks. Authentication,
coverage, model identity, truncation and other assurance failures fail closed.

Each attempt starts fresh OpenCode state with the same complete input and trusted
policy. The original session time, 64 provider requests and 384 tool calls are
shared across attempts. The completed session records actual provider/model,
thinking mode, safe route aliases and bounded attempt accounting. Qwen requests
force `enable_thinking: false`; observed reasoning content or nonzero reasoning
token usage is rejected. Provider-internal behavior beyond observable output is
not independently measurable.

This pool is local to one review. It does not claim independent quotas for keys
on one account, coordinate quota cooldown across runners, or prove sustained free
capacity. Additional providers require explicit fixed profiles and verification.

b.ai sometimes emits its token-rate-limit error as an HTTP 200 assistant message.
Only the observed exact JSON envelope is recognized as `provider_token_rate_limit`;
ordinary model text and tool calls are not reclassified. Its text is held only in
a bounded transient buffer, never copied into evidence. The closed code retires
the key and advances to the next approved route. Once a bridge fails it rejects
SDK retries before any further upstream requests and preserves the first failure.

Qwen enters a finalization phase when at most 32K plus 1K safety of input capacity,
or eight provider requests, remain. The provider then receives only the structured
submission tool with explicit function choice; every original message and complete
diff stays in the input. Merely hiding inspection schemas does not reliably stop
Qwen from calling remembered tools. After the trusted MCP server accepts the
structured result, tool choice becomes `none` so the model can acknowledge its
receipt without submitting again. No model text can substitute for that acceptance.
The agent receives the remaining call allocation, and its step budget matches the
host call budget. This reserves room for a result and its provider receipt instead
of consuming all context on repeated searches. Limitations must be disclosed;
missing submission, coverage or receipts still fails the review.
