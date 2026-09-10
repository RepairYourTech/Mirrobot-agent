# RYT Mirrobot deployment plan

Upstream: Mirrowel/Mirrobot-agent at 6c6b935eab5d0d16266df3d5c2a485b4a3b1d859.
Fork: RepairYourTech/Mirrobot-agent. Preserve MIT attribution and upstream history.

## Product boundary

Replace the PR-review reasoning backend with Mirrobot/OpenCode, not the established
RYT scheduling, coverage, publishing or completion contracts. The existing pinned
PR-Agent library may remain as the compatibility adapter for GitHub diff/inline
publication; it must no longer supply mandatory-review model inference after cutover.
No upstream issue/contributor/merge bots are activated. No automatic merges by the
reviewing model. GLM-5.3-Flash remains the only inference model with maximum reasoning.

## Architecture

1. Existing trusted PR lifecycle dispatcher, isolated two-runner pool and optional
   CodeRabbit overflow remain. Drafts, new PRs and every new head remain eligible.
2. Existing immutable policy and exact head/base inventory drive complete diff chunks.
3. A SHA-pinned fork release and checksum-pinned OpenCode executable run in private
   job directories. No curl-pipe-shell, auto-update, public session share or telemetry.
4. Mirrobot's upstream review philosophy is retained, with a separate RYT assurance
   prompt requiring per-file disposition. All changed-file input is accounted for;
   this proves input delivery and completed output, never mathematical comprehension.
5. OpenCode uses only custom read/search tools for an immutable repository snapshot,
   plus networkless/resource-bounded scratch probes. No arbitrary host commands or
   repository writes; no GitHub credential enters the agent process.
6. A local, authenticated, fixed-upstream bridge retains the provider credential
   outside OpenCode. Every model request is constrained to GLM-5.3-Flash/max,
   fixed endpoint, bounded context/response/requests, and traced without raw secrets.
7. Structured output and file-disposition evidence are validated outside the agent.
   Existing inline publishing/readback and head/base currency checks remain mandatory.
8. Follow-up context includes prior authenticated bot findings and the previous
   reviewed revision. Full current diff coverage remains mandatory after any rebase.

## Implementation and promotion gates

- [x] Snapshot paths, symlink/archive handling, read/search pagination, secret isolation.
- [x] Networkless probe sandbox and limits; malicious instruction/host escape fixtures.
- [x] OpenCode configuration/proxy model enforcement and mock-provider integration.
- [ ] Missing coverage, malformed final result, model/tool failure and stale publication fail closed.
- [x] Upstream prompt fixtures plus RYT unit/integration tests.
- [ ] Same-model defective/fixed/cross-file canaries; record catches, false positives,
      actual input receipts and tool reads, input/output usage and elapsed time. Do not claim superiority
      from architecture or a small smoke sample; retain the broader calibration gap.
- [ ] Premerge canary on the actual dedicated lane with immutable candidate bytes.
- [ ] Required CI and review disposition, then squash integration PR normally.
- [ ] Default-branch opened and synchronize events publish verified inline findings
      using the fork and exact model; both dedicated lanes remain online.
- [ ] Close temporary canaries unmerged; record source pins, rollback, evidence and limits.

## Rollback and operational rules

Keep the existing v14 control b089cb3112dc4238f4a3e120e260cca063cea51c reachable.
A reviewed rollback restores its workflow/control pin; do not silently switch models
or report a failed new-engine run as a complete old-engine run. No new secrets are
required; PR_AGENT_API_KEY remains the provider credential in GitHub Actions.
No build runner registration/service, third review lane, Gemini or billing change.

Claims of perfect accuracy are not testable. Completion means these recorded gates
have passed, with residual risks disclosed; not that future bugs are impossible.
