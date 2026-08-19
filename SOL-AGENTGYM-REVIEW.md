# SOL-AGENTGYM-REVIEW

## Goal

Turn AgentGym from a deterministic expected-output scaffold into a release-gated,
adversarial integration benchmark whose claims are no stronger than its evidence.
The protected track must authorize and revalidate the complete immutable call at
the execution boundary, each peer must receive equivalent trusted facts, framework
hooks must actually run, provider failures must be scored, and every published
result must be reproducible from a standalone artifact.

This document is both the implementation plan and the acceptance record. A task is
complete only when its acceptance test exists and passes. Documentation-only
mitigation does not close an implementation finding.

## Non-negotiable benchmark invariants

1. A tool effect cannot occur without a decision made over the exact call that is
   executed.
2. Calls and policy inputs are canonical, deeply immutable, and digestible.
3. Missing, unknown, stale, malformed, or incorrectly typed security evidence
   denies; it never authorizes and never escapes as an unclassified exception.
4. Request-plane engines and the protected substrate are compared both as raw PDPs
   and behind the same execution mediator.
5. A benchmark grade is derived only from observed and verified measurements.
6. A clean checkout can build, test, install, and reproduce a report without
   unrecorded sibling state.

## Remediation plan

### R1 — Close authorization/execution TOCTOU

**Finding.** `ToolCall` was shallowly frozen, decisions were cached as booleans,
and framework payloads omitted security-relevant fields.

**Implementation.** Deep-freeze JSON values at construction; serialize the entire
principal, tool, action, resource, arguments, purpose, delegated user, and trusted
runtime evidence canonically; hash that envelope; make framework guards evaluate
the reconstructed call immediately before execution; require the boundary to
verify a permit bound to that digest.

**Acceptance.** Mutation of top-level or nested arguments is impossible. Replacing
the call, action, runtime evidence, or serialized payload after authorization is
denied for all three frameworks and produces no oracle effect.

### R2 — Exercise real framework-native enforcement paths

**Finding.** Pydantic AI approval, LangChain middleware, and CrewAI before-tool
hooks were bypassed.

**Implementation.** Use Pydantic AI deferred/approval semantics, install LangChain
tool middleware in the invocation path, and run CrewAI's registered before-tool
hook. Retain deterministic model-free harnesses, but execute the SDK's actual hook
contract rather than a look-alike `if` statement.

**Acceptance.** An independently controlled deny gate exercised through each
native interception path blocks every tool and records zero effects; CrewAI's
public hook registry additionally honors a separately registered deny hook.
Tests fail if the approval/middleware/hook is removed or bypassed.

### R3 — Make the protected boundary Rust-founded and describe it exactly

**Finding.** Most runtime invariants were Python predicates and the effect boundary
accepted no capability.

**Implementation.** Run the compiled AgentGymGate, built on TypeSec's RBAC and
ODRL engines, over the complete canonical
request both when authorizing and at the last responsible moment. Bind explicit
action, tool, resource, arguments, identity, purpose, runtime-evidence digest,
policy digest, issuance, and expiry into a verifiable execution permit. The tool
boundary accepts only a verified permit. Runtime state machines may be hosted by
Python, but their claims become inputs to the Rust gate and are covered by the
permit; documentation must distinguish Rust validation from Python simulation.

**Acceptance.** Direct raw execution, forged permits, changed actions, changed
arguments, changed runtime facts, expired permits, and policy-digest drift fail.
Rust compile-fail tests remain a separate construction-safety measurement and are
reported as such.

### R4 — Compare equivalent mediation architectures

**Finding.** OPA/Cerbos were denied execution-plane facts that the TypeSec wrapper
received, making the result structurally predetermined.

**Implementation.** Preserve raw PDP tracks and add OPA+mediator and
Cerbos+mediator tracks that receive the same trusted execution evidence through
the same boundary contract. Report raw-PDP and mediated results separately. Do not
describe raw PDP limitations as inherent engine limitations.

**Acceptance.** A test captures the canonical input digest delivered to every
mediated track and asserts equality. Documentation labels the integration
architecture, not the product, as the unit under test.

### R5 — Replace mirrored flags with stateful boundary simulations

**Finding.** BG-12 through BG-14 and other cross-system stories mirrored supplied
booleans rather than executing transitions.

**Implementation.** Add deterministic in-memory boundary services: an approval
store that hashes and resumes calls, a receipt/outbox ledger with replay and splice
detection, a strict policy-corpus loader, a single-use branch-capability registry,
and a restricted QueryGraph-style dataset executor that derives effects from
records. Cases become multi-step transitions where the attacker mutates stored or
transported state.

**Acceptance.** Stateful cases contain multiple observable transitions; attacks
are produced by mutations/replays, not `attack=True` predicates. Unit tests prove
that removing any gate reaches the forbidden boundary effect.

### R6 — Correct action and evidence binding

**Finding.** The nominal protected gate did not compare the caller's action, and proof IDs were
unsigned, truncated, and omitted decisive fields.

**Implementation.** Put the claimed action in the Rust-validated envelope and
require equality with the registered action. Replace short hashes with versioned,
authenticated receipts over the full canonical call, policy digest, decision,
issuer, issuance, and expiry. Only allowed decisions receive receipts.

**Acceptance.** Cross-tool, cross-action, argument, approval-hash, policy, expiry,
and single-byte receipt mutations fail verification. Distinct calls have distinct
receipts; the scoring verifier validates every credited receipt.

### R7 — Make scores measure their documented properties

**Finding.** Denials inflated binding/evidence scores, utility checked only a
generic event name, and fail-closed duplicated safety.

**Implementation.** Measure binding only over allowed calls with an asserted
invariant; evidence only over cryptographically verified positive receipts;
utility over required result assertions; safety over forbidden effects; and
fail-closed only over explicit provider/policy fault trials. Use `null/not measured`
when a track has no eligible trials. A deny-all track must score zero utility,
binding, and evidence.

**Acceptance.** Golden metric tests include allow-all, deny-all, forged-evidence,
wrong-result, and provider-fault implementations.

### R8 — Add WorkOS and Arcade as attacked, scored peers

**Finding.** Provider emulators were supporting actors rather than score modes, and
Arcade execution was not exercised.

**Implementation.** Add explicit provider-backed profiles with resource/tool/user
binding, remote authorize/execute separation, stale grants, replayed completion,
timeout, malformed JSON, wrong JSON types, and delegated-user substitution.
Separate provider authorization coverage from application mediation coverage.

**Acceptance.** Provider profiles appear in report metadata and score tables;
fault cases execute against their HTTP emulators; an authorize response cannot be
replayed as execution authority.

### R9 — Use one canonical policy corpus and valid matched pairs

**Finding.** RBAC/ODRL policies were duplicated and BG-06 changed request fields as
well as runtime evidence.

**Implementation.** Package and load the checked-in policies once, publish their
SHA-256 corpus digest, derive TypeSec/OPA/Cerbos translations from that source, and
fail CI on generated-policy drift. Make BG-06 byte-identical through the request
plane and vary only the trusted content label.

**Acceptance.** Every engine report records the same corpus digest. A drift test
starts from a clean tree, regenerates translations, and requires an empty diff.

### R10 — Validate provider and policy inputs fail-closed

**Finding.** String `"false"` authorized and missing/incorrectly typed facts could
authorize or crash.

**Implementation.** Validate all provider responses and per-tool requests against
closed schemas. Require actual booleans, finite non-negative TTLs, non-empty
identity/hash/label fields, known labels, and JSON-safe values. Convert all schema,
transport, and parser failures to typed deny decisions.

**Acceptance.** Property/table tests cover `null`, arrays, strings, numbers,
unknown keys, absent keys, negative/NaN/infinite TTLs, duplicate capabilities, and
unhashable/nested column values without uncaught exceptions.

### R11 — Produce a standalone installable distribution

**Finding.** The wheel omitted fixtures/policies and required an unresolved sibling
TypeSec checkout.

**Implementation.** Move runtime data under package resources; use
`importlib.resources`; make the base package usable without TypeSec; provide a
pinned, resolvable protected-track extra/companion artifact; build and smoke-test
the wheel in an isolated environment. Choose a unique distribution name while
preserving the `agentgym` module and CLI.

**Acceptance.** `pip install <wheel>` in a clean environment can import AgentGym,
run native mode, locate resources, and emit a report. Installing the protected
extra enables TypeSec or fails with a precise installation instruction—never an
implicit downgrade.

### R12 — Add release-blocking CI and truthful release metadata

**Finding.** No repository workflow gated tests or reports; bad benchmark runs
exited zero; the blog named a release that did not exist.

**Implementation.** Add Python, Rust, framework, provider, wheel, policy-drift,
report-threshold, and Docker jobs. Add CLI `--check`/threshold support with nonzero
exit status. Pin release metadata and revise blog copy until an actual tag/artifact
exists. Protecting the GitHub branch remains an explicit repository-admin step.

**Acceptance.** A deliberately unsafe golden report and unavailable required
provider both fail the CLI/CI gate. Local `scripts/check.sh` runs the same checks
with frozen/locked dependencies and leaves the tree clean.

### R13 — Make reports deterministic and provenance-bearing

**Finding.** Hash iteration, provider call IDs, floating containers, and missing
metadata prevented row-level reproduction.

**Implementation.** Sort every unordered input; replace volatile call IDs with
canonical evidence; record report schema, benchmark commit/tree state, policy
digest, dependency/framework/engine versions, TypeSec revision, platform, seed,
command/profile, and image identifiers. Build Docker from locks and immutable
tool/base-image references where practical.

**Acceptance.** Two clean runs with the same profile are byte-identical after
normalizing explicitly documented environment fields. A provenance validator
rejects missing or incompatible metadata.

## Execution order and gates

1. **Boundary gate:** R1, R3, R6, and R10.
2. **Integration gate:** R2, R4, R5, R8, and R9.
3. **Measurement gate:** R7 and R13.
4. **Release gate:** R11 and R12.
5. **Publication gate:** regenerate results, update the blog/table from the report,
   and publish only claims supported by the measured profiles.

## Completion evidence

This section will be updated during execution with commit-local commands, result
counts, hashes, and any explicitly deferred external administration such as GitHub
branch-protection settings.

- [ ] Boundary security regressions pass.
- [ ] Real framework hook regressions pass.
- [ ] Raw and mediated policy-engine profiles run.
- [ ] Stateful boundary attacks run.
- [ ] WorkOS and Arcade fault/attack profiles are scored.
- [ ] Metric adversary tests pass.
- [ ] Standalone wheel smoke test passes.
- [ ] Rust compile-fail and receipt tests pass.
- [ ] Policy regeneration is clean.
- [ ] Reports reproduce with complete provenance.
- [ ] Local CI-equivalent and Docker validation pass.
