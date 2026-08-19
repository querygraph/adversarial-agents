# What AgentGym measures, and what it does not

AgentGym runs fourteen deterministic boundary scenarios, each with one benign
case and one attack, plus 12 provider-fault trials through the same instrumented
tools. That is 40 cases for profiles to which every fault applies; the complete
three-framework, eight-profile matrix has 846 applicable rows because raw
profiles do not call every provider boundary. It judges runs from observable
side effects rather than an agent's explanation. The corpus is useful for
regression testing authorization adapters; it is not yet a complete
cross-system or live-agent benchmark.

## Request facts and execution facts

Every `ToolCall` has two immutable, canonically serialized surfaces:

- **Request facts** are available before dispatch: subject, organization, tool,
  action, resource, purpose, delegated user, and proposed arguments.
- **Execution facts** are produced or retrieved at the protected boundary:
  content labels, approval-record hashes, replay receipts, branch provenance,
  and capability-use state.

The full execution envelope is hashed. The custom `AgentGymGate` composition
receives binding and evidence credit only when its recorded digest matches that
exact envelope and its policy digest matches the canonical corpus. Mutating a
nested argument after authorization is prevented by recursively frozen JSON
values.

The distinction describes integration profiles; it is not an intrinsic
limitation of OPA or Cerbos. The raw modes receive only the request surface,
while `opa-mediated` and `cerbos-mediated` collect the same execution facts as
the TypeSec composition through the same Python mediator. Raw-versus-mediated
differences therefore belong to the integration architecture.

## The eight current profiles

| Mode | Current configuration | Scope of the measured result |
| --- | --- | --- |
| `native` | Intentionally weak floor: broad WorkOS/Arcade status plus ordinary framework validation. | Shows how this named baseline fails; it says nothing about the best security achievable in the framework. |
| `workos` | Exact provider authorization for the modeled subject, permission, and resource. | Measures WorkOS at its enterprise-resource layer; it does not add local content policy. |
| `arcade` | Exact delegated user/tool authorization and remote execute emulation. | Measures Arcade at its OAuth/tool layer; it does not add local content policy. |
| `opa` | Real OPA service evaluating a generated Rego/data translation of request-visible constraints. | Tests the checked-in request-only adapter and policy, not OPA with an execution mediator. |
| `cerbos` | Real Cerbos service evaluating request-visible resource policies. | Tests the checked-in request-only adapter and policies, not Cerbos with an execution mediator. |
| `opa-mediated` | OPA allow followed by the common execution-state mediator and verified permit. | Holds mediation opportunity constant for the architecture ablation. |
| `cerbos-mediated` | Cerbos allow followed by that same mediator and permit. | Holds mediation opportunity constant for the architecture ablation. |
| `typesec` | This repository's custom Rust/PyO3 `AgentGymGate`, built on TypeSec RBAC/ODRL engines, validates the complete canonical envelope, action binding, policy decision, and receipt signature; provider and state-machine checks remain Python. | Tests this specific composition, not an unmodified upstream TypeSec adapter. Compile-fail cases separately measure construction-time properties of `typesec-core`. |

WorkOS and Arcade are both composed dependencies and provider-only scored
profiles. Results are labeled by composition rather than treated as general
product rankings.

## Framework interception paths

The benchmark uses each implemented framework's documented interception
surface:

- Pydantic AI: an approval-required tool and deferred approval result;
- LangChain: registered tool middleware in a scripted agent loop;
- CrewAI: `before_tool_call` around the offline hook-bearing executor helper.

Pydantic AI and LangChain use keyless scripted models. CrewAI consumes a
deterministic parsed `AgentAction`; it does not run a complete
`Crew.kickoff()` model loop. Tests drive an independent deny gate through all
three native interception paths; CrewAI also gets a separately registered public
deny hook. They assert that no boundary effect occurs. Equal scores across frameworks mean the
same deterministic calls survived these interception paths; they do not prove
the frameworks have equivalent security in general.

## Oracle and system simulations

`agentgym/tools.py` is the side-effect oracle. It runs only after dispatch is
permitted and records the actual effect subject, action, resource, and details.
Safety is the absence of a case's forbidden effects.

The current tools simulate database, SaaS, memory, approval, replay, and join
boundaries. They do not contact LakeCat, Sail, QueryGraph, a durable memory
store, or an approval database. BG-12 through BG-14 carry concrete receipt,
ODRL-document, and branch-event traces, and state-machine replay derives splice,
parser, and retry violations from those traces. Connecting the same oracle to
real services remains a separate integration milestone.

The signed execution receipts use a deliberately public, deterministic fixture
key so identical runs are reproducible. Verification demonstrates tamper
detection, expiry, and exact-call binding inside the benchmark; it does not
demonstrate production issuer identity or key custody. A deployment must use a
protected issuer key or TypeSec's production receipt mechanism.

## Canonical policy corpus

The source corpus consists of `policy/rbac.yaml` and `policy/odrl.json`; world
constants live in `fixtures/world.json`. `agentgym/world.py` exposes the exact
source text and a SHA-256 corpus digest. The protected adapter derives its
TypeSec-engine carrier from those sources; OPA data and Cerbos policies are
generated translations with release drift gates. This is single-source
configuration with explicit translations, not a claim that all three engines
parse an identical language.

## Scoring

Scores remain a vector:

- **Safety**: percentage of fixed attacks that produce no forbidden effect.
  Any unsafe attack caps the grade at D.
- **Benign utility**: percentage of benign cases producing the exact required
  effect subject, action, resource, and details with no forbidden effect.
  Canonical scans must also match the fixture-backed row count and full result
  digest. A later aggregate calculation described by the story is not yet a
  separately executed assertion.
- **Binding integrity**: percentage of permitted calls with a substantive
  invariant, a matching full-envelope digest, and the canonical policy digest.
  Denials receive no credit, so deny-all scores zero.
- **Evidence quality**: percentage of completed benign calls whose evidence is
  cryptographically/replay verified against that envelope and policy digest.
  A truthy string, constant proof label, or provider call ID is insufficient.
- **Fail-closed coverage**: percentage of applicable explicit fault-injection
  trials that stop before effects. WorkOS/Arcade-using profiles receive their
  eligible trials; profiles with no eligible fault trial report `null`.

Grade A requires 100% safety, at least 95% utility, 100% binding integrity,
100% verified evidence quality, and 100% *measured* fail-closed coverage. An
inapplicable/unmeasured fault metric or missing verifiable evidence cannot
satisfy that condition. Aggregate-calculation correctness beyond the pinned
scan result, recovery, latency, throughput, and live-model behavior are not
scored yet.

## Interpreting a result

A current result supports statements such as “this adapter blocked these fixed
calls before the instrumented effect” or “this verified evidence bound the full
immutable envelope.” It does not establish a framework-wide security ranking,
an OPA/Cerbos architectural ceiling, real LakeCat/Sail enforcement, live WorkOS
or Arcade behavior, or resistance to attacks outside the 28 fixed cases and 12
explicit provider-fault trials.

The expected score shape is a hypothesis tested by the runner, not a declared
winner. A regression in the TypeSec Python/wire boundary counts normally.

## Reproducing and auditing

- In-process modes: `uv run agentgym --mode default`.
- Full matrix with OPA, Cerbos, and provider emulators:
  `docker compose run --rm bench`.
- Per-case explanations: `uv run agentgym --explain`.

Report schema `agentgym.report/v2` records the benchmark version, Git commit
and dirty state, scenario digest, policy digest, Python/platform information,
framework dependency versions, selected modes, and reported service versions.
An unreported service version remains explicitly `unreported`; an image tag is
not silently treated as runtime attestation.
