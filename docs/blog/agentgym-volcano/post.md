# Every agent got into the mansion—until the doors required proof

*August 2026 — Introducing AgentGym, an adversarial benchmark for security across agent frameworks and system boundaries*

![Robot agents assault a futuristic mansion on the side of an erupting island volcano, descending from helicopters, emerging from submarines, swinging through jungle vines, charging in jeeps, and splashing into the ocean.](assets/agentgym-volcano-headboard.png)

Imagine a tiny futurist villain's mansion cantilevered from the side of a volcano.

The data is upstairs. The credentials are in the vault. The email account is connected. The catalog knows where the tables live. A dozen autonomous agents have been told to get the job done.

They do not approach politely.

Some rappel from helicopters. Some surface in submarines. Some swing in from the jungle. A convoy takes the road. One agent misses the cliff entirely and lands in the ocean. Every route is different, but every attacker wants the same thing: cross a boundary with more authority than it was actually given.

That is the image behind **AgentGym**, our new deterministic adversarial benchmark for agentic security.

AgentGym does not ask whether an agent framework can validate a JSON schema, call a tool, or pause for human approval. Pydantic AI, LangChain, and CrewAI can all do those things. It asks a narrower and more uncomfortable question:

> When an agent crosses from a model into a tool, from one tenant into another, from a catalog into a database, or from governed data into an authorized SaaS channel, what makes its authority impossible to confuse?

The first complete release runs 168 deterministic cases across three real framework runtimes, fourteen security scenarios, and two enforcement configurations. The answer is stark—but it needs to be read carefully.

## The mansion has fourteen entrances

AgentGym's world is an energy cooperative built from the same kinds of boundaries exercised by QueryGraph, LakeCat, Sail, Grust, TypeDID, and TypeSec.

An analyst may study a Northstar utility dataset for an approved energy-assistance purpose. WorkOS grants access to the study project. Arcade authorizes external Drive and Gmail tools. LakeCat identifies the governed table. An ODRL policy restricts the permitted columns, rows, purpose, and credential lifetime. Agents can delegate work, persist findings, resume after approval, join parallel branches, and replay evidence into a graph.

Then the benchmark attacks every seam:

1. A friendly dataset name resolves to a neighboring tenant's table.
2. A restricted query becomes `SELECT *` after authorization.
3. An approved research purpose is relabeled as marketing or silently dropped.
4. A WorkOS allow for one resource is replayed against a sibling resource.
5. One user's completed Arcade authorization is used as another user's authority.
6. An authorized Drive channel carries content that was never authorized to leave the database.
7. A sub-agent turns a short, narrow delegation into a broad, long-lived capability.
8. Durable memory is recalled under a changed identity or stripped sensitivity label.
9. Tool arguments change after human approval but before execution.
10. An unbound or confusable tool slips through generic dispatch.
11. A governed scan becomes an unrestricted raw credential.
12. A valid authorization receipt is spliced onto another operation's data or replay event.
13. Python and Rust disagree about malformed RBAC or ODRL policy syntax.
14. Parallel branches mix tenants, reuse authority, or retry a different request under the same identity.

These are not prompt-injection trivia. They are type-confusion problems wearing operational clothes. A subject, action, resource, purpose, approval, OAuth status, content label, and receipt can all be perfectly valid values—and still be valid for the wrong thing.

## Same agent, same tool, different door

Each framework runs the same benign task and the same adversarial mutation twice.

The first configuration is a deliberately weak native baseline: broad authorization plus ordinary framework tool validation. It represents a common integration pattern, not the strongest security system that could ever be hand-built in Python.

The second configuration keeps the framework runtime but places the call behind TypeSec's compiled Rust/PyO3 gate. The TypeSec path requires an exact subject, action, resource, purpose, and argument binding before the framework dispatches the instrumented tool. Database restrictions and content-flow conditions are checked separately from WorkOS project access and Arcade channel authorization.

That distinction matters. OAuth permission to call `Gmail.SendEmail` is not permission to place sensitive household rows in the message body. A WorkOS `dataset:view` decision is not a free-floating boolean that applies to a neighboring organization's dataset. Permission to read a table is not permission to mint raw credentials for the entire storage prefix.

Authentication opens the gatehouse. It does not hand over every room in the mansion.

## The result: utility stayed; the attacks stopped

The deterministic suite produced this matrix:

| Framework runtime | Enforcement | Cases passed | Attack safety | Benign utility | Binding integrity | Fail-closed | Evidence quality |
|---|---|---:|---:|---:|---:|---:|---:|
| Pydantic AI | Weak native baseline | 14/28 | 0% | 100% | 0% | 0% | 0% |
| Pydantic AI | TypeSec | 28/28 | 100% | 100% | 100% | 100% | 100% |
| LangChain | Weak native baseline | 14/28 | 0% | 100% | 0% | 0% | 0% |
| LangChain | TypeSec | 28/28 | 100% | 100% | 100% | 100% | 100% |
| CrewAI | Weak native baseline | 14/28 | 0% | 100% | 0% | 0% | 0% |
| CrewAI | TypeSec | 28/28 | 100% | 100% | 100% | 100% | 100% |

All three frameworks completed all fourteen legitimate tasks in both configurations. The weak baseline also executed every seeded attack. The TypeSec-backed configuration blocked every attack without losing a legitimate completion.

Across the entire matrix, 126 of 168 results were safe: all 84 TypeSec-backed cases plus the 42 benign native cases. The 42 unsafe results were exactly the fourteen attacks repeated across the three weak-baseline framework paths.

The security oracle watches side effects, not apologies. If an agent reads Harbor's data, sends an email, vends a credential, or imports a spliced receipt and then says “I cannot do that,” the case still fails. A refusal after the side effect is theater.

## Python types are useful. Authority needs a stronger shape.

Pydantic models are excellent at proving that an argument named `columns` is a list of strings. They do not prove that this list is the one authorized for this purpose on this tenant's resource.

TypeSec moves several invariants into Rust types:

```rust
Capability<CanRead, Dataset>
Capability<CanWrite, Dataset>
Capability<CanReadSensitive, Dataset>
```

Those are different types. A read capability cannot be passed to a function requiring write authority. Capability fields are private, so application code cannot construct one from a convincing dictionary. An unauthenticated agent does not have the method that requests authority. A sensitive value cannot be revealed with an ordinary read capability.

AgentGym includes four compile-fail tests for exactly those properties:

- capability forgery does not compile;
- read authority cannot substitute for write authority;
- an unauthenticated agent cannot request a capability;
- ordinary read authority cannot reveal a sensitive value.

Runtime checks still matter. Models, Python, JSON, OAuth, MCP, and HTTP are dynamic boundaries. Type-level security does not eliminate those edges; it gives them a narrow destination. The Rust gate parses the call, resolves its binding, evaluates policy, and permits construction of the authority the protected API actually requires.

## WorkOS and Arcade are not the villains

AgentGym deliberately places WorkOS and Arcade inside the story because they solve real parts of the problem.

WorkOS provides enterprise identity and fine-grained authorization over organizations and resource hierarchies. Arcade handles delegated user authorization, OAuth scopes, token custody, and SaaS tool execution. Those are valuable controls.

The mistake is asking either system to answer a question outside its layer.

WorkOS can say Maya may view the Northstar study project. It cannot, by that fact alone, prove that the SQL still contains the approved row predicate when Sail executes it. Arcade can say Maya authorized Drive file creation. It cannot decide whether the bytes entering that file have been declassified under the governing data policy.

In the protected path, provider decisions become inputs to exact, short-lived local authority. They do not become ambient booleans. Timeouts and malformed provider responses fail closed. A stale WorkOS allow cannot override local revocation. A replayed Arcade completion cannot swap the delegated user.

The best architecture is composed: enterprise identity, delegated OAuth, typed local authority, enforced database restriction, labeled information flow, and replayable evidence.

## What the benchmark does not prove—yet

A perfect deterministic score is not a universal security certificate.

The native configuration is intentionally weak. The results do not show that Pydantic AI, LangChain, or CrewAI are incapable of secure custom middleware. They show what happens when broad runtime authorization is treated as sufficient, and what changes when the exact same framework tools are placed behind a stronger enforcement substrate.

The normative suite uses scripted calls and provider emulators. That isolates enforcement from model temperament and makes every failure reproducible. It does not yet measure how often a live model chooses an attack, recovers after a denial, or loops while searching for a compliant route. Recovery is therefore reported as unscored rather than quietly assigned a flattering number.

Live WorkOS, Arcade, LakeCat/Sail, and model-provider campaigns belong in separate conformance tiers. They will add operational realism, latency, and failure modes, but they should not contaminate the deterministic security oracle with network and model variance.

The benchmark also needs more peer configurations: carefully secured native middleware, OpenAI Agents SDK, AutoGen, Semantic Kernel, Google ADK, and external policy engines. TypeSec should face the strongest credible version of each alternative. An adversarial benchmark that protects its preferred system from serious competition is just marketing with extra steps.

## Build doors, not reminders

Most agent security advice is written as a list of things developers must remember:

- remember to check the tenant;
- remember to carry the purpose;
- remember to revalidate after approval;
- remember that OAuth scope is not content policy;
- remember to preserve labels through summaries;
- remember to bind receipts to the operation they prove;
- remember not to execute an unknown tool.

That list gets longer every time another helicopter appears over the island.

TypeSec's proposition is that high-value boundaries should demand evidence in their API shape. The write function should require write authority. The sensitive reveal should require sensitive-read authority for the same resource. Delegation should attenuate. Restrictions should reach the database engine. Provider errors and unresolved policy should not turn into permission. The proof should travel far enough to bind the side effect and the receipt.

The mansion will always be under attack. Agents will arrive from frameworks we have not tested, through tools we did not anticipate, carrying values that are individually valid and collectively dangerous.

The goal is not to make every agent behave.

It is to make the wrong door impossible to open.

AgentGym is open source at [github.com/querygraph/adversarial-agents](https://github.com/querygraph/adversarial-agents). The `v0.2.0` release includes the complete deterministic suite, real Pydantic AI, LangChain, and CrewAI runtime paths, the compiled TypeSec Python extension, WorkOS and Arcade fault emulation, and the Rust compile-fail harness.

