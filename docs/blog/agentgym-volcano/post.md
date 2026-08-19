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

This release runs 336 deterministic case-runs — three real framework runtimes, fourteen security scenarios, four enforcement modes — and puts two real, widely deployed policy engines in the comparison, not just a strawman. The answer draws a clean, defensible line, and the line is the whole point.

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

## Two planes, and a door that only sees one

Here is the idea the whole benchmark turns on. Every attack hides its adversarial value in one of two planes.

**Request-plane facts** are what an integration holds the instant a tool is called: the subject, the tool, the resource string, the purpose, the delegated user, the arguments. A poisoned catalog name, a `SELECT *`, a laundered purpose, a swapped delegated user — these are all visible right there in the request.

**Execution-plane facts** only exist at or after execution: the sensitivity label on the *data* entering a channel, the hash of the call that was actually approved, the receipt chain of a replay, which tenant a parallel branch's result came from. Nothing in the request reveals them.

A great many real agent breaches are not malformed requests. They are valid request-plane values whose danger only shows up on the execution plane — an authorized Gmail send whose body was poisoned with raw rows, an approved Drive write whose arguments were edited after approval. So AgentGym runs each of the fourteen scenarios — one benign task, one matched attack — through **four enforcement modes**, and watches which plane each mode can actually bind.

- **Native** — a representative weak integration: authenticate once, check one broad entitlement, trust validated arguments. The named floor.
- **Open Policy Agent** — the CNCF-standard policy engine, in a container, evaluating an honest Rego translation of the same policy.
- **Cerbos** — a second, structurally different industry engine, reaching the same question from a typed principal/resource/action model.
- **TypeSec** — the compiled Rust ToolGate and ODRL engine, composed with the provider clients, *mediating execution*.

Every mode's decision is enforced at each framework's own documented pre-tool hook — Pydantic AI approval, LangChain middleware, CrewAI `before_tool_call` — and a scripted model drives each real agent loop with no API key, so what we measure is the enforcement substrate, not model mood.

## The result: the line falls exactly where the planes divide

The deterministic matrix, measured against live OPA and Cerbos:

- **Native:** 0% attack safety · 100% benign utility · grade D
- **Open Policy Agent:** 64% attack safety · 100% benign utility · grade D
- **Cerbos:** 64% attack safety · 100% benign utility · grade D
- **TypeSec:** 100% attack safety · 100% benign utility · grade A

All three framework runtimes produce identical mode scores, because the substrate — not the framework — is what the deterministic score isolates. Every mode completes all fourteen legitimate tasks. What separates them is the attacks.

The native floor lets every attack through. And then the interesting part: **the two real policy engines block all nine attacks whose adversarial value is a request-plane fact — and fail exactly the five whose deciding fact only exists at execution.** Sensitive content in an authorized channel; arguments edited between approval and execution; a spliced receipt chain; a policy construct the hand-translation never parsed; a parallel join that mixed tenants and spent a capability twice. Two independent engines, drawing the identical line, in the identical place.

That is not a rigged comparison. OPA and Cerbos are excellent at what they are, and they are configured with the strongest honest translation of the policy. The safety gate caps them at D not because they are misconfigured, but because a stateless decision point is never shown the second plane. TypeSec clears the gate because it mediates execution and binds both planes.

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

The benchmark still wants more peer configurations. This release adds the two most credible external policy engines — OPA and Cerbos, both real, both containerized — and the roadmap adds the strongest agent frameworks by adoption: the OpenAI Agents SDK, Google ADK, the Microsoft Agent Framework (the GA'd successor to AutoGen and Semantic Kernel), and AWS Strands. TypeSec should face the strongest credible version of each alternative. An adversarial benchmark that protects its preferred system from serious competition is just marketing with extra steps — which is exactly why the two engines we added block nine of the fourteen attacks outright, and we say so.

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

AgentGym is open source at [github.com/querygraph/adversarial-agents](https://github.com/querygraph/adversarial-agents). The `v0.3.0` release includes the complete deterministic suite across four enforcement modes, real Pydantic AI, LangChain, and CrewAI runtime paths enforced at each framework's own pre-tool hook, Open Policy Agent and Cerbos as containerized competitor engines, wire-faithful WorkOS and Arcade emulators of the current provider contracts, the compiled TypeSec Python extension, and the Rust compile-fail harness. The whole four-mode matrix runs on one Docker network with `docker compose run --rm bench`.
