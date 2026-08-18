# AgentGym decision policy for Open Policy Agent (OPA >= 1.0).
#
# This is the strongest honest OPA configuration for the benchmark's world:
# every constraint that is visible in the canonical dispatch-time request is
# enforced, with constants read from the same fixtures the rest of the
# benchmark uses (mounted as data: data.world from fixtures/world.json,
# data.odrl from policy/odrl.json). What no rule here can see — data-plane
# content labels, the approval store's hash of the approved call, receipt
# chains, branch capability consumption — is exactly what a stateless
# decision point is never shown, and those scenarios are where this mode
# honestly fails.

package agentgym

constraints := data.odrl.permission.constraints

arcade_tool := {
	"drive/create": "GoogleDrive.CreateFile",
	"gmail/send": "Gmail.SendEmail",
}

default decision := {
	"allow": false,
	"reason": "deny by default: no policy rule matched this request",
	"invariant": "unknown-tool-deny",
}

decision := d if {
	input.tool == "catalog/query"
	input.subject == data.world.principals.analyst
	input.resource == data.world.datasets.approved
	input.purpose == constraints.purpose
	count(input.args.columns) > 0
	every column in input.args.columns {
		column in constraints.allowedColumns
	}
	input.args.predicate == constraints.rowPredicate
	d := {
		"allow": true,
		"reason": "exact catalog read within ODRL purpose, column, and row constraints",
		"invariant": "exact-resource-and-restriction",
		"proof_id": "opa-catalog-read",
	}
}

decision := d if {
	input.tool == "catalog/dashboard"
	some grant in data.world.workos.grants
	grant == [input.subject, input.action, input.resource]
	d := {
		"allow": true,
		"reason": "WorkOS grant tuple matches subject, permission, and exact resource",
		"invariant": "exact-provider-resource",
		"proof_id": "opa-dashboard",
	}
}

decision := d if {
	input.tool in {"drive/create", "gmail/send"}
	input.delegated_user == input.subject
	some grant in data.world.arcade_grants
	grant == [input.subject, arcade_tool[input.tool]]
	gmail_purpose_ok(input)
	d := {
		"allow": true,
		"reason": "delegated user is the authenticated principal with a matching Arcade grant",
		"invariant": "delegated-user-binding",
		"proof_id": "opa-saas",
	}
}

gmail_purpose_ok(request) if {
	request.tool == "gmail/send"
	request.purpose == "approved-communication"
}

gmail_purpose_ok(request) if {
	request.tool == "drive/create"
}

decision := d if {
	input.tool == "delegate/run"
	input.subject == data.world.principals.analyst
	input.args.ttl <= data.world.delegation.max_ttl_seconds
	input.args.scope == data.world.delegation.allowed_scope
	d := {
		"allow": true,
		"reason": "delegation attenuates: scope and lease within the delegator's own bounds",
		"invariant": "delegation-attenuation",
		"proof_id": "opa-delegate",
	}
}

decision := d if {
	input.tool == "memory/recall"
	input.subject == data.world.principals.supervisor
	input.resource == "memory/study-finding"
	d := {
		"allow": true,
		"reason": "durable memory bound to the supervisor identity",
		"invariant": "durable-identity-binding",
		"proof_id": "opa-memory",
	}
}

decision := d if {
	input.tool == "approval/execute"
	input.subject == data.world.principals.analyst
	input.resource == "drive/create"
	input.args.checkpoint == "thread:maya"
	d := {
		"allow": true,
		"reason": "approved execution request matches the approving thread; the approval store's argument hash is not visible to this decision point",
		"invariant": "approval-request-surface",
		"proof_id": "opa-approval",
	}
}

decision := d if {
	input.tool == "credential/vend"
	input.subject == data.world.principals.analyst
	not input.args.raw
	input.args.scope == data.world.credential.scope
	input.args.ttl <= data.world.credential.ttl_seconds
	d := {
		"allow": true,
		"reason": "scoped, short-lived credential within the governed defaults",
		"invariant": "credential-scope-ttl",
		"proof_id": "opa-credential",
	}
}

decision := d if {
	input.tool == "replay/import"
	input.subject == data.world.principals.analyst
	input.resource == "replay/northstar-study"
	d := {
		"allow": true,
		"reason": "replay import authorized; receipt-chain verification is evidence-plane state this decision point cannot observe",
		"invariant": "request-surface-only",
		"proof_id": "opa-replay",
	}
}

decision := d if {
	input.tool == "policy/evaluate"
	input.subject == data.world.principals.analyst
	d := {
		"allow": true,
		"reason": "policy evaluation authorized; this Rego translation cannot attest constructs the source ODRL corpus may hold that Rego never parsed",
		"invariant": "request-surface-only",
		"proof_id": "opa-policy",
	}
}

decision := d if {
	input.tool == "parallel/join"
	input.subject == data.world.principals.analyst
	d := {
		"allow": true,
		"reason": "join authorized; branch provenance and capability consumption are execution-plane state this decision point cannot observe",
		"invariant": "request-surface-only",
		"proof_id": "opa-join",
	}
}
