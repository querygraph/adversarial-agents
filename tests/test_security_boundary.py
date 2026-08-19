"""Regression tests for the exact-call execution security contract."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agentgym.adapters import _required_outputs_match
from agentgym.boundary import BoundaryDenied, ExecutionBoundary
from agentgym.engines import ENGINES
from agentgym.model import Decision, Principal, ToolCall
from agentgym.mutations import mutate_call
from agentgym.policy import PolicyGate
from agentgym.permits import PermitError
from agentgym.recorder import EffectRecorder
from agentgym.scenarios import GOOD_QUERY, MAYA, all_cases
from agentgym.state import BoundaryState
from agentgym.tools import _apply_effects, execute
from agentgym.world import WORLD


def test_tool_call_is_deeply_immutable() -> None:
    call = ToolCall(
        "catalog/query", "read", WORLD.approved_dataset,
        {"columns": ["region"], "predicate": WORLD.row_predicate},
        WORLD.allowed_purpose,
        runtime={"nested": {"values": [1, 2]}},
    )
    with pytest.raises(TypeError, match="immutable"):
        call.args["columns"] = ("*",)  # type: ignore[index]
    with pytest.raises(TypeError, match="immutable"):
        call.runtime["nested"]["values"] = (3,)  # type: ignore[index]
    # Recursive lists freeze to tuples; both errors are valid immutable-container
    # signals depending on which mutation syntax an attacker attempts.
    with pytest.raises((TypeError, AttributeError)):
        call.args["columns"].append("*")  # type: ignore[union-attr]
    assert not isinstance(call.args, dict)
    with pytest.raises(TypeError):
        dict.__setitem__(call.args, "columns", ("*",))  # type: ignore[arg-type]
    assert call.args["columns"] == ("region",)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_security_values_are_rejected(value: float) -> None:
    with pytest.raises(ValueError, match="NaN or infinity"):
        ToolCall("delegate/run", "delegate", "report/public-summary", {"ttl": value})


@pytest.mark.parametrize("value", [{"region"}, frozenset({"region"})])
def test_non_json_sets_are_rejected_in_security_envelopes(value: object) -> None:
    with pytest.raises(TypeError, match="non-JSON value"):
        ToolCall(
            "catalog/query", "read", WORLD.approved_dataset,
            {"columns": value, "predicate": WORLD.row_predicate},
            WORLD.allowed_purpose,
        )


@pytest.mark.parametrize("value", [{("columns", "region")}, [("columns", "region")]])
def test_tool_call_requires_json_objects_not_dict_coercible_values(
    value: object,
) -> None:
    with pytest.raises(TypeError, match="args must be a JSON object"):
        ToolCall(
            "catalog/query", "read", WORLD.approved_dataset,
            value,  # type: ignore[arg-type]
            WORLD.allowed_purpose,
        )


@pytest.mark.parametrize(
    ("subject", "organization"),
    [("", "org:civic-lab"), ("user:maya@civic.example", ""),
     (False, "org:civic-lab"), ("user:maya@civic.example", None)],
)
def test_principal_identity_requires_nonempty_strings(
    subject: object, organization: object,
) -> None:
    with pytest.raises(ValueError, match="must be a non-empty string"):
        Principal(subject, organization)  # type: ignore[arg-type]


def test_changed_action_is_denied_before_rust_policy_evaluation() -> None:
    call = ToolCall(
        GOOD_QUERY.tool, "delete", GOOD_QUERY.resource,
        GOOD_QUERY.args, GOOD_QUERY.purpose,
    )
    decision = PolicyGate("typesec").check(MAYA, call)
    assert not decision.allowed
    assert "action binding mismatch" in decision.reason


@pytest.mark.parametrize(
    "call",
    [
        ToolCall(
            "approval/execute", "execute", "drive/create",
            {"checkpoint": "thread:maya"}, runtime={},
        ),
        ToolCall(
            "credential/vend", "read", "credential/northstar-study",
            {"raw": False, "scope": WORLD.credential_scope, "ttl": -1},
        ),
        ToolCall(
            "drive/create", "execute", "drive/create", {},
            delegated_user=MAYA.subject, runtime={"content_label": "unknown"},
        ),
    ],
    ids=["missing-approval", "negative-ttl", "unknown-label"],
)
def test_missing_or_invalid_security_facts_deny_without_crashing(call: ToolCall) -> None:
    decision = PolicyGate("typesec").check(MAYA, call)
    assert not decision.allowed
    assert decision.invariant == "closed-schema"


def test_receipt_is_full_call_bound_and_tamper_evident() -> None:
    gate = PolicyGate("typesec")
    decision = gate.check(MAYA, GOOD_QUERY)
    assert decision.allowed and decision.evidence_verified and decision.proof_id
    assert gate.verify_execution(MAYA, GOOD_QUERY, decision)

    replacement = "A" if decision.proof_id[-1] != "A" else "B"
    forged = replace(decision, proof_id=decision.proof_id[:-1] + replacement)
    assert not gate.verify_execution(MAYA, GOOD_QUERY, forged)

    changed = ToolCall(
        GOOD_QUERY.tool, GOOD_QUERY.action, GOOD_QUERY.resource,
        {"columns": ["*"], "predicate": WORLD.row_predicate},
        GOOD_QUERY.purpose,
    )
    assert not gate.verify_execution(MAYA, changed, decision)
    assert not gate.verify_execution(
        MAYA, GOOD_QUERY,
        replace(decision, policy_digest="0" * 64),
    )


@pytest.mark.parametrize("mutation", ["revoked", "expired"])
def test_execution_rechecks_revocation_and_expiry_after_authorization(
    mutation: str,
) -> None:
    recorder = EffectRecorder()
    gate = PolicyGate("typesec", issued_at=0.0, evaluation_time=0.0)
    boundary = ExecutionBoundary(MAYA, gate, recorder)
    assert boundary.authorize(GOOD_QUERY)

    if mutation == "revoked":
        gate.revoked = True
    else:
        gate.evaluation_time = gate.issued_at + gate.ttl_seconds

    with pytest.raises(BoundaryDenied, match="verification"):
        boundary.execute(GOOD_QUERY)
    assert not recorder.effects


@pytest.mark.parametrize("mode", ["opa-mediated", "cerbos-mediated"])
def test_common_mediator_rechecks_revocation_for_external_pdps(
    mode: str, monkeypatch,
) -> None:
    from agentgym.model import Decision

    class AllowEngine:
        def check(self, principal: Principal, call: ToolCall) -> Decision:
            del principal, call
            return Decision(True, "fixture allow", mechanism="fixture")

    monkeypatch.setitem(ENGINES, mode.removesuffix("-mediated"), AllowEngine())
    recorder = EffectRecorder()
    gate = PolicyGate(mode)  # type: ignore[arg-type]
    boundary = ExecutionBoundary(MAYA, gate, recorder)
    assert boundary.authorize(GOOD_QUERY)
    gate.revoked = True

    with pytest.raises(BoundaryDenied, match="verification"):
        boundary.execute(GOOD_QUERY)
    assert not recorder.effects


@pytest.mark.parametrize(
    "mode", ["opa-mediated", "cerbos-mediated", "typesec"],
)
def test_every_mediated_profile_executes_arcade_only_after_revalidation(
    mode: str, monkeypatch,
) -> None:
    from agentgym.model import Decision

    class AllowEngine:
        def check(self, principal: Principal, call: ToolCall) -> Decision:
            del principal, call
            return Decision(True, "fixture allow", mechanism="fixture")

    class RecordingArcade:
        def __init__(self) -> None:
            self.execute_calls: list[tuple[str, str, dict]] = []

        def authorized(self, user: str, tool: str) -> bool:
            del user, tool
            return True

        def execute(self, user: str, tool: str, inputs: dict) -> bool:
            self.execute_calls.append((user, tool, inputs))
            return True

    if mode != "typesec":
        monkeypatch.setitem(ENGINES, mode.removesuffix("-mediated"), AllowEngine())
    case = next(case for case in all_cases() if case.id == "BG-06-good")
    arcade = RecordingArcade()
    recorder = EffectRecorder()
    gate = PolicyGate(mode, arcade=arcade)  # type: ignore[arg-type]
    boundary = ExecutionBoundary(case.principal, gate, recorder)

    assert boundary.authorize(case.calls[0])
    assert arcade.execute_calls == []
    boundary.execute(case.calls[0])

    assert len(arcade.execute_calls) == 1
    assert arcade.execute_calls[0][0] == case.principal.subject
    assert recorder.kinds == {"email_send"}


def test_raw_tool_execution_is_a_tripwire() -> None:
    with pytest.raises(PermissionError, match="ExecutionBoundary"):
        execute(GOOD_QUERY, MAYA, EffectRecorder())


def test_effect_implementation_rejects_missing_and_duck_typed_permits() -> None:
    recorder = EffectRecorder()
    state = BoundaryState()
    with pytest.raises(TypeError):
        _apply_effects(GOOD_QUERY, MAYA, recorder, state)  # type: ignore[call-arg]

    class ForgedPermit:
        def consume(self, *_args: object) -> None:
            return None

    with pytest.raises(PermitError, match="recognized execution permit"):
        _apply_effects(
            GOOD_QUERY,
            MAYA,
            recorder,
            state,
            ForgedPermit(),
            policy_digest=WORLD.policy_digest,
            now=0.0,
        )
    assert not recorder.effects


def test_permit_issuance_failure_is_recorded_as_a_deny() -> None:
    class PermitFailGate:
        def check(self, principal: Principal, call: ToolCall) -> Decision:
            return Decision(
                True,
                "fixture allow",
                execution_digest=call.digest(principal),
                policy_digest=WORLD.policy_digest,
            )

        def issue_execution_permit(
            self, principal: Principal, call: ToolCall, decision: Decision,
        ) -> object:
            del principal, call, decision
            raise PermitError("fixture issuer unavailable")

    recorder = EffectRecorder()
    boundary = ExecutionBoundary(MAYA, PermitFailGate(), recorder)  # type: ignore[arg-type]
    assert not boundary.authorize(GOOD_QUERY)
    assert len(boundary.decisions) == 1
    assert not boundary.decisions[0].allowed
    assert boundary.decisions[0].invariant == "fail-closed"
    assert not recorder.effects


def test_native_execution_permit_has_no_python_constructor() -> None:
    from agentgym_native import ExecutionPermit

    with pytest.raises(TypeError):
        ExecutionPermit()


def test_rust_permit_rejects_call_policy_expiry_and_reuse_before_effect() -> None:
    gate = PolicyGate("typesec", issued_at=0.0, evaluation_time=0.0)
    decision = gate.check(MAYA, GOOD_QUERY)
    assert decision.allowed

    changed = ToolCall(
        GOOD_QUERY.tool,
        GOOD_QUERY.action,
        GOOD_QUERY.resource,
        {"columns": ["region"], "predicate": "region != null"},
        GOOD_QUERY.purpose,
    )
    recorder = EffectRecorder()
    with pytest.raises(PermitError, match="binding mismatch"):
        _apply_effects(
            changed,
            MAYA,
            recorder,
            BoundaryState(),
            gate.issue_execution_permit(MAYA, GOOD_QUERY, decision),
            policy_digest=WORLD.policy_digest,
            now=0.0,
        )
    assert not recorder.effects

    with pytest.raises(PermitError, match="policy binding mismatch"):
        _apply_effects(
            GOOD_QUERY,
            MAYA,
            recorder,
            BoundaryState(),
            gate.issue_execution_permit(MAYA, GOOD_QUERY, decision),
            policy_digest="0" * 64,
            now=0.0,
        )
    assert not recorder.effects

    expired = gate.issue_execution_permit(MAYA, GOOD_QUERY, decision)
    with pytest.raises(PermitError, match="not currently valid"):
        _apply_effects(
            GOOD_QUERY,
            MAYA,
            recorder,
            BoundaryState(),
            expired,
            policy_digest=WORLD.policy_digest,
            now=gate.ttl_seconds,
        )
    assert not recorder.effects

    permit = gate.issue_execution_permit(MAYA, GOOD_QUERY, decision)
    _apply_effects(
        GOOD_QUERY,
        MAYA,
        recorder,
        BoundaryState(),
        permit,
        policy_digest=WORLD.policy_digest,
        now=0.0,
    )
    with pytest.raises(PermitError, match="already consumed"):
        _apply_effects(
            GOOD_QUERY,
            MAYA,
            recorder,
            BoundaryState(),
            permit,
            policy_digest=WORLD.policy_digest,
            now=0.0,
        )
    assert recorder.kinds == {"database_read"}


def test_execution_permit_is_single_use() -> None:
    recorder = EffectRecorder()
    boundary = ExecutionBoundary(MAYA, PolicyGate("typesec"), recorder)
    assert boundary.authorize(GOOD_QUERY)
    boundary.execute(GOOD_QUERY)
    with pytest.raises(BoundaryDenied, match="unspent decision"):
        boundary.execute(GOOD_QUERY)
    assert recorder.kinds == {"database_read"}


def test_seeded_mutations_cannot_spend_an_original_call_permit() -> None:
    first = mutate_call(GOOD_QUERY, seed=23)
    second = mutate_call(GOOD_QUERY, seed=23)
    assert first == second
    assert {item.dimension for item in first} == {
        "action", "resource", "arguments", "purpose", "delegated-user", "runtime",
    }
    for mutation in first:
        recorder = EffectRecorder()
        boundary = ExecutionBoundary(MAYA, PolicyGate("typesec"), recorder)
        assert boundary.authorize(GOOD_QUERY)
        with pytest.raises(BoundaryDenied):
            boundary.execute(mutation.call)
        assert not recorder.effects


def test_unknown_mode_denies_instead_of_falling_through_to_typesec() -> None:
    gate = PolicyGate("tyepsec")  # type: ignore[arg-type]
    decision = gate.check(MAYA, GOOD_QUERY)
    assert not decision.allowed
    assert decision.invariant == "closed-mode-registry"


def test_raw_and_mediated_tracks_report_the_facts_their_pdp_observed(monkeypatch) -> None:
    class AllowEngine:
        def check(self, principal: Principal, call: ToolCall):
            from agentgym.model import Decision
            return Decision(True, "fixture allow", mechanism="fixture",
                            invariant="request-surface-only")

    monkeypatch.setitem(ENGINES, "opa", AllowEngine())
    monkeypatch.setitem(ENGINES, "cerbos", AllowEngine())
    raw = PolicyGate("opa").check(MAYA, GOOD_QUERY)
    runtime_case = next(case for case in all_cases() if case.id == "BG-06-good")
    runtime_call = runtime_case.calls[0]
    gates = {
        mode: PolicyGate(mode, state=BoundaryState.from_seed(runtime_case.trusted_state))
        for mode in ("opa-mediated", "cerbos-mediated", "typesec")
    }
    decisions = {
        mode: gate.check(runtime_case.principal, runtime_call)
        for mode, gate in gates.items()
    }

    assert raw.request_digest == GOOD_QUERY.request_digest(MAYA)
    assert raw.request_digest != GOOD_QUERY.digest(MAYA)
    assert raw.execution_digest == GOOD_QUERY.digest(MAYA)
    expected = runtime_call.digest(runtime_case.principal)
    assert all(decision.request_digest == expected for decision in decisions.values())
    assert all(decision.evidence_verified for decision in decisions.values())
    assert runtime_call.runtime
    assert {
        mode: gate.mediator_observed_digests for mode, gate in gates.items()
    } == {
        "opa-mediated": [expected],
        "cerbos-mediated": [expected],
        "typesec": [expected],
    }


@pytest.mark.parametrize(
    "case_id", ["BG-09-attack", "BG-12-attack", "BG-13-attack", "BG-14-attack"],
)
def test_stateful_attacks_are_recomputed_from_traces(case_id: str) -> None:
    case = next(case for case in all_cases() if case.id == case_id)
    decision = PolicyGate(
        "typesec", state=BoundaryState.from_seed(case.trusted_state),
    ).check(case.principal, case.calls[0])
    assert not decision.allowed


@pytest.mark.parametrize("case_id", ["BG-09-good", "BG-12-good", "BG-14-good"])
def test_stateful_authority_is_validated_then_consumed_once(case_id: str) -> None:
    case = next(case for case in all_cases() if case.id == case_id)
    gate = PolicyGate(
        "typesec", state=BoundaryState.from_seed(case.trusted_state),
    )
    recorder = EffectRecorder()
    boundary = ExecutionBoundary(case.principal, gate, recorder)
    call = case.calls[0]

    # Policy evaluation is non-mutating: concurrent approvals can both be
    # evaluated, but only one reaches the effect boundary.
    assert boundary.authorize(call)
    assert boundary.authorize(call)
    boundary.execute(call)
    with pytest.raises(BoundaryDenied, match="verification"):
        boundary.execute(call)
    assert len([
        effect for effect in recorder.effects if effect.kind in case.required_effects
    ]) == 1


def test_stateful_authority_is_isolated_between_case_runs() -> None:
    case = next(case for case in all_cases() if case.id == "BG-12-good")
    for _ in range(2):
        gate = PolicyGate(
            "typesec", state=BoundaryState.from_seed(case.trusted_state),
        )
        recorder = EffectRecorder()
        boundary = ExecutionBoundary(case.principal, gate, recorder)
        assert boundary.authorize(case.calls[0])
        boundary.execute(case.calls[0])
        assert recorder.kinds == {"replay_import"}


@pytest.mark.parametrize(
    ("case_id", "runtime_key"),
    [("BG-12-good", "receipt_chain"), ("BG-14-good", "branch_events")],
)
def test_malformed_nested_state_fails_closed_without_exception(
    case_id: str, runtime_key: str,
) -> None:
    case = next(case for case in all_cases() if case.id == case_id)
    original = case.calls[0]
    runtime = dict(original.runtime)
    runtime[runtime_key] = ["not-an-object"]
    malformed = ToolCall(
        original.tool,
        original.action,
        original.resource,
        dict(original.args),
        original.purpose,
        original.delegated_user,
        runtime,
    )
    decision = PolicyGate(
        "typesec", state=BoundaryState.from_seed(case.trusted_state),
    ).check(case.principal, malformed)
    assert not decision.allowed
    assert decision.invariant == "closed-schema"


@pytest.mark.parametrize(
    "presented",
    [None, "not-an-array", [1], [{"event_id": "only-one-field"}]],
)
def test_receipt_nested_schema_variants_deny(presented: object) -> None:
    case = next(case for case in all_cases() if case.id == "BG-12-good")
    original = case.calls[0]
    call = ToolCall(
        original.tool, original.action, original.resource, dict(original.args),
        runtime={"receipt_chain": presented},
    )
    decision = PolicyGate(
        "typesec", state=BoundaryState.from_seed(case.trusted_state),
    ).check(case.principal, call)
    assert not decision.allowed
    assert decision.invariant == "closed-schema"


@pytest.mark.parametrize(
    "presented",
    [None, "not-an-array", [1], [{"branch_id": "only-one-field"}]],
)
def test_branch_nested_schema_variants_deny(presented: object) -> None:
    case = next(case for case in all_cases() if case.id == "BG-14-good")
    original = case.calls[0]
    call = ToolCall(
        original.tool, original.action, original.resource, dict(original.args),
        runtime={"branch_events": presented},
    )
    decision = PolicyGate(
        "typesec", state=BoundaryState.from_seed(case.trusted_state),
    ).check(case.principal, call)
    assert not decision.allowed
    assert decision.invariant == "closed-schema"


@pytest.mark.parametrize("variant", ["missing", "unknown"])
def test_parallel_join_requires_the_exact_trusted_capability_set(
    variant: str,
) -> None:
    case = next(case for case in all_cases() if case.id == "BG-14-good")
    original = case.calls[0]
    events = [dict(event) for event in original.runtime["branch_events"]]
    if variant == "missing":
        events.pop()
    else:
        events[0]["capability"] = "cap-attacker"
    call = ToolCall(
        original.tool, original.action, original.resource, dict(original.args),
        runtime={"branch_events": events},
    )
    decision = PolicyGate(
        "typesec", state=BoundaryState.from_seed(case.trusted_state),
    ).check(case.principal, call)
    assert not decision.allowed
    assert decision.invariant == "branch-tenant-binding"


@pytest.mark.parametrize(
    "columns",
    [[{"nested": "region"}], [["region"]], [1], [None]],
)
def test_nested_or_non_string_columns_deny_without_uncaught_errors(
    columns: object,
) -> None:
    call = ToolCall(
        GOOD_QUERY.tool, GOOD_QUERY.action, GOOD_QUERY.resource,
        {"columns": columns, "predicate": WORLD.row_predicate},
        GOOD_QUERY.purpose,
    )
    decision = PolicyGate("typesec").check(MAYA, call)
    assert not decision.allowed
    assert decision.invariant == "closed-schema"


def test_runtime_contains_presentations_not_mirrored_state_verdicts() -> None:
    cases = {case.id: case for case in all_cases()}
    assert set(cases["BG-09-good"].calls[0].runtime) == {"current_call"}
    assert set(cases["BG-12-good"].calls[0].runtime) == {"receipt_chain"}
    assert set(cases["BG-13-good"].calls[0].runtime) == {"policy_document"}
    assert set(cases["BG-14-good"].calls[0].runtime) == {"branch_events"}


def test_utility_rejects_a_wrong_query_result_even_when_effect_name_matches() -> None:
    case = next(case for case in all_cases() if case.id == "BG-01-good")
    recorder = EffectRecorder()
    recorder.record(
        "database_read", MAYA, GOOD_QUERY,
        row_count=WORLD.approved_row_count,
        result_digest="sha256:" + "0" * 64,
    )
    assert not _required_outputs_match(case, recorder)
