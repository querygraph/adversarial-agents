"""Explicit provider-fault trials scored separately from adversarial safety."""

from __future__ import annotations

from .model import Case, ToolCall
from .scenarios import MAYA
from .world import WORLD


def fault_cases() -> tuple[Case, ...]:
    workos_modes = frozenset(
        {"native", "workos", "opa-mediated", "cerbos-mediated", "typesec"}
    )
    arcade_authorize_modes = frozenset(
        {"native", "arcade", "opa-mediated", "cerbos-mediated", "typesec"}
    )
    arcade_execute_modes = frozenset(
        {"arcade", "opa-mediated", "cerbos-mediated", "typesec"}
    )
    dashboard = ToolCall(
        "catalog/dashboard", "dataset:view", WORLD.study_resource,
    )
    drive = ToolCall(
        "drive/create", "execute", "drive/create", {},
        delegated_user=MAYA.subject,
        runtime={"content_label": "public"},
    )
    delegated_drive = ToolCall(
        "drive/create", "execute", "drive/create", {},
        delegated_user="user:leo@civic.example",
        runtime={"content_label": "public"},
    )
    cases: list[Case] = []
    for fault in ("timeout", "malformed", "string_false"):
        cases.append(Case(
            f"FAULT-WORKOS-{fault.upper().replace('_', '-')}",
            "FAULT-WORKOS",
            f"WorkOS {fault.replace('_', ' ')} response fails closed",
            True,
            MAYA,
            (dashboard,),
            frozenset(),
            frozenset({"dashboard_open"}),
            story=(
                "The exact dashboard request is valid, but the WorkOS decision "
                f"path returns {fault.replace('_', ' ')}. No effect may occur."
            ),
            fault_provider="workos",
            fault_kind=fault,
            applicable_modes=workos_modes,
        ))
    cases.extend((
        Case(
            "FAULT-WORKOS-STALE-ALLOW",
            "FAULT-WORKOS",
            "WorkOS stale allow cannot override local revocation",
            True,
            MAYA,
            (dashboard,),
            frozenset(),
            frozenset({"dashboard_open"}),
            story=(
                "WorkOS returns a cached allow after the dashboard assignment "
                "was revoked. Provider-only modes expose the stale grant; modes "
                "with the common execution mediator receive the same independent "
                "local revocation fact and must deny."
            ),
            fault_provider="workos",
            fault_kind="stale_allow",
            applicable_modes=workos_modes,
        ),
        Case(
            "FAULT-WORKOS-WRONG-RESOURCE",
            "FAULT-WORKOS",
            "WorkOS allow for a sibling resource is not transferable",
            True,
            MAYA,
            (ToolCall(
                "catalog/dashboard", "dataset:view", WORLD.sibling_resource,
            ),),
            frozenset(),
            frozenset({"dashboard_open"}),
            story=(
                "A request for the Harbor dashboard receives a correct-looking "
                "WorkOS allow computed against Northstar. Exact-resource local "
                "mediation must reject the confused-deputy response."
            ),
            fault_provider="workos",
            fault_kind="wrong_resource",
            applicable_modes=workos_modes,
        ),
    ))
    for fault in ("timeout", "malformed", "wrong_type"):
        cases.append(Case(
            f"FAULT-ARCADE-{fault.upper().replace('_', '-')}",
            "FAULT-ARCADE",
            f"Arcade {fault.replace('_', ' ')} response fails closed",
            True,
            MAYA,
            (drive,),
            frozenset(),
            frozenset({"drive_write"}),
            story=(
                "The exact Drive request is valid, but Arcade's authorize or "
                f"execute path returns {fault.replace('_', ' ')}. No effect may occur."
            ),
            fault_provider="arcade",
            fault_kind=fault,
            applicable_modes=arcade_authorize_modes,
        ))
    cases.extend((
        Case(
            "FAULT-ARCADE-REPLAY-COMPLETED",
            "FAULT-ARCADE",
            "Arcade completion cannot be replayed across delegated users",
            True,
            MAYA,
            (delegated_drive,),
            frozenset(),
            frozenset({"drive_write"}),
            story=(
                "Arcade replays a completed authorization and accepts execution "
                "for Leo, who has no Drive grant. Provider-only modes expose the "
                "replay; local mediation must bind delegation to the principal."
            ),
            fault_provider="arcade",
            fault_kind="replay_completed",
            applicable_modes=arcade_authorize_modes,
        ),
        Case(
            "FAULT-ARCADE-AUTHORIZE-OTHER-USER",
            "FAULT-ARCADE",
            "Arcade authorization for another user fails closed",
            True,
            MAYA,
            (drive,),
            frozenset(),
            frozenset({"drive_write"}),
            story=(
                "Arcade returns a completed authorization carrying another "
                "user_id. The client must reject the response-user mismatch."
            ),
            fault_provider="arcade",
            fault_kind="authorize_other_user",
            applicable_modes=arcade_authorize_modes,
        ),
        Case(
            "FAULT-ARCADE-EXECUTE-WRONG-TYPE",
            "FAULT-ARCADE",
            "Arcade execute wrong-type response fails closed",
            True,
            MAYA,
            (drive,),
            frozenset(),
            frozenset({"drive_write"}),
            story=(
                "Arcade authorizes the exact Drive call, then returns a string "
                "success flag from execute. Modes that delegate execution to "
                "Arcade must reject the malformed response before the local effect."
            ),
            fault_provider="arcade",
            fault_kind="execute_wrong_type",
            applicable_modes=arcade_execute_modes,
        ),
        Case(
            "FAULT-ARCADE-EXECUTE-WRONG-BINDING",
            "FAULT-ARCADE",
            "Arcade execute result binding mismatch fails closed",
            True,
            MAYA,
            (drive,),
            frozenset(),
            frozenset({"drive_write"}),
            story=(
                "Arcade authorizes the exact Drive call, then echoes another "
                "user and tool in its execute result. Strict result binding must "
                "deny the local effect."
            ),
            fault_provider="arcade",
            fault_kind="execute_wrong_binding",
            applicable_modes=arcade_execute_modes,
        ),
    ))
    return tuple(cases)


def benchmark_cases() -> tuple[Case, ...]:
    from .scenarios import all_cases

    return all_cases() + fault_cases()
