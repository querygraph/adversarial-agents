//! Rust execution-envelope gate for AgentGym's protected profile.

use std::collections::{HashMap, HashSet};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use typesec_core::{
    ResourceId, SubjectId,
    policy::{PolicyEngine, PolicyResult, RequestContext},
};
use typesec_odrl::OdrlEngine;
use typesec_rbac::RbacEngine;

type HmacSha256 = Hmac<Sha256>;
const RECEIPT_KEY_MATERIAL: &[u8] = b"agentgym deterministic test receipt key v1";

const RECEIPT_FIELDS: [&str; 14] = [
    "v",
    "iss",
    "mode",
    "decision",
    "subject",
    "organization",
    "tool",
    "action",
    "resource",
    "call",
    "request_digest",
    "policy_digest",
    "issued_at",
    "expires_at",
];

const ENVELOPE_FIELDS: [&str; 9] = [
    "subject",
    "organization",
    "tool",
    "action",
    "resource",
    "purpose",
    "delegated_user",
    "args",
    "runtime",
];

#[pyclass(frozen)]
#[derive(Clone, Debug)]
struct Decision {
    #[pyo3(get)]
    allowed: bool,
    #[pyo3(get)]
    reason: String,
    #[pyo3(get)]
    action: String,
    #[pyo3(get)]
    resource: String,
    #[pyo3(get)]
    request_digest: String,
    #[pyo3(get)]
    policy_digest: String,
}

impl Decision {
    fn deny(
        reason: impl Into<String>,
        action: &str,
        resource: &str,
        request_digest: &str,
        policy_digest: &str,
    ) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            action: action.to_owned(),
            resource: resource.to_owned(),
            request_digest: request_digest.to_owned(),
            policy_digest: policy_digest.to_owned(),
        }
    }
}

#[pyclass]
struct AgentGymGate {
    rbac: RbacEngine,
    odrl: OdrlEngine,
    bindings: HashMap<String, String>,
    organization: String,
    policy_digest: String,
}

/// Rust issuer/verifier for deterministic benchmark receipts.
///
/// The compiled key is deliberately a public test fixture. Deployments must
/// substitute a protected key or TypeSec's Ed25519 receipt issuer.
#[pyclass]
struct ReceiptSigner {
    key: [u8; 32],
}

/// Opaque, single-use authority required by the Python effect implementation.
///
/// There is intentionally no Python constructor. A permit is returned only
/// after the compiled signer verifies an authenticated, closed-schema allow
/// receipt whose embedded call hashes to the bound execution digest.
#[pyclass]
struct ExecutionPermit {
    request_digest: String,
    policy_digest: String,
    issued_at: f64,
    expires_at: f64,
    consumed: bool,
}

#[pymethods]
impl ExecutionPermit {
    fn consume(&mut self, request_digest: &str, policy_digest: &str, now: f64) -> PyResult<()> {
        if self.consumed {
            return Err(PyValueError::new_err(
                "execution permit was already consumed",
            ));
        }
        if request_digest != self.request_digest || policy_digest != self.policy_digest {
            return Err(PyValueError::new_err(
                "execution permit call or policy binding mismatch",
            ));
        }
        if !now.is_finite() || now < self.issued_at || now >= self.expires_at {
            return Err(PyValueError::new_err(
                "execution permit is not currently valid",
            ));
        }
        self.consumed = true;
        Ok(())
    }
}

#[pymethods]
impl ReceiptSigner {
    #[new]
    fn new() -> Self {
        Self {
            key: Sha256::digest(RECEIPT_KEY_MATERIAL).into(),
        }
    }

    fn issue(&self, canonical_claims_json: &str) -> PyResult<String> {
        validate_canonical_claims(canonical_claims_json)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("SHA-256 HMAC accepts a 32-byte key");
        mac.update(canonical_claims_json.as_bytes());
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(canonical_claims_json.as_bytes()),
            URL_SAFE_NO_PAD.encode(signature),
        ))
    }

    fn verify(&self, token: &str, canonical_claims_json: &str) -> bool {
        if validate_canonical_claims(canonical_claims_json).is_err() {
            return false;
        }
        let Some((payload, signature)) = token.split_once('.') else {
            return false;
        };
        if payload != URL_SAFE_NO_PAD.encode(canonical_claims_json.as_bytes()) {
            return false;
        }
        let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
            return false;
        };
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("SHA-256 HMAC accepts a 32-byte key");
        mac.update(canonical_claims_json.as_bytes());
        mac.verify_slice(&signature).is_ok()
    }

    fn execution_permit(
        &self,
        token: &str,
        canonical_claims_json: &str,
    ) -> PyResult<ExecutionPermit> {
        if !self.verify(token, canonical_claims_json) {
            return Err(PyValueError::new_err("receipt signature is invalid"));
        }
        let claims = parse_canonical_claims(canonical_claims_json)?;
        let object = claims
            .as_object()
            .ok_or_else(|| PyValueError::new_err("receipt claims must be an object"))?;
        let actual_fields: HashSet<&str> = object.keys().map(String::as_str).collect();
        let expected_fields: HashSet<&str> = RECEIPT_FIELDS.into_iter().collect();
        if actual_fields != expected_fields {
            return Err(PyValueError::new_err(
                "receipt claims fields are not closed",
            ));
        }
        if object.get("v").and_then(Value::as_u64) != Some(1)
            || object.get("decision").and_then(Value::as_str) != Some("allow")
        {
            return Err(PyValueError::new_err("receipt is not a versioned allow"));
        }
        let request_digest = required_claim_string(object, "request_digest")?;
        let policy_digest = required_claim_string(object, "policy_digest")?;
        if !is_sha256(&request_digest) || !is_sha256(&policy_digest) {
            return Err(PyValueError::new_err(
                "receipt request and policy digests must be SHA-256",
            ));
        }
        let call = object
            .get("call")
            .and_then(Value::as_object)
            .ok_or_else(|| PyValueError::new_err("receipt call must be an object"))?;
        for field in ["subject", "organization", "tool", "action", "resource"] {
            if object.get(field).and_then(Value::as_str) != call.get(field).and_then(Value::as_str)
            {
                return Err(PyValueError::new_err(format!(
                    "receipt {field} does not match its embedded call",
                )));
            }
        }
        let canonical_call = serde_json::to_string(call)
            .map_err(|err| PyValueError::new_err(format!("receipt call cannot encode: {err}")))?;
        let actual_digest = format!("{:x}", Sha256::digest(canonical_call.as_bytes()));
        if actual_digest != request_digest {
            return Err(PyValueError::new_err(
                "receipt embedded call digest mismatch",
            ));
        }
        let issued_at = required_claim_number(object, "issued_at")?;
        let expires_at = required_claim_number(object, "expires_at")?;
        if !issued_at.is_finite() || !expires_at.is_finite() || expires_at <= issued_at {
            return Err(PyValueError::new_err("receipt validity window is invalid"));
        }
        Ok(ExecutionPermit {
            request_digest,
            policy_digest,
            issued_at,
            expires_at,
            consumed: false,
        })
    }
}

fn parse_canonical_claims(value: &str) -> PyResult<Value> {
    let parsed: Value = serde_json::from_str(value)
        .map_err(|err| PyValueError::new_err(format!("receipt claims are not JSON: {err}")))?;
    let canonical = serde_json::to_string(&parsed)
        .map_err(|err| PyValueError::new_err(format!("receipt claims cannot encode: {err}")))?;
    if !parsed.is_object() || canonical != value {
        return Err(PyValueError::new_err(
            "receipt claims must be a canonical JSON object",
        ));
    }
    Ok(parsed)
}

fn validate_canonical_claims(value: &str) -> PyResult<()> {
    parse_canonical_claims(value).map(|_| ())
}

fn required_claim_string(claims: &serde_json::Map<String, Value>, field: &str) -> PyResult<String> {
    claims
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| PyValueError::new_err(format!("receipt {field} must be a string")))
}

fn required_claim_number(claims: &serde_json::Map<String, Value>, field: &str) -> PyResult<f64> {
    claims
        .get(field)
        .and_then(Value::as_f64)
        .ok_or_else(|| PyValueError::new_err(format!("receipt {field} must be numeric")))
}

#[pymethods]
impl AgentGymGate {
    #[new]
    fn new(
        rbac_yaml: &str,
        odrl_yaml: &str,
        bindings_json: &str,
        organization: &str,
        policy_digest: &str,
    ) -> PyResult<Self> {
        let rbac = RbacEngine::from_yaml(rbac_yaml)
            .map_err(|err| PyValueError::new_err(format!("invalid RBAC policy: {err}")))?;
        let odrl = OdrlEngine::from_yaml(odrl_yaml)
            .map_err(|err| PyValueError::new_err(format!("invalid ODRL policy: {err}")))?;
        let bindings: HashMap<String, String> = serde_json::from_str(bindings_json)
            .map_err(|err| PyValueError::new_err(format!("invalid tool bindings: {err}")))?;
        if bindings.is_empty()
            || bindings
                .iter()
                .any(|(tool, action)| tool.is_empty() || action.is_empty())
        {
            return Err(PyValueError::new_err(
                "tool bindings must be non-empty strings",
            ));
        }
        if organization.is_empty() {
            return Err(PyValueError::new_err(
                "organization binding must not be empty",
            ));
        }
        if !is_sha256(policy_digest) {
            return Err(PyValueError::new_err(
                "policy digest must be 64 lowercase hex bytes",
            ));
        }
        Ok(Self {
            rbac,
            odrl,
            bindings,
            organization: organization.to_owned(),
            policy_digest: policy_digest.to_owned(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn check(
        &self,
        subject: &str,
        tool: &str,
        action: &str,
        resource: &str,
        purpose: Option<&str>,
        envelope_json: &str,
        request_digest: &str,
    ) -> Decision {
        let deny = |reason: String| {
            Decision::deny(
                reason,
                action,
                resource,
                request_digest,
                &self.policy_digest,
            )
        };
        if subject.is_empty() || tool.is_empty() || action.is_empty() || resource.is_empty() {
            return deny("identity, tool, action, and resource must be non-empty".into());
        }
        if !is_sha256(request_digest) {
            return deny("request digest must be 64 lowercase hex bytes".into());
        }
        let Some(bound_action) = self.bindings.get(tool) else {
            return deny(format!(
                "tool '{tool}' has no TypeSec binding (deny by default)"
            ));
        };
        if action != bound_action {
            return deny(format!(
                "action binding mismatch: tool '{tool}' requires '{bound_action}', got '{action}'"
            ));
        }

        let envelope: Value = match serde_json::from_str(envelope_json) {
            Ok(value) => value,
            Err(err) => return deny(format!("execution envelope is not JSON: {err}")),
        };
        match serde_json::to_string(&envelope) {
            Ok(canonical) if canonical == envelope_json => {}
            _ => return deny("execution envelope is not canonical JSON".into()),
        }
        let Some(object) = envelope.as_object() else {
            return deny("execution envelope must be an object".into());
        };
        let actual_fields: HashSet<&str> = object.keys().map(String::as_str).collect();
        let expected_fields: HashSet<&str> = ENVELOPE_FIELDS.into_iter().collect();
        if actual_fields != expected_fields {
            return deny("execution envelope fields are not closed".into());
        }
        let matches =
            |name: &str, expected: &str| object.get(name).and_then(Value::as_str) == Some(expected);
        if !matches("subject", subject)
            || !matches("organization", &self.organization)
            || !matches("tool", tool)
            || !matches("action", action)
            || !matches("resource", resource)
        {
            return deny("execution envelope identity/action/resource binding mismatch".into());
        }
        let purpose_matches = match (purpose, object.get("purpose")) {
            (None, Some(Value::Null)) => true,
            (Some(expected), Some(Value::String(actual))) => expected == actual,
            _ => false,
        };
        if !purpose_matches
            || !object.get("args").is_some_and(Value::is_object)
            || !object.get("runtime").is_some_and(Value::is_object)
        {
            return deny("execution envelope purpose/arguments/runtime shape mismatch".into());
        }
        let actual_digest = format!("{:x}", Sha256::digest(envelope_json.as_bytes()));
        if actual_digest != request_digest {
            return deny("execution envelope digest mismatch".into());
        }

        let subject_id = SubjectId::from(subject);
        let resource_id = ResourceId::from(resource);
        match self.rbac.check(&subject_id, action, &resource_id) {
            PolicyResult::Allow => {}
            PolicyResult::Deny(reason) => return deny(format!("Rust RBAC denied: {reason}")),
            _ => return deny("Rust RBAC returned a non-allow verdict".into()),
        }
        if tool == "catalog/query" {
            let mut context = RequestContext::default();
            if let Some(value) = purpose {
                context = context.with_purpose(value.to_owned());
            }
            match PolicyEngine::check_with_context(
                &self.odrl,
                &subject_id,
                action,
                &resource_id,
                &context,
            ) {
                PolicyResult::Allow => {}
                PolicyResult::Deny(reason) => {
                    return deny(format!("Rust ODRL denied: {reason}"));
                }
                _ => return deny("Rust ODRL returned a non-allow verdict".into()),
            }
        }
        Decision {
            allowed: true,
            reason: "Rust TypeSec policy and canonical envelope allowed".into(),
            action: action.to_owned(),
            resource: resource.to_owned(),
            request_digest: request_digest.to_owned(),
            policy_digest: self.policy_digest.clone(),
        }
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[pymodule]
fn agentgym_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<AgentGymGate>()?;
    module.add_class::<Decision>()?;
    module.add_class::<ReceiptSigner>()?;
    module.add_class::<ExecutionPermit>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RBAC: &str = r#"
roles:
  - name: analyst
    permissions: [read]
    resources: ["lakecat://northstar/household_energy"]
assignments:
  - subject: "user:maya@civic.example"
    roles: [analyst]
"#;

    const ODRL: &str = r#"
policies:
  - uid: policy:test
    type: Set
    rules:
      - type: permission
        assignee: user:maya@civic.example
        action: read
        target: lakecat://northstar/household_energy
        constraints:
          - leftOperand: purpose
            operator: eq
            rightOperand: research
"#;

    fn test_gate() -> AgentGymGate {
        AgentGymGate::new(
            RBAC,
            ODRL,
            r#"{"catalog/query":"read"}"#,
            "org:civic-lab",
            &"a".repeat(64),
        )
        .unwrap()
    }

    fn envelope(action: &str, organization: &str) -> (String, String) {
        let value = json!({
            "action": action,
            "args": {"columns": ["region"]},
            "delegated_user": null,
            "organization": organization,
            "purpose": "research",
            "resource": "lakecat://northstar/household_energy",
            "runtime": {},
            "subject": "user:maya@civic.example",
            "tool": "catalog/query"
        });
        let encoded = serde_json::to_string(&value).unwrap();
        let digest = format!("{:x}", Sha256::digest(encoded.as_bytes()));
        (encoded, digest)
    }

    #[test]
    fn exact_envelope_passes_rbac_and_odrl() {
        let (encoded, digest) = envelope("read", "org:civic-lab");
        let result = test_gate().check(
            "user:maya@civic.example",
            "catalog/query",
            "read",
            "lakecat://northstar/household_energy",
            Some("research"),
            &encoded,
            &digest,
        );
        assert!(result.allowed, "{}", result.reason);
    }

    #[test]
    fn action_digest_and_organization_mismatches_deny() {
        let gate = test_gate();
        let (encoded, digest) = envelope("delete", "org:civic-lab");
        assert!(
            !gate
                .check(
                    "user:maya@civic.example",
                    "catalog/query",
                    "delete",
                    "lakecat://northstar/household_energy",
                    Some("research"),
                    &encoded,
                    &digest,
                )
                .allowed
        );
        let (encoded, _) = envelope("read", "org:civic-lab");
        assert!(
            !gate
                .check(
                    "user:maya@civic.example",
                    "catalog/query",
                    "read",
                    "lakecat://northstar/household_energy",
                    Some("research"),
                    &encoded,
                    &"0".repeat(64),
                )
                .allowed
        );
        let (encoded, digest) = envelope("read", "org:attacker");
        assert!(
            !gate
                .check(
                    "user:maya@civic.example",
                    "catalog/query",
                    "read",
                    "lakecat://northstar/household_energy",
                    Some("research"),
                    &encoded,
                    &digest,
                )
                .allowed
        );
    }

    #[test]
    fn unbound_tool_and_missing_purpose_deny() {
        let gate = test_gate();
        let (encoded, digest) = envelope("read", "org:civic-lab");
        assert!(
            !gate
                .check(
                    "user:maya@civic.example",
                    "unknown/admin",
                    "read",
                    "lakecat://northstar/household_energy",
                    Some("research"),
                    &encoded,
                    &digest,
                )
                .allowed
        );
        assert!(
            !gate
                .check(
                    "user:maya@civic.example",
                    "catalog/query",
                    "read",
                    "lakecat://northstar/household_energy",
                    None,
                    &encoded,
                    &digest,
                )
                .allowed
        );
    }

    #[test]
    fn receipts_are_deterministic_and_tamper_evident() {
        let signer = ReceiptSigner::new();
        let (call_json, request_digest) = envelope("read", "org:civic-lab");
        let call: Value = serde_json::from_str(&call_json).unwrap();
        let claims = serde_json::to_string(&json!({
            "action": "read",
            "call": call,
            "decision": "allow",
            "expires_at": 60.0,
            "iss": "agentgym:test-issuer:v1",
            "issued_at": 0.0,
            "mode": "typesec",
            "organization": "org:civic-lab",
            "policy_digest": "a".repeat(64),
            "request_digest": request_digest,
            "resource": "lakecat://northstar/household_energy",
            "subject": "user:maya@civic.example",
            "tool": "catalog/query",
            "v": 1,
        }))
        .unwrap();
        let first = signer.issue(&claims).unwrap();
        let second = signer.issue(&claims).unwrap();
        assert_eq!(first, second);
        assert!(signer.verify(&first, &claims));
        let mut permit = signer.execution_permit(&first, &claims).unwrap();
        assert!(
            permit
                .consume(&request_digest, &"a".repeat(64), 0.0)
                .is_ok()
        );
        assert!(
            permit
                .consume(&request_digest, &"a".repeat(64), 0.0)
                .is_err()
        );
        let mut tampered = first.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert!(!signer.verify(std::str::from_utf8(&tampered).unwrap(), &claims));
        assert!(signer.issue(r#"{ "action": "read" }"#).is_err());
    }
}
