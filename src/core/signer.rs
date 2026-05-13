//! The "Amalgafy Seal": every 60 seconds the daemon must export a
//! cryptographically signed `EnergyManifest` covering the full set of
//! per-PID attributions plus the hardware serial and the total joules.
//!
//! The signature is a detached Ed25519 signature over a *canonical* JSON
//! encoding of the seal. Canonicalization guarantees that two daemons in a
//! data center produce byte-identical payloads for the same logical state,
//! which is what auditors verify when they replay the seal.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::provider::PidEnergyAttribution;

/// The cadence at which the daemon is required to publish a fresh
/// [`AmalgafySeal`]. Exposed as a constant so embedders can schedule a
/// `tokio::time::interval` against it.
pub const AMALGAFY_SEAL_INTERVAL_SECS: u64 = 60;

/// The payload that gets covered by the Ed25519 signature.
///
/// All fields are sorted into canonical order at serialization time, so the
/// in-memory field order here is not load-bearing — but we still keep it
/// stable for readability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmalgafySealPayload {
    pub manifest_version: u32,
    pub hardware_serial: String,
    pub sealed_at_unix_ns: u64,
    pub total_micro_joules: u64,
    pub attributions: Vec<PidEnergyAttribution>,
}

/// A signed seal. The signature is *detached* — i.e. it can be verified
/// without re-encoding the payload by hand, as long as the verifier uses the
/// same canonical-JSON producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmalgafySeal {
    pub payload: AmalgafySealPayload,
    pub signing_public_key: [u8; 32],
    pub signature: Vec<u8>,
    pub canonical_payload: Vec<u8>,
}

impl AmalgafySeal {
    /// Re-verify the seal's signature against its canonical payload.
    pub fn verify(&self) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(&self.signing_public_key)?;
        let signature_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid ed25519 signature length"))?;
        let signature = Signature::from_bytes(&signature_bytes);

        // Verify against the *canonical* bytes we stored, and additionally
        // re-derive them from the payload to make sure they match. A mismatch
        // means the payload was tampered with after sealing.
        let re_canonical = canonical_json(&self.payload)?;
        if re_canonical != self.canonical_payload {
            return Err(anyhow!(
                "AmalgafySeal canonical payload does not match its declared payload"
            ));
        }

        verifying_key.verify(&self.canonical_payload, &signature)?;
        Ok(())
    }
}

/// Holder for the daemon's signing key. The signer never exposes the secret
/// half and only borrows the [`SigningKey`] long enough to produce a
/// signature.
#[derive(Debug)]
pub struct AmalgafySigner {
    signing_key: SigningKey,
    manifest_version: u32,
}

impl AmalgafySigner {
    /// Create a signer that will stamp every seal with the daemon's Ed25519
    /// identity.
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            manifest_version: 1,
        }
    }

    /// Override the manifest version embedded in every seal (handy for
    /// schema migrations).
    #[must_use]
    pub fn with_manifest_version(mut self, version: u32) -> Self {
        self.manifest_version = version;
        self
    }

    /// Public key that auditors must use to verify seals produced by this
    /// daemon. Safe to publish.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Produce a signed seal over `attributions`, the `hardware_serial`, and
    /// the precomputed `total_micro_joules`.
    ///
    /// This is the "Amalgafy Seal" referenced in the design directive. The
    /// signature explicitly covers the hardware serial and the total joules so
    /// an attacker cannot swap a high-energy payload for a different machine
    /// or zero out the total without invalidating the signature.
    ///
    /// Determinism: `attributions` is sorted by `(pid, window_start_ns,
    /// window_end_ns)` before being canonicalized, so two daemons observing
    /// the same logical state produce byte-identical canonical payloads (and
    /// therefore byte-identical signatures) regardless of the order in which
    /// the caller assembled the input.
    pub fn seal(
        &self,
        mut attributions: Vec<PidEnergyAttribution>,
        hardware_serial: impl Into<String>,
        total_micro_joules: u64,
    ) -> Result<AmalgafySeal> {
        let sealed_at_unix_ns = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        )
        .unwrap_or(u64::MAX);

        // Enforce a deterministic order at the API boundary so the
        // "canonical JSON" promise cannot be accidentally violated by a
        // caller assembling attributions in a different order.
        attributions.sort_by(|a, b| {
            a.pid
                .cmp(&b.pid)
                .then(a.window_start_ns.cmp(&b.window_start_ns))
                .then(a.window_end_ns.cmp(&b.window_end_ns))
        });

        let payload = AmalgafySealPayload {
            manifest_version: self.manifest_version,
            hardware_serial: hardware_serial.into(),
            sealed_at_unix_ns,
            total_micro_joules,
            attributions,
        };

        let canonical = canonical_json(&payload)?;
        let signature = self.signing_key.sign(&canonical).to_bytes().to_vec();

        Ok(AmalgafySeal {
            payload,
            signing_public_key: self.signing_key.verifying_key().to_bytes(),
            signature,
            canonical_payload: canonical,
        })
    }
}

/// Encode `payload` in a canonical JSON form: all object keys are sorted
/// lexicographically and there is no insignificant whitespace. Arrays preserve
/// their insertion order, so producers that want signature-level determinism
/// across hosts must sort array contents before handing them to this function
/// — [`AmalgafySigner::seal`] does that for its attribution list.
///
/// This is **not** a full JCS implementation (RFC 8785), but it is sufficient
/// for the homogeneous payload shape produced by [`AmalgafySigner::seal`],
/// which only contains integers, strings, booleans, arrays, and objects.
pub fn canonical_json<T: Serialize>(payload: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(payload)?;
    let canonical = canonicalize_value(value);
    Ok(serde_json::to_vec(&canonical)?)
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(String, Value)> = map.into_iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            let mut canonical = serde_json::Map::with_capacity(sorted.len());
            for (k, v) in sorted {
                canonical.insert(k, canonicalize_value(v));
            }
            Value::Object(canonical)
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().map(canonicalize_value).collect())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{SECRET_KEY_LENGTH, SigningKey};

    use crate::core::provider::PidEnergyAttribution;

    use super::{AmalgafySigner, canonical_json};

    fn fixture_attributions() -> Vec<PidEnergyAttribution> {
        vec![
            PidEnergyAttribution {
                pid: 4242,
                window_start_ns: 100,
                window_end_ns: 200,
                burst_power_uw: 5_500_000,
                attributed_energy_uj: 550,
                hardware_signature: "NV-H100-SXM5-SN-0001".to_owned(),
            },
            PidEnergyAttribution {
                pid: 7,
                window_start_ns: 100,
                window_end_ns: 200,
                burst_power_uw: 1_000_000,
                attributed_energy_uj: 100,
                hardware_signature: "NV-H100-SXM5-SN-0001".to_owned(),
            },
        ]
    }

    #[test]
    fn signer_produces_a_verifiable_seal() {
        let signer = AmalgafySigner::new(SigningKey::from_bytes(&[3_u8; SECRET_KEY_LENGTH]));
        let seal = signer
            .seal(fixture_attributions(), "NV-H100-SXM5-SN-0001", 650)
            .expect("seal should sign");

        seal.verify().expect("seal should verify");
        assert_eq!(seal.payload.total_micro_joules, 650);
        assert_eq!(seal.payload.hardware_serial, "NV-H100-SXM5-SN-0001");
        assert_eq!(seal.payload.attributions.len(), 2);
        assert_eq!(seal.signature.len(), 64);
    }

    #[test]
    fn seal_verification_fails_after_tampering_with_total_joules() {
        let signer = AmalgafySigner::new(SigningKey::from_bytes(&[5_u8; SECRET_KEY_LENGTH]));
        let mut seal = signer
            .seal(fixture_attributions(), "NV-H100", 650)
            .expect("seal should sign");

        seal.payload.total_micro_joules = 1;

        assert!(seal.verify().is_err());
    }

    #[test]
    fn seal_verification_fails_after_swapping_hardware_serial() {
        let signer = AmalgafySigner::new(SigningKey::from_bytes(&[6_u8; SECRET_KEY_LENGTH]));
        let mut seal = signer
            .seal(fixture_attributions(), "NV-H100", 650)
            .expect("seal should sign");

        seal.payload.hardware_serial = "WRONG-SERIAL".to_owned();

        assert!(seal.verify().is_err());
    }

    #[test]
    fn seal_is_order_independent_across_attribution_inputs() {
        let signer = AmalgafySigner::new(SigningKey::from_bytes(&[9_u8; SECRET_KEY_LENGTH]));

        let forward = fixture_attributions();
        let mut reversed = fixture_attributions();
        reversed.reverse();

        let seal_a = signer
            .seal(forward, "NV-H100-SXM5-SN-0001", 650)
            .expect("seal should sign");
        let seal_b = signer
            .seal(reversed, "NV-H100-SXM5-SN-0001", 650)
            .expect("seal should sign");

        // Different caller-supplied orderings must canonicalize to the same
        // bytes (and therefore the same signature). `sealed_at_unix_ns`
        // varies between calls, so compare the deterministic fields.
        assert_eq!(
            seal_a
                .payload
                .attributions
                .iter()
                .map(|a| a.pid)
                .collect::<Vec<_>>(),
            seal_b
                .payload
                .attributions
                .iter()
                .map(|a| a.pid)
                .collect::<Vec<_>>(),
        );
        assert_eq!(seal_a.payload.attributions, seal_b.payload.attributions);
        // Sort enforces ascending PID order.
        assert_eq!(
            seal_a
                .payload
                .attributions
                .iter()
                .map(|a| a.pid)
                .collect::<Vec<_>>(),
            vec![7, 4242],
        );
    }

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value = serde_json::json!({
            "z": 1,
            "a": 2,
            "m": { "y": 3, "b": 4 },
        });
        let bytes = canonical_json(&value).expect("canonical encoding should succeed");
        let encoded = String::from_utf8(bytes).expect("canonical bytes are valid utf-8");

        assert_eq!(encoded, r#"{"a":2,"m":{"b":4,"y":3},"z":1}"#);
    }
}
