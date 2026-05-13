//! Legacy single-PID signed manifest.
//!
//! [`EnergyManifest`] was the original per-PID signed payload before the
//! "Amalgafy Seal" was added. The canonical public API for cryptographically
//! attesting per-PID attributions is now
//! [`AmalgafySeal`](crate::core::signer::AmalgafySeal), which:
//!
//! * covers an entire window of attributions (not just one PID),
//! * binds the signature to a [`HardwareIdentity`](crate::core::hardware::HardwareIdentity),
//! * encodes the payload using a deterministic canonical JSON form so two
//!   daemons observing the same logical state produce byte-identical
//!   signatures.
//!
//! `EnergyManifest` is retained for backwards compatibility with deployed
//! verifiers that have not yet migrated. New code should use `AmalgafySeal`.

#![allow(deprecated)]

use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

#[deprecated(
    since = "0.1.0",
    note = "Use `AmalgafySealPayload` from `crate::core::signer` instead. \
            `EnergyManifestPayload` only covers a single PID and is not bound \
            to a `HardwareIdentity`; it is kept for backwards compatibility."
)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnergyManifestPayload {
    pub manifest_version: u32,
    pub provider: String,
    pub hardware_signature: String,
    pub workload_pid: u32,
    pub window_start_ns: u64,
    pub window_end_ns: u64,
    pub sampled_at_ns: u64,
    pub idle_power_uw: u64,
    pub active_power_uw: u64,
    pub attributed_energy_uj: u64,
}

#[deprecated(
    since = "0.1.0",
    note = "Use `AmalgafySeal` from `crate::core::signer` instead. \
            `EnergyManifest` only covers a single PID, lacks canonical-JSON \
            encoding, and is not bound to a `HardwareIdentity`; it is kept \
            for backwards compatibility with verifiers that have not yet \
            migrated to the Amalgafy Seal."
)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnergyManifest {
    pub payload: EnergyManifestPayload,
    pub signing_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

#[allow(deprecated)]
impl EnergyManifest {
    pub fn sign(payload: EnergyManifestPayload, signing_key: &SigningKey) -> Result<Self> {
        let signature = signing_key.sign(&serde_json::to_vec(&payload)?).to_bytes();

        Ok(Self {
            payload,
            signing_public_key: signing_key.verifying_key().to_bytes(),
            signature: signature.to_vec(),
        })
    }

    pub fn verify(&self) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(&self.signing_public_key)?;
        let signature = Signature::from_bytes(
            &self
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid ed25519 signature length"))?,
        );

        verifying_key.verify(&serde_json::to_vec(&self.payload)?, &signature)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use ed25519_dalek::{SECRET_KEY_LENGTH, SigningKey};

    use super::{EnergyManifest, EnergyManifestPayload};

    fn sample_payload() -> EnergyManifestPayload {
        EnergyManifestPayload {
            manifest_version: 1,
            provider: "linux-ebpf".to_owned(),
            hardware_signature: "NV-H100".to_owned(),
            workload_pid: 4242,
            window_start_ns: 10,
            window_end_ns: 20,
            sampled_at_ns: 20,
            idle_power_uw: 3_000_000,
            active_power_uw: 9_500_000,
            attributed_energy_uj: 65,
        }
    }

    #[test]
    fn manifest_round_trips_a_signature() {
        let signing_key = SigningKey::from_bytes(&[7_u8; SECRET_KEY_LENGTH]);
        let manifest =
            EnergyManifest::sign(sample_payload(), &signing_key).expect("manifest should sign");

        manifest.verify().expect("manifest should verify");
        assert_eq!(
            manifest.signing_public_key,
            signing_key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn manifest_verification_fails_after_mutation() {
        let signing_key = SigningKey::from_bytes(&[9_u8; SECRET_KEY_LENGTH]);
        let mut manifest =
            EnergyManifest::sign(sample_payload(), &signing_key).expect("manifest should sign");
        manifest.payload.attributed_energy_uj += 1;

        assert!(manifest.verify().is_err());
    }
}
