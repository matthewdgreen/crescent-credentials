//! Tests for the spec-driven expiry check (`ProofSpec.check_expiry`).
//!
//! Uses the in-repo mdl1 test vectors (prebuilt `client_state.bin`, so no
//! multi-GB prover params are needed). Covers:
//!  - `check_expiry: false` shows carry NO expiry range proof and verify;
//!  - `check_expiry: true` (and absent = default) still carries + verifies it;
//!  - SECURITY fail-closed: a proof whose expiry-proof presence disagrees with
//!    the verifier's spec is rejected — in the honest-mismatch direction via
//!    the Groth16 context binding (the internal spec is serialized into the
//!    context on both sides), and in the grafted-proof direction (spec says
//!    skip, proof carries one anyway) via the explicit presence check.

use crescent::device::TestDevice;
use crescent::groth16rand::ClientState;
use crescent::rangeproof::RangeProofPK;
use crescent::structs::IOLocations;
use crescent::utils::read_from_file;
use crescent::{
    create_show_proof, verify_show, CachePaths, CrescentPairing, ProofSpec, ShowProof,
    VerifierParams,
};

// Hash-sized: the device flow signs with ECDSA `sign_prehash`, which rejects
// short messages (the sample proof_spec.json's 4-byte value is overridden the
// same way by consumers).
const PRESENTATION_MESSAGE: [u8; 32] = [42u8; 32];

fn paths() -> CachePaths {
    CachePaths::new_from_str(&format!("{}/test-vectors/mdl1/", env!("CARGO_MANIFEST_DIR")))
}

fn spec(check_expiry: Option<bool>) -> ProofSpec {
    ProofSpec {
        revealed: vec![],
        range_over_year: None,
        presentation_message: Some(PRESENTATION_MESSAGE.to_vec()),
        device_bound: Some(true),
        committed: Some(vec![
            "birth_date".to_string(),
            "resident_state".to_string(),
            "height".to_string(),
        ]),
        check_expiry,
    }
}

fn make_show(spec: &ProofSpec) -> (ShowProof<CrescentPairing>, VerifierParams<CrescentPairing>) {
    let paths = paths();
    let io = IOLocations::new(&paths.io_locations);
    let mut client_state: ClientState<CrescentPairing> =
        read_from_file(&paths.client_state).expect("client_state.bin (in-repo test vector)");
    let range_pk: RangeProofPK<CrescentPairing> =
        read_from_file(&paths.range_pk).expect("range_pk.bin");
    let device = TestDevice::new_from_file(&paths.device_prv_pem);
    let sig = device.sign(&PRESENTATION_MESSAGE);
    let proof = create_show_proof(&mut client_state, &range_pk, &io, spec, Some(sig))
        .expect("create_show_proof");
    let vp = VerifierParams::new(&paths).expect("verifier params");
    (proof, vp)
}

#[test]
fn check_expiry_false_omits_range_proof_and_verifies() {
    let spec_off = spec(Some(false));
    let (proof, vp) = make_show(&spec_off);
    assert!(
        proof.show_range_exp.is_none(),
        "check_expiry: false must not carry an expiry range proof"
    );
    let (ok, _) = verify_show(&vp, &proof, &spec_off);
    assert!(ok, "check_expiry: false show must verify under the same spec");
}

#[test]
fn check_expiry_default_still_always_on() {
    // Absent (None) preserves the historical always-on behavior.
    let spec_default = spec(None);
    let (proof, vp) = make_show(&spec_default);
    assert!(
        proof.show_range_exp.is_some(),
        "default spec must carry the expiry range proof"
    );
    let (ok, _) = verify_show(&vp, &proof, &spec_default);
    assert!(ok, "default show must verify");
}

#[test]
fn spec_mismatch_rejected_in_both_directions() {
    let spec_off = spec(Some(false));
    let spec_on = spec(Some(true));

    // Honest prover with check_expiry:false, verifier demands the check:
    // rejected (context binding; and the presence check backstops it).
    let (proof_off, vp) = make_show(&spec_off);
    let (ok, _) = verify_show(&vp, &proof_off, &spec_on);
    assert!(!ok, "expiry-less proof must NOT verify under a checking spec");

    // And the reverse: a check_expiry:true proof under a skipping spec.
    let (proof_on, vp2) = make_show(&spec_on);
    let (ok, _) = verify_show(&vp2, &proof_on, &spec_off);
    assert!(!ok, "expiry-carrying proof must NOT verify under a skipping spec");
}

#[test]
fn grafted_expiry_proof_rejected() {
    // SECURITY fail-closed direction the context binding does NOT cover:
    // same spec on both sides (check_expiry: false), but the proof carries
    // extraneous expiry-proof data grafted from another proof. The explicit
    // presence check must reject it.
    let spec_off = spec(Some(false));
    let spec_on = spec(Some(true));
    let (mut proof, vp) = make_show(&spec_off);
    let (donor, _) = make_show(&spec_on);
    proof.show_range_exp = donor.show_range_exp;
    let (ok, _) = verify_show(&vp, &proof, &spec_off);
    assert!(!ok, "grafted expiry range proof must be rejected");
}
