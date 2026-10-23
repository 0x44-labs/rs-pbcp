use blake3::Hasher;
use subtle::ConstantTimeEq;
use traversev::{Params, TraverseV};
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::common::{derive_secret, unix_now};
use crate::errors::PbcpError;
use crate::prover::Proof;
use crate::verifier::{Challenge, ReplayStore};

/// Proof-Bound Claims Protocol (PBCP) Verifier.
///
/// Capable of issuing [Challenges](Challenge) and evaluating any received
/// [Proof] for authenticity.
pub struct Verifier {
    context: String,
    key: [u8; 32],
    ttl: u64,
    params: Params,
}

impl Verifier {
    pub(crate) fn new(
        context: &str,
        key: &[u8; 32],
        ttl: u64,
        params: Params,
    ) -> Self {
        Self {
            context: context.to_owned(),
            key: *key,
            ttl,
            params,
        }
    }

    /// Issue a [Challenge] over the given nonce.
    pub fn issue(&self, nonce: &[u8]) -> Result<Challenge, PbcpError> {
        if nonce.len() > 64 {
            return Err(PbcpError::ChallengeNonce);
        }

        let id = Ulid::generate();
        let expires_at = unix_now().saturating_add(self.ttl);

        let tag = auth_tag(&self.key, id, expires_at, nonce, self.params);
        Ok(Challenge::new(id, expires_at, nonce, self.params, tag))
    }

    /// Verify a [Proof] against this verifier's challenge, returning
    /// whether its nonce is a valid proof over its claims.
    ///
    /// Returns an error if the proof belongs to a different challenge, the
    /// challenge has expired, or the challenge is already recorded in `store`.
    pub fn verify(
        &self,
        proof: &Proof,
        store: Option<&ReplayStore>,
    ) -> Result<bool, PbcpError> {
        let challenge = proof.challenge();

        let mut expected = auth_tag(
            &self.key,
            challenge.id(),
            challenge.expires_at(),
            challenge.nonce(),
            challenge.params(),
        );
        let tampered = expected.ct_ne(&challenge.auth_tag());

        #[cfg(feature = "zeroize")]
        expected.zeroize();

        if bool::from(tampered) {
            return Err(PbcpError::WrongChallenge);
        }

        let time = {
            let mut counter = proof.nonce();
            let time = counter.time();

            #[cfg(feature = "zeroize")]
            counter.zeroize();

            time
        };
        if time > challenge.expires_at() || unix_now() > challenge.expires_at()
        {
            return Err(PbcpError::Expired);
        }

        let mut input = proof.claims().to_bytes()?;

        if let Some(store) = store {
            match store.check_and_insert(challenge.id(), challenge.expires_at())
            {
                Ok(true) => {}
                Ok(false) => {
                    #[cfg(feature = "zeroize")]
                    input.zeroize();

                    return Err(PbcpError::Replayed);
                }
                Err(e) => {
                    #[cfg(feature = "zeroize")]
                    input.zeroize();

                    return Err(e);
                }
            }
        }

        let mut secret = derive_secret(&challenge.id(), challenge.nonce());
        let tv = TraverseV::new_permissioned(
            &secret,
            &self.context,
            challenge.params(),
        );
        let mut nonce = proof.nonce();
        let valid = tv.verify(&input, nonce);

        #[cfg(feature = "zeroize")]
        {
            input.zeroize();
            secret.zeroize();
            nonce.zeroize();
        }

        Ok(valid)
    }

    /// Returns the TTL applied to issued challenges, in seconds.
    pub const fn ttl(&self) -> u64 {
        self.ttl
    }

    /// Returns the proof-of-work parameters applied to issued challenges.
    pub const fn params(&self) -> Params {
        self.params
    }
}

impl core::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("ttl", &self.ttl)
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Verifier {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Verifier {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Verifier {}

fn auth_tag(
    key: &[u8; 32],
    id: Ulid,
    expires_at: u64,
    nonce: &[u8],
    params: Params,
) -> [u8; 16] {
    let mut hasher = Hasher::new_keyed(key);

    hasher.update(&id.to_bytes());
    hasher.update(&expires_at.to_le_bytes());
    for cost in [
        params.m_cost(),
        params.t_cost(),
        params.e_cost(),
        params.n_cost(),
    ] {
        hasher.update(&cost.to_le_bytes());
    }
    hasher.update(nonce);

    let mut reader = hasher.finalize_xof();
    let mut tag = [0u8; 16];
    reader.fill(&mut tag);

    #[cfg(feature = "zeroize")]
    {
        hasher.zeroize();
        reader.zeroize();
    }

    tag
}

#[cfg(test)]
mod tests {
    use crate::common::{Claims, Counter};

    use super::*;

    type Error = PbcpError;

    const CONTEXT: &str = "This is a context string";
    const KEY: [u8; 32] = [0u8; 32];
    const TTL: u64 = 300;
    const NONCE: &[u8] = b"This is a challenge nonce";

    /// Parameters for testing.
    fn params() -> Params {
        Params::new(8, 2, 2, 12).expect("valid parameters")
    }

    fn claims() -> Claims {
        Claims::builder()
            .claim("iss", "https://humanity.example")
            .claim("sub", "Homo sapiens")
            .claim("aud", "https://humans-only.example")
            .claim("iat", 1786554930)
            .claim("exp", 1786561137)
            .build()
    }

    /// A counter with a zero count and the given time in the high 64 bits.
    fn counter_at(time: u64) -> Counter {
        Counter::from(u128::from(time) << 64)
    }

    /// A TraverseV instance built for a given challenge.
    fn instance(challenge: &Challenge) -> TraverseV {
        let secret = derive_secret(&challenge.id(), challenge.nonce());
        TraverseV::new_permissioned(&secret, CONTEXT, challenge.params())
    }

    /// A nonce value satisfying the given challenge's difficulty.
    fn nonce(challenge: &Challenge, claims: &Claims) -> Counter {
        let input = claims
            .to_bytes()
            .expect("valid Claims serialise to canonical JSON bytes");
        instance(challenge).mine(&input, Counter::default(), 1u64)
    }

    #[test]
    fn issue_issues_challenge() {
        let verifier = Verifier::new(CONTEXT, &KEY, TTL, params());

        let before = unix_now() + TTL;
        let challenge = verifier.issue(NONCE).expect("nonce below 64 bytes");
        let after = unix_now() + TTL;

        assert!((before..=after).contains(&challenge.expires_at()));
    }

    #[test]
    fn verify_verifies_proof() {
        let verifier = Verifier::new(CONTEXT, &KEY, TTL, params());
        let claims = claims();

        let challenge = verifier.issue(NONCE).expect("nonce below 64 bytes");
        let nonce = nonce(&challenge, &claims);
        let proof = Proof::new(&challenge, &claims, nonce);

        let result = verifier.verify(&proof, None);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_rejects_wrong_challenge() {
        let params = params();
        let verifier = Verifier::new(CONTEXT, &KEY, TTL, params);

        // Challenge not issued by this Verifier
        let challenge = Challenge::new(
            Ulid::generate(),
            unix_now() + TTL,
            NONCE,
            params,
            [0u8; 16],
        );
        let proof = Proof::new(&challenge, &claims(), counter_at(unix_now()));

        let result = verifier.verify(&proof, None);
        assert!(matches!(result.err(), Some(Error::WrongChallenge)));
    }

    #[test]
    fn verify_rejects_expired_challenge() {
        let params = params();
        let verifier = Verifier::new(CONTEXT, &KEY, TTL, params);
        let store = ReplayStore::new();

        // The verifier's clock is within the TTL, only the nonce time rejects
        let challenge = verifier.issue(NONCE).expect("nonce below 64 bytes");
        let nonce = counter_at(challenge.expires_at() + 1);
        let proof = Proof::new(&challenge, &claims(), nonce);
        let result = verifier.verify(&proof, Some(&store));
        assert!(matches!(result.err(), Some(Error::Expired)));

        // The nonce time is within the TTL, only the verifier's clock rejects
        let id = Ulid::generate();
        let expires_at = unix_now() - 1;
        let tag = auth_tag(&KEY, id, expires_at, NONCE, params);
        let challenge = Challenge::new(id, expires_at, NONCE, params, tag);
        let proof = Proof::new(&challenge, &claims(), counter_at(expires_at));
        let result = verifier.verify(&proof, Some(&store));
        assert!(matches!(result.err(), Some(Error::Expired)));
    }

    #[test]
    fn verify_rejects_replayed_challenge() {
        let verifier = Verifier::new(CONTEXT, &KEY, TTL, params());
        let store = ReplayStore::new();

        let challenge = verifier.issue(NONCE).expect("nonce below 64 bytes");
        let proof = Proof::new(&challenge, &claims(), counter_at(unix_now()));

        let original = verifier.verify(&proof, Some(&store));
        assert!(original.is_ok());

        let replayed = verifier.verify(&proof, Some(&store));
        assert!(matches!(replayed.err(), Some(PbcpError::Replayed)));
    }

    #[test]
    fn verify_propagates_store_failure() {
        let verifier = Verifier::new(CONTEXT, &KEY, TTL, params());
        let store = ReplayStore::from_fn(|_, _| Err("unavailable".into()));

        let challenge = verifier.issue(NONCE).expect("nonce below 64 bytes");
        let proof = Proof::new(&challenge, &claims(), counter_at(unix_now()));

        let result = verifier.verify(&proof, Some(&store));
        assert!(matches!(result.err(), Some(Error::StoreFail(_))));
    }

    #[test]
    fn accessors_return_their_own_field() {
        let params = params();
        let verifier = Verifier::new(CONTEXT, &KEY, TTL, params);

        assert_eq!(verifier.ttl(), TTL);
        assert_eq!(verifier.params(), params);
    }

    #[test]
    fn debug_shows_ttl_and_params() {
        let params = params();
        let verifier = Verifier::new(CONTEXT, &KEY, TTL, params);

        assert_eq!(
            format!("{verifier:?}"),
            format!("Verifier {{ ttl: {TTL}, params: {params:?}, .. }}")
        );
    }
}
