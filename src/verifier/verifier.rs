use blake3::Hasher;
use std::{
    collections::BTreeSet,
    sync::{Mutex, PoisonError},
};
use subtle::ConstantTimeEq;
use traversev::{Params, TraverseV};
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::common::{derive_secret, unix_now};
use crate::errors::PbcpError;
use crate::prover::Proof;
use crate::verifier::{Challenge, Outcome};

/// Verifier for [Pbcp], capable of issuing [Challenges](Challenge) and
/// evaluating any received [Proof] for authenticity.
pub struct Verifier {
    context: String,
    key: [u8; 32],
    ttl: u64,
    params: Params,
    seen: Mutex<Seen>,
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
            seen: Mutex::new(Seen::new()),
        }
    }

    /// Issue a [Challenge] over the given nonce.
    pub fn issue(&self, nonce: &[u8]) -> Challenge {
        let id = Ulid::generate();
        let expires_at = unix_now().saturating_add(self.ttl);

        let tag = auth_tag(&self.key, id, expires_at, nonce, self.params);
        Challenge::new(id, expires_at, nonce, self.params, tag)
    }

    /// Verify a [Proof] against this verifier's challenge, returning
    /// whether its nonce is a valid proof over its claims.
    ///
    /// Returns an error if the proof belongs to a different challenge or the
    /// challenge has expired.
    pub fn verify(&self, proof: &Proof) -> Result<bool, PbcpError> {
        let challenge = proof.challenge();

        let expected = auth_tag(
            &self.key,
            challenge.id(),
            challenge.expires_at(),
            challenge.nonce(),
            challenge.params(),
        );
        let tampered = expected.ct_ne(&challenge.auth_tag());
        if bool::from(tampered) {
            return Err(PbcpError::WrongChallenge);
        }

        if proof.nonce().time() > challenge.expires_at()
            || unix_now() > challenge.expires_at()
        {
            return Err(PbcpError::Expired);
        }

        let mut input = match proof.claims().to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => return Err(e),
        };

        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.evict(unix_now());
        if seen.contains(challenge.id(), challenge.expires_at()) {
            #[cfg(feature = "zeroize")]
            input.zeroize();

            return Err(PbcpError::Replayed);
        }
        seen.record(challenge.id(), challenge.expires_at());
        drop(seen);

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

    /// Verify a [Proof] and report the result as an [Outcome].
    pub fn judge(&self, proof: &Proof) -> Outcome {
        let id = proof.challenge().id();

        match self.verify(proof) {
            Ok(true) => Outcome::Accepted(id),
            Ok(false) => Outcome::Rejected(id),
            Err(e) => Outcome::from_error(id, e),
        }
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

struct Seen(BTreeSet<(u64, Ulid)>);

impl Seen {
    fn new() -> Self {
        Self(BTreeSet::new())
    }

    fn contains(&self, id: Ulid, expires_at: u64) -> bool {
        self.0.contains(&(expires_at, id))
    }

    fn record(&mut self, id: Ulid, expires_at: u64) {
        self.0.insert((expires_at, id));
    }

    fn evict(&mut self, now: u64) {
        while let Some(&(expiry, _)) = self.0.first() {
            if expiry >= now {
                break;
            }
            self.0.pop_first();
        }
    }
}

fn auth_tag(
    key: &[u8; 32],
    id: Ulid,
    expires_at: u64,
    nonce: &[u8],
    params: Params,
) -> [u8; 16] {
    let mut hasher = Hasher::new();

    hasher.update(key);
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
    hasher.update(&nonce);

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

/*
#[cfg(test)]
mod tests {
    use crate::common::{Claims, Counter};

    use super::*;

    type Error = PbcpError;

    const CONTEXT: &str = "PBCP_TEST";
    const NONCE: &[u8] = b"This is a challenge nonce";
    const TTL: u64 = 300;

    /// Parameters for testing.
    fn params() -> Params {
        Params::new(8, 2, 2, 12).expect("test parameters are valid")
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

    #[test]
    fn new_applies_ttl() {
        let params = params();

        let before = unix_now() + TTL;
        let verifier = Verifier::new(CONTEXT, NONCE, TTL, params);
        let after = unix_now() + TTL;

        assert!((before..=after).contains(&verifier.expires_at));
    }

    #[test]
    fn to_challenge_carries_fields() {
        let params = params();
        let verifier = Verifier::new(CONTEXT, NONCE, TTL, params);
        let challenge = verifier.to_challenge();

        assert_eq!(challenge.id(), verifier.id());
        assert_eq!(challenge.expires_at(), verifier.expires_at());
        assert_eq!(challenge.nonce(), verifier.nonce());
        assert_eq!(challenge.params(), verifier.params());
    }

    #[test]
    fn verify_rejects_wrong_challenge() {
        let params = params();
        let verifier = Verifier::new(CONTEXT, NONCE, TTL, params);

        let id = Ulid::generate();
        let claims = claims();
        let nonce = counter_at(unix_now());
        let proof = Proof::new(id, &claims, nonce);

        let result = verifier.verify(&proof);
        assert!(matches!(result.err(), Some(Error::WrongChallenge)));
    }

    #[test]
    fn verify_rejects_after_expiry() {
        let params = params();
        let mut verifier = Verifier::new(CONTEXT, NONCE, TTL, params);

        // The verifier's clock is within the TTL, only the nonce time rejects
        let nonce = counter_at(verifier.expires_at() + 1);
        let proof = Proof::new(verifier.id(), &claims(), nonce);
        let result = verifier.verify(&proof);
        assert!(matches!(result.err(), Some(Error::Expired)));

        // The nonce time is within the TTL, only the verifier's clock rejects
        verifier.expires_at = unix_now() - 1;
        let nonce = counter_at(verifier.expires_at());
        let proof = Proof::new(verifier.id(), &claims(), nonce);
        let result = verifier.verify(&proof);
        assert!(matches!(result.err(), Some(Error::Expired)));
    }
}
*/
