use traversev::{Params, TraverseV};
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::common::{derive_secret, unix_now};
use crate::errors::PbcpError;
use crate::prover::Proof;
use crate::verifier::Challenge;

/// Verifier for [Pbcp], capable of issuing a [Challenge] and evaluating any
/// received [Proof] for authenticity.
#[derive(Debug)]
pub struct Verifier {
    id: Ulid,
    expires_at: u64,
    nonce: Vec<u8>,
    tv: TraverseV,
    params: Params,
}

impl Verifier {
    pub(crate) fn new(
        context: &str,
        nonce: &[u8],
        ttl: u64,
        params: Params,
    ) -> Self {
        let id = Ulid::generate();
        let expires_at = unix_now() + ttl;

        let mut secret = derive_secret(&id, nonce);
        let tv = TraverseV::new_permissioned(&secret, context, params);

        #[cfg(feature = "zeroize")]
        secret.zeroize();

        Self {
            id,
            expires_at,
            nonce: nonce.to_vec(),
            tv,
            params,
        }
    }

    /// Create a [Challenge] from this verifier.
    pub fn to_challenge(&self) -> Challenge {
        Challenge::new(self.id, self.expires_at, &self.nonce, self.params)
    }

    /// Verify a [Proof] against this verifier's challenge, returning
    /// whether its nonce is a valid proof over its claims.
    ///
    /// Returns an error if the proof belongs to a different challenge or the
    /// challenge has expired.
    pub fn verify(&self, proof: &Proof) -> Result<bool, PbcpError> {
        if proof.id() != self.id {
            return Err(PbcpError::WrongChallenge);
        }
        if proof.nonce().time() > self.expires_at
            || unix_now() > self.expires_at
        {
            return Err(PbcpError::Expired);
        }

        let mut input = match proof.claims().to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => return Err(e),
        };
        let mut nonce = proof.nonce();
        let valid = self.tv.verify(&input, nonce);

        #[cfg(feature = "zeroize")]
        {
            input.zeroize();
            nonce.zeroize();
        }

        Ok(valid)
    }

    /// Returns this verifier's challenge identifier.
    pub const fn id(&self) -> Ulid {
        self.id
    }

    /// Returns the time of expiration for this verifier's challenge.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns a reference to this verifier's challenge nonce.
    pub const fn nonce(&self) -> &Vec<u8> {
        &self.nonce
    }

    /// Returns this verifier's proof-of-work parameters.
    pub const fn params(&self) -> Params {
        self.params
    }
}

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
