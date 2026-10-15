use traversev::TraverseV;
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::common::{Claims, Counter, derive_secret};
use crate::errors::PbcpError;
use crate::prover::Proof;
use crate::verifier::Challenge;

/// Prover for [Pbcp], capable of mining a proof over [Claims] for a received
/// challenge.
#[derive(Debug)]
pub struct Prover {
    challenge: Challenge,
    tv: TraverseV,
}

impl Prover {
    pub(crate) fn new(context: &str, challenge: &Challenge) -> Self {
        let nonce = challenge.nonce();
        let params = challenge.params();

        let mut secret = derive_secret(&challenge.id(), &nonce);
        let tv = TraverseV::new_permissioned(&secret, context, params);

        #[cfg(feature = "zeroize")]
        secret.zeroize();

        Self {
            challenge: challenge.clone(),
            tv,
        }
    }

    /// Mine a [Proof] over the given [Claims] for the challenge this [Prover]
    /// was constructed from.
    ///
    /// Mining searches until a satisfying nonce is found, so runtime is
    /// unbounded at high difficulties.
    pub fn prove(&self, claims: &Claims) -> Result<Proof, PbcpError> {
        let mut input = claims.to_bytes()?;
        let mut nonce: Counter = self.tv.mine(&input, Counter::default(), 1);

        #[cfg(feature = "zeroize")]
        input.zeroize();

        let proof = Proof::new(&self.challenge, claims, nonce);

        #[cfg(feature = "zeroize")]
        nonce.zeroize();

        Ok(proof)
    }

    /// Returns this prover's challenge identifier.
    pub const fn id(&self) -> Ulid {
        self.challenge.id()
    }
}

/*
#[cfg(test)]
mod tests {
    use traversev::Params;

    use crate::common::unix_now;

    use super::*;

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

    fn challenge(id: Ulid) -> Challenge {
        let expires_at = unix_now() + TTL;
        Challenge::new(id, expires_at, NONCE, params())
    }

    #[test]
    fn prove_binds_challenge_and_claims() {
        let id = Ulid::generate();
        let prover = Prover::new(CONTEXT, &challenge(id));
        let claims = claims();

        let proof = prover
            .prove(&claims)
            .expect("any valid Claims are provable");

        assert_eq!(proof.id(), id);
        assert_eq!(proof.claims(), &claims);
    }

    #[test]
    fn accessor_returns_own_field() {
        let id = Ulid::generate();
        let prover = Prover::new(CONTEXT, &challenge(id));

        assert_eq!(prover.id(), id);
    }
}
*/
