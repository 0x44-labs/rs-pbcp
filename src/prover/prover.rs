use traversev::TraverseV;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::common::{Claims, Counter, derive_secret, unix_now};
use crate::errors::PbcpError;
use crate::prover::Proof;
use crate::verifier::Challenge;

/// Proof-Bound Claims Protocol (PBCP) Prover.
///
/// Capable of mining a proof over [Claims] for a received challenge.
#[derive(Debug)]
pub struct Prover {
    challenge: Challenge,
    tv: TraverseV,
}

impl Prover {
    pub(crate) fn new(context: &str, challenge: &Challenge) -> Self {
        let nonce = challenge.nonce();
        let params = challenge.params();

        let mut secret = derive_secret(&challenge.id(), nonce);
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
        if unix_now() > self.challenge.expires_at() {
            return Err(PbcpError::Expired);
        }

        let mut input = claims.to_bytes()?;
        let mut nonce: Counter = self.tv.mine(&input, Counter::default(), 1);

        #[cfg(feature = "zeroize")]
        input.zeroize();

        let proof = Proof::new(&self.challenge, claims, nonce);

        #[cfg(feature = "zeroize")]
        nonce.zeroize();

        Ok(proof)
    }

    /// Returns a reference to this prover's challenge.
    pub const fn challenge(&self) -> &Challenge {
        &self.challenge
    }
}

#[cfg(test)]
mod tests {
    use traversev::Params;
    use ulid::Ulid;

    use crate::common::unix_now;

    use super::*;

    const CONTEXT: &str = "This is a context string";

    fn challenge() -> Challenge {
        Challenge::new(
            Ulid::generate(),
            unix_now() + 300,
            b"This is a challenge nonce",
            Params::new(8, 2, 2, 12).expect("valid parameters"),
            [0u8; 16],
        )
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

    #[test]
    fn prove_mines_proof() {
        let prover = Prover::new(CONTEXT, &challenge());
        let claims = claims();

        let result = prover.prove(&claims);
        assert!(result.is_ok());
    }

    #[test]
    fn challenge_returns_challenge() {
        let challenge = challenge();
        let prover = Prover::new(CONTEXT, &challenge);

        assert_eq!(prover.challenge(), &challenge);
    }
}
