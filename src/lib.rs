#![cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
//! ## Features
//!
//! The `zeroize` feature (disabled by default) implements `Zeroize` and
//! `ZeroizeOnDrop` for `Claims`, `ClaimsBuilder`, and `Proof`, and
//! zeroises intermediate values on a best-effort basis.
mod common;
mod errors;
mod prover;
mod verifier;

pub use crate::common::{Claims, ClaimsBuilder, Counter};
pub use crate::errors::PbcpError;
pub use crate::prover::{Proof, Prover};
pub use crate::verifier::{Challenge, Outcome, ReplayStore, Verifier};

/// Alias for TraverseV proof-of-work parameters.
pub type TvParams = traversev::Params;

/// Proof-Bound Claims Protocol (PBCP) context.
///
/// This is the primary type of this crate's API, and creates the two roles of
/// a PBCP exchange: [Verifier] and [Prover]. It contains the following:
/// - Application context string, shared by both roles.
/// - TraverseV [Params](TvParams), used for the challenges its verifiers issue
///   and as the ceiling for the challenges its provers accept.
#[derive(Debug, Clone)]
pub struct Pbcp {
    context: String,
    params: TvParams,
}

impl Pbcp {
    /// Create a new PBCP context.
    pub fn new(context: impl Into<String>, params: TvParams) -> Self {
        Self {
            context: context.into(),
            params,
        }
    }

    /// Create a new keyed [Verifier] with the given time to live (TTL) in
    /// seconds.
    ///
    /// All challenges expires `ttl` seconds after the verifier issues them.
    pub fn verifier(&self, key: &[u8; 32], ttl: u64) -> Verifier {
        Verifier::new(&self.context, key, ttl, self.params)
    }

    /// Create a new [Prover] for the given [Challenge].
    ///
    /// Returns an error if the challenge parameters exceed those of this
    /// context.
    pub fn prover(&self, challenge: &Challenge) -> Result<Prover, PbcpError> {
        let limit = self.params;
        let requested = challenge.params();

        if requested.m_cost() > limit.m_cost()
            || requested.t_cost() > limit.t_cost()
            || requested.e_cost() > limit.e_cost()
            || requested.n_cost() > limit.n_cost()
        {
            return Err(PbcpError::TooCostly);
        }

        Ok(Prover::new(&self.context, challenge))
    }
}

#[cfg(test)]
mod tests {
    use ulid::Ulid;

    use crate::common::unix_now;

    use super::*;

    const CONTEXT: &str = "This is a context string";
    const KEY: [u8; 32] = [0u8; 32];
    const TTL: u64 = 300;
    const NONCE: &[u8] = b"This is a challenge nonce";

    /// Parameters for testing.
    fn params() -> TvParams {
        TvParams::new(8, 2, 2, 12).expect("valid parameters")
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
    fn verifier_creates_verifier() {
        let pbcp = Pbcp::new(CONTEXT, params());

        let verifier = pbcp.verifier(&KEY, TTL);
        assert_eq!(verifier.ttl(), TTL);
    }

    #[test]
    fn prover_creates_from_challenge() {
        let pbcp = Pbcp::new(CONTEXT, params());
        let verifier = pbcp.verifier(&KEY, TTL);

        let prover = pbcp
            .prover(&verifier.issue(NONCE))
            .expect("challenge is within limits");
        assert_eq!(prover.challenge().nonce(), NONCE);
    }

    #[test]
    fn proof_verifies() {
        let pbcp = Pbcp::new(CONTEXT, params());

        let verifier = pbcp.verifier(&KEY, TTL);
        let store = ReplayStore::new();

        let prover = pbcp
            .prover(&verifier.issue(NONCE))
            .expect("challenge is within limits");

        let claims = claims();
        let proof = prover
            .prove(&claims)
            .expect("any valid Claims are provable");

        let result = verifier.verify(&proof, &store);
        assert!(result.is_ok());

        let valid = result.unwrap();
        assert_eq!(valid, true);
    }

    #[test]
    fn prover_accepts_challenge_at_limits() {
        let pbcp = Pbcp::new(CONTEXT, params());
        let challenge = pbcp.verifier(&KEY, TTL).issue(NONCE);

        let result = pbcp.prover(&challenge);
        assert!(result.is_ok());
    }

    #[test]
    fn prover_rejects_challenge_exceeding_limits() {
        let pbcp = Pbcp::new(CONTEXT, params());

        for (m_cost, t_cost, e_cost, n_cost) in
            [(9, 2, 2, 12), (8, 3, 2, 12), (8, 2, 3, 12), (8, 2, 2, 13)]
        {
            let params = TvParams::new(m_cost, t_cost, e_cost, n_cost)
                .expect("test parameters are valid");
            let challenge = Challenge::new(
                Ulid::generate(),
                unix_now() + TTL,
                NONCE,
                params,
                [0u8; 16],
            );

            let result = pbcp.prover(&challenge);
            assert!(matches!(result.err(), Some(PbcpError::TooCostly)));
        }
    }
}
