#![allow(clippy::module_inception)]
#![cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
#![doc = include_str!("../README.md")]
//! ## Example
//! ```
//! use pbcp::{Claims, Pbcp, PbcpError, ReplayStore, TvParams};
//!
//! fn main() {
//!     // Create a new PBCP context
//!     let params = TvParams::new(12 * 1024, 3, 8, 12).expect("valid params");
//!     let pbcp = Pbcp::new("This is a context string", params);
//!
//!     // Issue a new challenge
//!     let key = [0u8; 32];
//!     let ttl = 300;
//!
//!     let challenge = pbcp
//!         .verifier(&key, ttl)
//!         .issue(b"This is a challenge nonce".as_ref())
//!         .expect("nonce below 64 bytes");
//!
//!     // Build JWT-style claims
//!     let claims = Claims::builder()
//!         .claim("iss", "https://humanity.example")
//!         .claim("sub", "Homo sapiens")
//!         .claim("aud", "https://humans-only.example")
//!         .claim("iat", 1786554930)
//!         .claim("exp", 1786561137)
//!         .build();
//!
//!     // Create a prover from the challenge, then mine a proof over the claims
//!     let prover = pbcp.prover(&challenge).expect("parameters in range");
//!     let proof = prover
//!         .prove(&claims)
//!         .expect("any valid Claims are provable");
//!
//!     // Create a verifier and in-memory replay storage
//!     let verifier = pbcp.verifier(&key, ttl);
//!     let store = ReplayStore::new();
//!
//!     // The proof is accepted for the challenge
//!     let result = verifier.verify(&proof, Some(&store));
//!     assert!(result.is_ok());
//!     let valid = result.expect("result is Ok");
//!     assert!(valid);
//!
//!     // Resubmitting the proof rejects for challenge replay
//!     let result = verifier.verify(&proof, Some(&store));
//!     assert!(matches!(result.err(), Some(PbcpError::Replayed)));
//! }
//! ```
//! ## Features
//!
//! The `zeroize` feature (disabled by default) implements `Zeroize` and
//! `ZeroizeOnDrop` for `Claims`, `ClaimsBuilder`, `Proof`, and `Verifier`.
//! Intermediate values are zeroized on a best-effort basis.
mod common;
mod errors;
mod prover;
mod verifier;

use crate::common::unix_now;
pub use crate::common::{Claims, ClaimsBuilder, Counter};
pub use crate::errors::PbcpError;
pub use crate::prover::{Proof, Prover};
pub use crate::verifier::{BackendError, Challenge, ReplayStore, Verifier};

/// Alias for TraverseV proof-of-work parameters.
pub type TvParams = traversev::Params;

/// Proof-Bound Claims Protocol (PBCP) Context.
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

        if unix_now() > challenge.expires_at() {
            return Err(PbcpError::Expired);
        }

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
            .prover(&verifier.issue(NONCE).expect("nonce below 64 bytes"))
            .expect("challenge is within limits");
        assert_eq!(prover.challenge().nonce(), NONCE);
    }

    #[test]
    fn proof_verifies() {
        let pbcp = Pbcp::new(CONTEXT, params());
        let verifier = pbcp.verifier(&KEY, TTL);

        let prover = pbcp
            .prover(&verifier.issue(NONCE).expect("nonce below 64 bytes"))
            .expect("challenge is within limits");

        let claims = claims();
        let proof = prover
            .prove(&claims)
            .expect("any valid Claims are provable");

        let result = verifier.verify(&proof, None);
        assert!(result.is_ok());

        let valid = result.expect("result is Ok");
        assert!(valid);
    }

    #[test]
    fn prover_accepts_challenge_at_limits() {
        let pbcp = Pbcp::new(CONTEXT, params());
        let challenge = pbcp
            .verifier(&KEY, TTL)
            .issue(NONCE)
            .expect("nonce below 64 bytes");

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
