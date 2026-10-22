use crate::errors::PbcpError;

/// A verifier's verdict on a submitted proof.
///
/// Only [Accepted](Outcome::Accepted) indicates success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The proof is valid.
    Accepted,

    /// The challenge has expired.
    Expired,

    /// This verifier's internal failure prevented verification of the proof.
    InternalFail,

    /// The submission could not be parsed or was structurally invalid.
    Malformed,

    /// The submission was well-formed but the proof-of-work did not verify.
    Rejected,

    /// A proof was already submitted for this challenge.
    Replayed,

    /// The proof was not bound to a challenge issued by this verifier.
    WrongChallenge,
}

impl Outcome {
    pub(crate) fn from_error(error: PbcpError) -> Self {
        match error {
            PbcpError::Expired => Self::Expired,
            PbcpError::StoreFail(_) => Self::InternalFail,
            PbcpError::Replayed => Self::Replayed,
            PbcpError::WrongChallenge => Self::WrongChallenge,
            _ => Self::Malformed,
        }
    }

    /// Returns `true` only for [Accepted](Outcome::Accepted) outcomes.
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_error_maps_errors() {
        // Expired, StoreFail, Replayed, and WrongChallenge have explicit mappings
        assert_eq!(Outcome::from_error(PbcpError::Expired), Outcome::Expired);
        assert_eq!(
            Outcome::from_error(PbcpError::StoreFail(
                "backend unavailable".into()
            )),
            Outcome::InternalFail
        );
        assert_eq!(Outcome::from_error(PbcpError::Replayed), Outcome::Replayed);
        assert_eq!(
            Outcome::from_error(PbcpError::WrongChallenge),
            Outcome::WrongChallenge
        );

        // All other errors are Malformed outcomes
        assert_eq!(
            Outcome::from_error(PbcpError::InvalidHost),
            Outcome::Malformed
        );
    }

    #[test]
    fn is_accepted_only_for_accepted() {
        // Accepted outcome returns true
        let accepted = Outcome::Accepted;
        assert!(accepted.is_accepted());

        // Rejected outcome returns false
        let rejected = Outcome::Rejected;
        assert!(!rejected.is_accepted());
    }
}
