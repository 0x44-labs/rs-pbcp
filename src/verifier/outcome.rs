use http::Uri;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::common::{URI_SCHEME, Wire, host_query};
use crate::errors::PbcpError;

/// The verifier's verdict on a submitted proof. Only
/// [Accepted](Outcome::Accepted) indicates success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The proof is valid.
    Accepted(Ulid),

    /// The challenge has expired.
    Expired(Ulid),

    /// The submission could not be parsed or was structurally invalid.
    Malformed(Ulid),

    /// The submission was well-formed but the proof-of-work did not verify.
    Rejected(Ulid),

    /// A proof was already submitted for this challenge.
    Replayed(Ulid),

    /// The proof was not bound to a challenge issued by this verifier.
    WrongChallenge(Ulid),
}

impl Outcome {
    pub(crate) fn from_error(id: Ulid, error: PbcpError) -> Self {
        match error {
            PbcpError::Expired => Self::Expired(id),
            PbcpError::Replayed => Self::Replayed(id),
            PbcpError::WrongChallenge => Self::WrongChallenge(id),
            _ => Self::Malformed(id),
        }
    }

    /// Serialise this [Outcome] to a `pbcp://result` URI.
    pub fn to_uri(&self) -> Result<Uri, PbcpError> {
        let wire = OutcomeWire {
            id: self.id(),
            outcome: Kind::from(*self),
        };

        let p_and_q = wire.path_and_query()?;
        let uri = Uri::builder()
            .scheme(URI_SCHEME)
            .authority("result")
            .path_and_query(p_and_q)
            .build()?;

        Ok(uri)
    }

    /// Parse an [Outcome] from a `pbcp://result` URI.
    pub fn from_uri(uri: &Uri) -> Result<Self, PbcpError> {
        let query = host_query(uri, "result")?;
        let wire: OutcomeWire = serde_qs::from_str(query)?;

        let id = wire.id;
        Ok(match wire.outcome {
            Kind::Accepted => Self::Accepted(id),
            Kind::Expired => Self::Expired(id),
            Kind::Malformed => Self::Malformed(id),
            Kind::Rejected => Self::Rejected(id),
            Kind::Replayed => Self::Replayed(id),
            Kind::WrongChallenge => Self::WrongChallenge(id),
        })
    }

    /// Returns the challenge identifier this [Outcome] refers to.
    pub const fn id(&self) -> Ulid {
        match self {
            Self::Accepted(id)
            | Self::Expired(id)
            | Self::Malformed(id)
            | Self::Rejected(id)
            | Self::Replayed(id)
            | Self::WrongChallenge(id) => *id,
        }
    }

    /// Returns `true` only for [Accepted](OutcomeKind::Accepted) outcomes.
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Accepted,
    Expired,
    Malformed,
    Rejected,
    Replayed,
    WrongChallenge,
}

impl From<Outcome> for Kind {
    fn from(value: Outcome) -> Self {
        match value {
            Outcome::Accepted(_) => Self::Accepted,
            Outcome::Expired(_) => Self::Expired,
            Outcome::Malformed(_) => Self::Malformed,
            Outcome::Rejected(_) => Self::Rejected,
            Outcome::Replayed(_) => Self::Replayed,
            Outcome::WrongChallenge(_) => Self::WrongChallenge,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeWire {
    id: Ulid,
    outcome: Kind,
}

impl Wire for OutcomeWire {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_error_maps_errors() {
        let id = Ulid::generate();

        // Expired, Replayed, and WrongChallenge have explicit mappings
        assert_eq!(
            Outcome::from_error(id, PbcpError::Expired),
            Outcome::Expired(id)
        );
        assert_eq!(
            Outcome::from_error(id, PbcpError::Replayed),
            Outcome::Replayed(id)
        );
        assert_eq!(
            Outcome::from_error(id, PbcpError::WrongChallenge),
            Outcome::WrongChallenge(id)
        );

        // All other errors are Malformed outcomes
        assert_eq!(
            Outcome::from_error(id, PbcpError::InvalidHost),
            Outcome::Malformed(id)
        );
    }

    #[test]
    fn uri_round_trip() {
        let id = Ulid::generate();

        for original in [
            Outcome::Accepted(id),
            Outcome::Expired(id),
            Outcome::Malformed(id),
            Outcome::Rejected(id),
            Outcome::Replayed(id),
            Outcome::WrongChallenge(id),
        ] {
            let uri =
                original.to_uri().expect("valid Outcome serialises to URI");

            let reconstructed =
                Outcome::from_uri(&uri).expect("valid URI parses to Outcome");
            assert_eq!(original, reconstructed);
        }
    }

    #[test]
    fn id_returns_challenge_id() {
        let id = Ulid::generate();
        let outcome = Outcome::Accepted(id);

        assert_eq!(outcome.id(), id);
    }

    #[test]
    fn is_accepted_only_for_accepted() {
        let id = Ulid::generate();

        // Accepted outcome returns true
        let accepted = Outcome::Accepted(id);
        assert!(accepted.is_accepted());

        // Rejected outcome returns false
        let rejected = Outcome::Rejected(id);
        assert!(!rejected.is_accepted());
    }
}
