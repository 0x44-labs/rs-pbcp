use http::Uri;
use serde::{Deserialize, Serialize};

use crate::common::{URI_SCHEME, Wire, host_query};
use crate::errors::PbcpError;

/// The verifier's verdict on a submitted proof. Only
/// [Accepted](Outcome::Accepted) indicates success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The proof is valid.
    Accepted,

    /// The challenge has expired.
    Expired,

    /// The submission could not be parsed or was structurally invalid.
    Malformed,

    /// The submission was well-formed but the proof-of-work did not verify.
    Rejected,

    /// A proof was already submitted for this challenge.
    Replayed,

    /// The proof was not bound to a challenge issued by this verifier.
    #[serde(rename = "wrong_challenge")]
    WrongChallenge,
}

impl Outcome {
    pub(crate) fn from_error(error: PbcpError) -> Self {
        match error {
            PbcpError::Expired => Self::Expired,
            PbcpError::Replayed => Self::Replayed,
            PbcpError::WrongChallenge => Self::WrongChallenge,
            _ => Self::Malformed,
        }
    }

    /// Serialise this [Outcome] to a `pbcp://result` URI.
    pub fn to_uri(&self) -> Result<Uri, PbcpError> {
        let p_and_q = OutcomeWire { outcome: *self }.path_and_query()?;
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

        Ok(wire.outcome)
    }

    /// Returns `true` only for the [Accepted](Outcome::Accepted) variant.
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeWire {
    outcome: Outcome,
}

impl Wire for OutcomeWire {}
