use http::Uri;
use serde::{Deserialize, Serialize};
use serde_qs;
use traversev::Params;
use ulid::Ulid;

use crate::common::{URI_SCHEME, Wire, b64url_vec, host_query, non_default};
use crate::errors::PbcpError;

/// A [verifier](crate::verifier::Verifier)-issued challenge.
///
/// Carries a unique identifier, expiration, nonce value, and parameters, all
/// bound to the issuer by an authentication tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    id: Ulid,
    expires_at: u64,
    nonce: Vec<u8>,
    params: Params,
    auth_tag: [u8; 16],
}

impl Challenge {
    /// Create a new [Challenge] with the given challenge identifier, time
    /// of expiration, nonce, TraverseV parameters, and authentication tag.
    pub fn new(
        id: Ulid,
        expires_at: u64,
        nonce: &[u8],
        params: Params,
        auth_tag: [u8; 16],
    ) -> Self {
        Self {
            id,
            expires_at,
            nonce: nonce.to_vec(),
            params,
            auth_tag,
        }
    }

    /// Serialise this [Challenge] to a `pbcp://challenge` URI, omitting
    /// parameters that have their default values.
    pub fn to_uri(&self) -> Result<Uri, PbcpError> {
        let wire = ChallengeWire::from(self);

        let p_and_q = wire.path_and_query()?;
        let uri = Uri::builder()
            .scheme(URI_SCHEME)
            .authority("challenge")
            .path_and_query(p_and_q)
            .build()?;

        Ok(uri)
    }

    /// Parse a [Challenge] from a `pbcp://challenge` URI, using defaults for
    /// omitted parameters.
    pub fn from_uri(uri: &Uri) -> Result<Self, PbcpError> {
        let query = host_query(uri, "challenge")?;
        let wire: ChallengeWire = serde_qs::from_str(query)?;

        Challenge::try_from(wire)
    }

    /// Serialise this [Challenge] to CBOR bytes, omitting parameters that have
    /// their default values.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PbcpError> {
        let mut buf = Vec::new();
        ciborium::into_writer(&ChallengeWire::from(self), &mut buf)?;
        Ok(buf)
    }

    /// Parse a [Challenge] from CBOR bytes, using defaults for omitted
    /// parameters.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PbcpError> {
        let wire: ChallengeWire = ciborium::from_reader(bytes)?;
        Challenge::try_from(wire)
    }

    /// Returns the challenge identifier.
    pub const fn id(&self) -> Ulid {
        self.id
    }

    /// Returns the time of challenge expiration.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns a reference to the nonce.
    pub const fn nonce(&self) -> &Vec<u8> {
        &self.nonce
    }

    /// Returns the parameters.
    pub const fn params(&self) -> Params {
        self.params
    }

    /// Returns the authentication tag.
    pub const fn auth_tag(&self) -> [u8; 16] {
        self.auth_tag
    }
}

impl TryFrom<ChallengeWire> for Challenge {
    type Error = PbcpError;

    fn try_from(value: ChallengeWire) -> Result<Self, Self::Error> {
        let params = Params::new(
            value.m_cost.unwrap_or(traversev::Params::DEFAULT_M),
            value.t_cost.unwrap_or(traversev::Params::DEFAULT_T),
            value.e_cost.unwrap_or(traversev::Params::DEFAULT_E),
            value.n_cost.unwrap_or(traversev::Params::DEFAULT_N),
        )
        .map_err(|e| Self::Error::Params(e))?;

        let auth_tag: [u8; 16] = value
            .auth_tag
            .clone()
            .try_into()
            .map_err(|_| Self::Error::TagLen)?;

        Ok(Challenge {
            id: value.id,
            expires_at: value.expires_at,
            nonce: value.nonce.clone(),
            params,
            auth_tag,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[serde(deny_unknown_fields)]
pub(crate) struct ChallengeWire {
    pub(crate) id: Ulid,
    pub(crate) expires_at: u64,
    #[serde(with = "b64url_vec")]
    pub(crate) nonce: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) m_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) t_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) e_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) n_cost: Option<u32>,
    #[serde(with = "b64url_vec")]
    pub(crate) auth_tag: Vec<u8>,
}

impl Wire for ChallengeWire {}

impl From<&Challenge> for ChallengeWire {
    fn from(value: &Challenge) -> Self {
        Self {
            id: value.id,
            expires_at: value.expires_at,
            nonce: value.nonce.clone(),
            m_cost: non_default(value.params.m_cost(), Params::DEFAULT_M),
            t_cost: non_default(value.params.t_cost(), Params::DEFAULT_T),
            e_cost: non_default(value.params.e_cost(), Params::DEFAULT_E),
            n_cost: non_default(value.params.n_cost(), Params::DEFAULT_N),
            auth_tag: value.auth_tag.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    type Error = PbcpError;

    const TIME: u64 = 1786558105;
    const TTL: u64 = 300;
    const NONCE: &[u8] = b"This is a challenge nonce";

    fn challenge(id: Ulid, params: Params) -> Challenge {
        Challenge::new(
            id,
            TIME + 300,
            b"This is a challenge nonce",
            params,
            [0u8; 16],
        )
    }

    fn challenge_query() -> String {
        format!(
            "id={}&expires_at={}&nonce={}&auth_tag={}",
            Ulid::generate(),
            TIME + TTL,
            URL_SAFE_NO_PAD.encode(NONCE),
            URL_SAFE_NO_PAD.encode([0u8; 16])
        )
    }

    fn parse_uri(authority: &str, query: &str) -> Uri {
        format!("pbcp://{authority}/?{query}")
            .parse()
            .expect("valid URI")
    }

    #[test]
    fn uri_round_trip() {
        let default_params = Params::default();
        let custom_params = Params::new(16 * 1024, 2, 4, 12)
            .expect("valid parameters for TraverseV");

        for params in [default_params, custom_params] {
            let original = challenge(Ulid::generate(), params);
            let uri = original
                .to_uri()
                .expect("valid Challenge serialises to URI");

            let reconstructed = Challenge::from_uri(&uri)
                .expect("valid URI parses to Challenge");
            assert_eq!(original, reconstructed);
        }
    }

    #[test]
    fn from_uri_rejects_missing_field() {
        let uri = parse_uri("challenge", "start=1");
        let result = Challenge::from_uri(&uri);
        assert!(matches!(result.err(), Some(Error::QueryString(_))));
    }

    #[test]
    fn from_uri_rejects_invalid_params() {
        let uri =
            parse_uri("challenge", &format!("{}&m_cost=1", challenge_query()));
        let result = Challenge::from_uri(&uri);
        assert!(matches!(result.err(), Some(Error::Params(_))));
    }

    #[test]
    fn cbor_bytes_round_trip() {
        let params = Params::new(8, 2, 2, 12).expect("valid parameters");

        let original = challenge(Ulid::generate(), params);
        let bytes = original
            .to_bytes()
            .expect("valid Challenge serialises to CBOR bytes");

        let reconstructed = Challenge::from_bytes(&bytes)
            .expect("valid CBOR bytes parse to Challenge");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn accessors_return_their_own_field() {
        let id = Ulid::generate();
        let params = Params::default();
        let challenge = challenge(id, params);

        assert_eq!(challenge.id(), id);
        assert_eq!(challenge.expires_at(), TIME + TTL);
        assert_eq!(challenge.nonce(), &NONCE.to_vec());
        assert_eq!(challenge.params(), params);
        assert_eq!(challenge.auth_tag(), [0u8; 16]);
    }
}
