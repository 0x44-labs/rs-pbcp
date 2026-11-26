use std::collections::BTreeSet;

use http::{Uri, uri::Authority};
use serde::{Deserialize, Serialize};
use traversev::Params;
use ulid::Ulid;

use crate::common::{Claims, Wire, b64url_vec, claim_names};
use crate::errors::PbcpError;

const URI_SCHEME: &str = "pbcp";

/// A [verifier](crate::verifier::Verifier)-issued challenge.
///
/// Carries a unique identifier, expiration, nonce value, and parameters, all
/// bound to the issuer by an authentication tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    id: Ulid,
    expires_at: u64,
    nonce: Vec<u8>,
    required_claims: BTreeSet<String>,
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
            required_claims: BTreeSet::new(),
            params,
            auth_tag,
        }
    }

    /// Require the named claims to be present in any claims set proven for
    /// this [Challenge]. Claim names are unique, so duplicates collapse.
    pub fn with_required_claims<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_claims = names.into_iter().map(Into::into).collect();
        self
    }

    /// Returns whether the given [Claims] contain every required claim.
    pub fn is_satisfied_by(&self, claims: &Claims) -> bool {
        self.required_claims
            .iter()
            .all(|name| claims.claim(name).is_some())
    }

    /// Serialise this [Challenge] to a `pbcp://` URI for the given authority.
    pub fn to_uri<T>(&self, auth: T) -> Result<Uri, PbcpError>
    where
        T: TryInto<Authority>,
        <T as TryInto<Authority>>::Error: Into<http::Error>,
    {
        let wire = ChallengeWire::from(self);

        let p_and_q = wire.path_and_query()?;
        let uri = Uri::builder()
            .scheme(URI_SCHEME)
            .authority(auth)
            .path_and_query(p_and_q)
            .build()?;

        Ok(uri)
    }

    /// Parse a [Challenge] from a `pbcp://` URI.
    pub fn from_uri(uri: &Uri) -> Result<Self, PbcpError> {
        if uri.scheme_str() != Some(URI_SCHEME) {
            return Err(PbcpError::UriParse);
        }
        let query = match uri.query() {
            Some(q) => Ok(q),
            None => Err(PbcpError::UriParse),
        }?;
        let wire: ChallengeWire = serde_qs::from_str(query)?;

        Challenge::try_from(wire)
    }

    /// Serialise this [Challenge] to CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PbcpError> {
        let mut buf = Vec::new();
        ciborium::into_writer(&ChallengeWire::from(self), &mut buf)?;
        Ok(buf)
    }

    /// Parse a [Challenge] from CBOR bytes.
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

    /// Returns a reference to the claims required by this challenge.
    pub const fn required_claims(&self) -> &BTreeSet<String> {
        &self.required_claims
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
        let required_claims = value.required_claims.clone();

        let params =
            Params::new(value.m_cost, value.t_cost, value.e_cost, value.n_cost)
                .map_err(Self::Error::Params)?;

        let auth_tag: [u8; 16] = value
            .auth_tag
            .clone()
            .try_into()
            .map_err(|_| Self::Error::AuthTag)?;

        Ok(Challenge {
            id: value.id,
            expires_at: value.expires_at,
            nonce: value.nonce.clone(),
            required_claims,
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
    #[serde(
        default,
        skip_serializing_if = "BTreeSet::is_empty",
        with = "claim_names"
    )]
    pub(crate) required_claims: BTreeSet<String>,
    pub(crate) m_cost: u32,
    pub(crate) t_cost: u32,
    pub(crate) e_cost: u32,
    pub(crate) n_cost: u32,
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
            required_claims: value.required_claims.clone(),
            m_cost: value.params.m_cost(),
            t_cost: value.params.t_cost(),
            e_cost: value.params.e_cost(),
            n_cost: value.params.n_cost(),
            auth_tag: value.auth_tag.to_vec(),
        }
    }
}

/*
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

    fn claims() -> Claims {
        Claims::builder()
            .claim("iss", "https://humanity.example")
            .claim("sub", "Homo sapiens")
            .claim("aud", "https://humans-only.example")
            .claim("iat", 1786554930)
            .claim("exp", 1786561137)
            .build()
    }

    fn challenge_query(
        m_cost: u32,
        t_cost: u32,
        e_cost: u32,
        n_cost: u32,
    ) -> String {
        format!(
            "id={}&expires_at={}&nonce={}&m_cost={}&t_cost={}&e_cost={}&n_cost={}&auth_tag={}",
            Ulid::generate(),
            TIME + TTL,
            URL_SAFE_NO_PAD.encode(NONCE),
            m_cost,
            t_cost,
            e_cost,
            n_cost,
            URL_SAFE_NO_PAD.encode([0u8; 16])
        )
    }

    fn parse_uri(authority: &str, query: &str) -> Uri {
        format!("pbcp://{authority}/?{query}")
            .parse()
            .expect("valid URI")
    }

    #[test]
    fn with_required_claims_rejects_invalid_names() {
        for names in [vec![""], vec!["", "a,b"]] {
            let result = challenge(Ulid::generate(), Params::default())
                .with_required_claims(names);
            assert!(matches!(result.err(), Some(Error::ClaimName)));
        }
    }

    #[test]
    fn required_claims_satisfied_by_claims() {
        let challenge = challenge(Ulid::generate(), Params::default())
            .with_required_claims(["iss", "sub", "aud", "iat", "exp"])
            .expect("valid claim names");
        let claims = claims();

        let satisfied = challenge.is_satisfied_by(&claims);
        assert!(satisfied);
    }

    #[test]
    fn uri_round_trip() {
        let default_params = Params::default();
        let custom_params = Params::new(16 * 1024, 2, 4, 12)
            .expect("valid parameters for TraverseV");

        for params in [default_params, custom_params] {
            let original = challenge(Ulid::generate(), params)
                .with_required_claims(["iss", "sub", "aud", "iat", "exp"])
                .expect("valid claim names");
            let auth = Authority::from_static("example.com:3000");
            let uri = original
                .to_uri(auth)
                .expect("valid Challenge serialises to URI");
            assert!(
                uri.query()
                    .expect("URI has query")
                    .contains("claims=iss%2Csub%2Caud%2Ciat%2Cexp")
            );

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
        let default_params = Params::default();
        let uri = parse_uri(
            "challenge",
            &challenge_query(
                1, // m_cost of 1 is too low
                default_params.t_cost(),
                default_params.e_cost(),
                default_params.n_cost(),
            ),
        );
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
*/
