use std::collections::BTreeSet;

use blake3::Hasher;
use http::{Uri, uri::Authority};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use traversev::Params;
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

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
    auth_tag: Option<[u8; 16]>,
}

impl Challenge {
    /// Create a new [Challenge] with the given challenge identifier, time
    /// of expiration, nonce, and TraverseV parameters.
    pub fn new(
        id: Ulid,
        expires_at: u64,
        nonce: &[u8],
        params: Params,
    ) -> Self {
        Self {
            id,
            expires_at,
            nonce: nonce.to_vec(),
            required_claims: BTreeSet::new(),
            params,
            auth_tag: None,
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

    /// Compute the authentication tag of this [Challenge] with the given key.
    pub fn authenticate(mut self, key: &[u8; 32]) -> Result<Self, PbcpError> {
        self.auth_tag = Some(self.compute_auth_tag(key)?);
        Ok(self)
    }

    /// Returns whether the authentication tag of this [Challenge] was computed
    /// with the given key. A challenge without a tag is never authentic.
    pub fn is_authentic(&self, key: &[u8; 32]) -> Result<bool, PbcpError> {
        let Some(tag) = self.auth_tag else {
            return Ok(false);
        };

        let mut expected = self.compute_auth_tag(key)?;
        let authentic = expected.ct_eq(&tag);

        #[cfg(feature = "zeroize")]
        expected.zeroize();

        Ok(bool::from(authentic))
    }

    /// Serialise this [Challenge] to a `pbcp://` URI for the given authority.
    ///
    /// Returns an error if the challenge has not been authenticated.
    pub fn to_uri<T>(&self, auth: T) -> Result<Uri, PbcpError>
    where
        T: TryInto<Authority>,
        <T as TryInto<Authority>>::Error: Into<http::Error>,
    {
        if self.auth_tag.is_none() {
            return Err(PbcpError::Unauthenticated);
        }

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
    ///
    /// Returns an error if the challenge has not been authenticated.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PbcpError> {
        if self.auth_tag.is_none() {
            return Err(PbcpError::Unauthenticated);
        }

        self.encode(true)
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

    /// Returns the authentication tag, if the challenge has been
    /// authenticated.
    pub const fn auth_tag(&self) -> Option<[u8; 16]> {
        self.auth_tag
    }

    fn compute_auth_tag(&self, key: &[u8; 32]) -> Result<[u8; 16], PbcpError> {
        let mut input = self.encode(false)?;

        let mut hasher = Hasher::new_keyed(key);
        hasher.update(&input);

        let mut reader = hasher.finalize_xof();
        let mut auth_tag = [0u8; 16];
        reader.fill(&mut auth_tag);

        #[cfg(feature = "zeroize")]
        {
            input.zeroize();
            hasher.zeroize();
            reader.zeroize();
        }

        Ok(auth_tag)
    }

    fn encode(&self, authenticated: bool) -> Result<Vec<u8>, PbcpError> {
        let mut wire = ChallengeWire::from(self);
        if !authenticated {
            wire.auth_tag.clear();
        }

        let mut buf = Vec::new();
        ciborium::into_writer(&wire, &mut buf)?;
        Ok(buf)
    }
}

impl TryFrom<ChallengeWire> for Challenge {
    type Error = PbcpError;

    fn try_from(value: ChallengeWire) -> Result<Self, Self::Error> {
        let required_claims = value.required_claims.clone();

        let params =
            Params::new(value.m_cost, value.t_cost, value.e_cost, value.n_cost)
                .map_err(Self::Error::Params)?;

        let auth_tag = if value.auth_tag.is_empty() {
            None
        } else {
            Some(
                <[u8; 16]>::try_from(value.auth_tag.as_slice())
                    .map_err(|_| Self::Error::AuthTag)?,
            )
        };

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
struct ChallengeWire {
    id: Ulid,
    expires_at: u64,
    #[serde(with = "b64url_vec")]
    nonce: Vec<u8>,
    #[serde(
        default,
        skip_serializing_if = "BTreeSet::is_empty",
        with = "claim_names"
    )]
    required_claims: BTreeSet<String>,
    m_cost: u32,
    t_cost: u32,
    e_cost: u32,
    n_cost: u32,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "b64url_vec"
    )]
    auth_tag: Vec<u8>,
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
            auth_tag: value
                .auth_tag
                .map(|tag| tag.to_vec())
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    type Error = PbcpError;

    const KEY: [u8; 32] = [0u8; 32];
    const TIME: u64 = 1786558105;
    const TTL: u64 = 300;
    const NONCE: &[u8] = b"This is a challenge nonce";

    fn challenge(id: Ulid, params: Params) -> Challenge {
        Challenge::new(id, TIME + 300, b"This is a challenge nonce", params)
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
    fn required_claims_satisfied_by_claims() {
        let challenge = challenge(Ulid::generate(), Params::default())
            .with_required_claims(["iss", "sub", "aud", "iat", "exp"]);
        let claims = claims();

        let satisfied = challenge.is_satisfied_by(&claims);
        assert!(satisfied);
    }

    #[test]
    fn required_claims_unsatisfied_by_missing_claim() {
        let challenge = challenge(Ulid::generate(), Params::default())
            .with_required_claims(["iss", "nbf"]);
        let claims = claims();

        let satisfied = challenge.is_satisfied_by(&claims);
        assert!(!satisfied);
    }

    #[test]
    fn authenticate_produces_authentic_challenge() {
        let challenge = challenge(Ulid::generate(), Params::default())
            .authenticate(&KEY)
            .expect("valid Challenge authenticates");

        let authentic = challenge
            .is_authentic(&KEY)
            .expect("valid Challenge can be checked for authenticity");
        assert!(challenge.auth_tag().is_some());
        assert!(authentic);
    }

    #[test]
    fn is_authentic_rejects_missing_tag() {
        let unauthenticated = challenge(Ulid::generate(), Params::default());

        let missing_tag = unauthenticated
            .is_authentic(&KEY)
            .expect("valid Challenge serialises to CBOR bytes");
        assert!(!missing_tag);
    }

    #[test]
    fn is_authentic_rejects_wrong_key() {
        let authenticated = challenge(Ulid::generate(), Params::default())
            .authenticate(&KEY)
            .expect("valid Challenge authenticates");

        let wrong_key = authenticated
            .is_authentic(&[1u8; 32])
            .expect("valid Challenge serialises to CBOR bytes");
        assert!(!wrong_key);
    }

    #[test]
    fn is_authentic_rejects_modified_challenge() {
        let modified = challenge(Ulid::generate(), Params::default())
            .authenticate(&KEY)
            .expect("valid Challenge authenticates")
            .with_required_claims(["iss"]);

        let authentic = modified
            .is_authentic(&KEY)
            .expect("valid Challenge serialises to CBOR bytes");
        assert!(!authentic);
    }

    #[test]
    fn uri_round_trip() {
        let default_params = Params::default();
        let custom_params = Params::new(16 * 1024, 2, 4, 12)
            .expect("valid parameters for TraverseV");

        for params in [default_params, custom_params] {
            let original = challenge(Ulid::generate(), params)
                .with_required_claims(["iss", "sub", "aud", "iat", "exp"])
                .authenticate(&KEY)
                .expect("valid Challenge authenticates");
            let auth = Authority::from_static("example.com:3000");
            let uri = original
                .to_uri(auth)
                .expect("valid Challenge serialises to URI");
            assert!(
                uri.query()
                    .expect("URI has query")
                    .contains("required_claims=aud%2Cexp%2Ciat%2Ciss%2Csub")
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

        let original = challenge(Ulid::generate(), params)
            .with_required_claims(["iss", "sub", "aud", "iat", "exp"])
            .authenticate(&KEY)
            .expect("valid Challenge authenticates");
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
        let challenge = challenge(id, params).with_required_claims(["iss"]);

        assert_eq!(challenge.id(), id);
        assert_eq!(challenge.expires_at(), TIME + TTL);
        assert_eq!(challenge.nonce(), &NONCE.to_vec());
        assert_eq!(
            challenge.required_claims(),
            &BTreeSet::from(["iss".to_owned()])
        );
        assert_eq!(challenge.params(), params);
        assert_eq!(challenge.auth_tag(), None);
    }
}
