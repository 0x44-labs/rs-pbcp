use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Uri;
use num_traits::{FromBytes, ToBytes};
use serde_qs;
use traversev::Params;
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::PbcpError;
use crate::model::{ChallengeWire, Claims, Counter, ProofWire, Wire};

const SCHEME: &str = "pbcp";

/// A `Challenge` represents a challenge identifier, time of expiration (in
/// seconds), nonce value, and TraverseV parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    id: Ulid,
    expires_at: u64,
    nonce: Vec<u8>,
    params: Params,
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
            params,
        }
    }

    /// Serialise this [Challenge] to a `pbcp://challenge` URI, omitting
    /// parameters that have their default values.
    pub fn to_uri(&self) -> Result<Uri, PbcpError> {
        let wire = ChallengeWire {
            id: self.id,
            expires_at: self.expires_at,
            nonce: self.nonce.to_vec(),
            m_cost: non_default(self.params.m_cost(), Params::DEFAULT_M),
            t_cost: non_default(self.params.t_cost(), Params::DEFAULT_T),
            e_cost: non_default(self.params.e_cost(), Params::DEFAULT_E),
            n_cost: non_default(self.params.n_cost(), Params::DEFAULT_N),
        };

        let p_and_q = wire.path_and_query()?;
        let uri = Uri::builder()
            .scheme(SCHEME)
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

        let params = Params::new(
            wire.m_cost.unwrap_or(traversev::Params::DEFAULT_M),
            wire.t_cost.unwrap_or(traversev::Params::DEFAULT_T),
            wire.e_cost.unwrap_or(traversev::Params::DEFAULT_E),
            wire.n_cost.unwrap_or(traversev::Params::DEFAULT_N),
        )
        .map_err(|e| PbcpError::Params(e))?;

        Ok(Challenge {
            id: wire.id,
            expires_at: wire.expires_at,
            nonce: wire.nonce,
            params,
        })
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
}

/// A `Proof` represents a [Claims] and the mined nonce that proves it,
/// bound to a challenge identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    id: Ulid,
    claims: Claims,
    nonce: Counter,
}

impl Proof {
    /// Create a new [Proof] for the given challenge identifier, claims and
    /// nonce.
    pub fn new(id: Ulid, claims: &Claims, nonce: Counter) -> Self {
        Self {
            id: id,
            claims: claims.clone(),
            nonce,
        }
    }

    /// Serialise this [Proof] to a `pbcp://proof` URI.
    pub fn to_uri(&self) -> Result<Uri, PbcpError> {
        let wire = ProofWire {
            id: self.id,
            nonce: self.nonce.to_le_bytes(),
            claims: self.claims.to_bytes()?,
        };

        let p_and_q = wire.path_and_query()?;
        let uri = Uri::builder()
            .scheme(SCHEME)
            .authority("proof")
            .path_and_query(p_and_q)
            .build()?;

        Ok(uri)
    }

    /// Parse a [Proof] from a `pbcp://proof` URI.
    pub fn from_uri(uri: &Uri) -> Result<Self, PbcpError> {
        let query = host_query(uri, "proof")?;
        let wire: ProofWire = serde_qs::from_str(query)?;

        Ok(Proof {
            id: wire.id,
            claims: Claims::from_bytes(&wire.claims)?,
            nonce: Counter::from_le_bytes(&wire.nonce),
        })
    }

    /// Serialise this [Proof] to a string of the form `id.claims.nonce`,
    /// with the claims and nonce encoded as unpadded URL-safe base64.
    pub fn to_string(&self) -> Result<String, PbcpError> {
        let id = self.id.to_string();

        let mut claims_bytes = self.claims.to_bytes()?;
        let mut nonce_bytes = self.nonce.to_le_bytes();

        let mut claims = URL_SAFE_NO_PAD.encode(&claims_bytes);
        let mut nonce = URL_SAFE_NO_PAD.encode(&nonce_bytes);

        let proof_str = format!("{id}.{claims}.{nonce}");

        #[cfg(feature = "zeroize")]
        {
            claims_bytes.zeroize();
            nonce_bytes.zeroize();
            claims.zeroize();
            nonce.zeroize();
        }

        Ok(proof_str)
    }

    /// Parse a [Proof] from a string of the form `id.claims.nonce`, with the
    /// claims and nonce encoded as unpadded URL-safe base64.
    pub fn from_string(s: &str) -> Result<Self, PbcpError> {
        let mut parts = s.split(".");
        let (Some(first), Some(second), Some(third), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(PbcpError::ProofFormat);
        };

        let id =
            Ulid::from_string(first).map_err(|_| PbcpError::ProofFormat)?;
        let claims = with_decoded(second, Claims::from_bytes)??;
        let mut nonce = with_decoded(third, |v| {
            <&[u8; 16]>::try_from(v).map(|bytes| Counter::from_le_bytes(bytes))
        })?
        .map_err(|_| PbcpError::ProofFormat)?;

        let proof = Self { id, claims, nonce };

        #[cfg(feature = "zeroize")]
        nonce.zeroize();

        Ok(proof)
    }

    /// Returns the challenge identifier.
    pub const fn id(&self) -> Ulid {
        self.id
    }

    /// Returns a reference to the claims.
    pub const fn claims(&self) -> &Claims {
        &self.claims
    }

    /// Returns the nonce.
    pub const fn nonce(&self) -> Counter {
        self.nonce
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Proof {
    fn zeroize(&mut self) {
        self.claims.zeroize();
        self.nonce.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Proof {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Proof {}

fn non_default<T: PartialEq>(value: T, default: T) -> Option<T> {
    (value != default).then_some(value)
}

fn host_query<'a>(uri: &'a Uri, host: &str) -> Result<&'a str, PbcpError> {
    if uri.scheme_str() != Some(SCHEME) {
        return Err(PbcpError::UriParse);
    }
    if uri.host() != Some(host) {
        return Err(PbcpError::InvalidHost);
    }
    match uri.query() {
        Some(q) => Ok(q),
        None => return Err(PbcpError::UriParse),
    }
}

fn with_decoded<T>(
    s: &str,
    f: impl FnOnce(&[u8]) -> T,
) -> Result<T, PbcpError> {
    let mut bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| PbcpError::ProofFormat)?;
    let out = f(&bytes);

    #[cfg(feature = "zeroize")]
    bytes.zeroize();

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Error = PbcpError;

    const TIME: u64 = 1786558105;
    const TTL: u64 = 300;
    const NONCE: &[u8] = b"This is a challenge nonce";

    fn challenge(id: Ulid, params: Params) -> Challenge {
        Challenge::new(id, TIME + TTL, NONCE, params)
    }

    fn challenge_query() -> String {
        format!(
            "id={}&expires_at={}&nonce={}",
            Ulid::generate(),
            TIME + TTL,
            URL_SAFE_NO_PAD.encode(NONCE)
        )
    }

    fn parse_uri(authority: &str, query: &str) -> Uri {
        format!("pbcp://{authority}/?{query}")
            .parse()
            .expect("valid URI")
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

    fn proof() -> Proof {
        let id = Ulid::generate();
        let claims = claims();
        let nonce = Counter::default();

        Proof::new(id, &claims, nonce)
    }

    #[test]
    fn challenge_uri_round_trip() {
        let default_params = Params::default();
        let custom_params = Params::new(16 * 1024, 2, 4, 12)
            .expect("valid set of TraverseV params");

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
    fn challenge_accessors_return_their_own_field() {
        let id = Ulid::generate();
        let params = Params::default();
        let challenge = challenge(id, params);

        assert_eq!(challenge.id(), id);
        assert_eq!(challenge.expires_at(), TIME + TTL);
        assert_eq!(challenge.nonce(), &NONCE.to_vec());
        assert_eq!(challenge.params(), params);
    }

    #[test]
    fn challenge_from_uri_rejects_missing_field() {
        let uri = parse_uri("challenge", "start=1");
        let result = Challenge::from_uri(&uri);
        assert!(matches!(result.err(), Some(Error::QueryString(_))));
    }

    #[test]
    fn challenge_from_uri_rejects_invalid_params() {
        let uri =
            parse_uri("challenge", &format!("{}&m_cost=1", challenge_query()));
        let result = Challenge::from_uri(&uri);
        assert!(matches!(result.err(), Some(Error::Params(_))));
    }

    #[test]
    fn proof_uri_round_trip() {
        let original = proof();
        let uri = original.to_uri().expect("valid Proof serialises to URI");

        let reconstructed =
            Proof::from_uri(&uri).expect("valid URI parses to Proof");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn proof_string_round_trip() {
        let original = proof();
        let string = original
            .to_string()
            .expect("valid Proof serialises to string");

        let reconstructed =
            Proof::from_string(&string).expect("valid string parses to Proof");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn proof_from_string_rejects_malformed() {
        let id = Ulid::generate();
        let claims = URL_SAFE_NO_PAD.encode(
            claims()
                .to_bytes()
                .expect("valid Claims serialise to canonical JSON bytes"),
        );
        let nonce = URL_SAFE_NO_PAD.encode(0u128.to_le_bytes());

        for string in [
            format!("{nonce}.{claims}.{id}"),
            format!("{claims}.{id}.{nonce}"),
            format!("{id}.{claims}"),
            format!("{claims}.{nonce}"),
        ] {
            let result = Proof::from_string(&string);
            assert!(matches!(result.err(), Some(Error::ProofFormat)));
        }
    }

    #[test]
    fn proof_accessors_return_their_own_field() {
        let id = Ulid::generate();
        let claims = claims();
        let nonce = Counter::default();
        let proof = Proof::new(id, &claims, nonce);

        assert_eq!(proof.id(), id);
        assert_eq!(proof.claims(), &claims);
        assert_eq!(proof.nonce(), nonce);
    }

    #[test]
    fn host_query_rejects_wrong_scheme() {
        let uri: Uri = "http://challenge/?a=b".parse().expect("valid URI");
        let result = host_query(&uri, "challenge");
        assert!(matches!(result.err(), Some(Error::UriParse)));
    }

    #[test]
    fn host_query_rejects_wrong_host() {
        let uri = parse_uri("proof", "a=b");
        let result = host_query(&uri, "challenge");
        assert!(matches!(result.err(), Some(Error::InvalidHost)));
    }

    #[test]
    fn host_query_rejects_missing_query() {
        let uri: Uri = "pbcp://challenge/".parse().expect("valid URI");
        let result = host_query(&uri, "challenge");
        assert!(matches!(result.err(), Some(Error::UriParse)));
    }
}
