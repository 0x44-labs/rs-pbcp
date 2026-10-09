use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Uri;
use serde_qs;
use ulid::Ulid;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::TlphError;
use crate::model::{ChallengeWire, ProofWire, Solution, Wire};
use crate::params::{Params, TvParams};

/// A `Challenge` represents a session identifier, a start time step, a nonce
/// and a set of parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    id: Ulid,
    start: u64,
    nonce: Vec<u8>,
    params: Params,
}

impl Challenge {
    /// Create a new [Challenge] with the given session identifier, starting
    /// time step, nonce, and parameters.
    pub fn new(id: Ulid, start: u64, nonce: &[u8], params: Params) -> Self {
        Self {
            id,
            start,
            nonce: nonce.to_vec(),
            params,
        }
    }

    /// Serialise this [Challenge] to a `tlph://challenge` URI, omitting
    /// parameters that have their default values.
    pub fn to_uri(&self) -> Result<Uri, TlphError> {
        let tv = self.params.tv();
        let wire = ChallengeWire {
            id: self.id,
            start: self.start,
            nonce: self.nonce.to_vec(),
            m_cost: non_default(tv.m_cost(), TvParams::DEFAULT_M),
            t_cost: non_default(tv.t_cost(), TvParams::DEFAULT_T),
            e_cost: non_default(tv.e_cost(), TvParams::DEFAULT_E),
            n_cost: non_default(tv.n_cost(), TvParams::DEFAULT_N),
            x: non_default(self.params.x(), Params::DEFAULT_X),
            l: non_default(self.params.l(), Params::DEFAULT_L),
            t0: non_default(self.params.t0(), Params::DEFAULT_T0),
        };

        let p_and_q = wire.path_and_query()?;
        let uri = Uri::builder()
            .scheme("tlph")
            .authority("challenge")
            .path_and_query(p_and_q)
            .build()?;

        Ok(uri)
    }

    /// Parse a [Challenge] from a `tlph://challenge` URI, using defaults for
    /// omitted parameters.
    pub fn from_uri(uri: &Uri) -> Result<Self, TlphError> {
        let query = host_query(uri, "challenge")?;
        let wire: ChallengeWire = serde_qs::from_str(query)?;

        let tv = traversev::Params::new(
            wire.m_cost.unwrap_or(traversev::Params::DEFAULT_M),
            wire.t_cost.unwrap_or(traversev::Params::DEFAULT_T),
            wire.e_cost.unwrap_or(traversev::Params::DEFAULT_E),
            wire.n_cost.unwrap_or(traversev::Params::DEFAULT_N),
        )
        .map_err(|e| TlphError::TvParams(e))?;

        let params = Params::new(
            tv,
            wire.x.unwrap_or(Params::DEFAULT_X),
            wire.l.unwrap_or(Params::DEFAULT_L),
            wire.t0,
        )?;

        Ok(Challenge {
            id: wire.id,
            start: wire.start,
            nonce: wire.nonce,
            params,
        })
    }

    /// Returns the session identifier.
    pub const fn id(&self) -> Ulid {
        self.id
    }

    /// Returns the starting time step.
    pub const fn start(&self) -> u64 {
        self.start
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

/// A `Proof` represents a [Solution] and the mined nonce that proves it,
/// bound to a session identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    id: Ulid,
    solution: Solution,
    nonce: u128,
}

impl Proof {
    /// Create a new [Proof] for the given session identifier, solution and
    /// nonce.
    pub fn new(id: Ulid, solution: &Solution, nonce: u128) -> Self {
        Self {
            id: id,
            solution: solution.clone(),
            nonce,
        }
    }

    /// Serialise this [Proof] to a `tlph://proof` URI.
    pub fn to_uri(&self) -> Result<Uri, TlphError> {
        let wire = ProofWire {
            id: self.id,
            nonce: self.nonce,
            solution: self.solution.to_bytes()?,
        };

        let p_and_q = wire.path_and_query()?;
        let uri = Uri::builder()
            .scheme("tlph")
            .authority("proof")
            .path_and_query(p_and_q)
            .build()?;

        Ok(uri)
    }

    /// Parse a [Proof] from a `tlph://proof` URI.
    pub fn from_uri(uri: &Uri) -> Result<Self, TlphError> {
        let query = host_query(uri, "proof")?;
        let wire: ProofWire = serde_qs::from_str(query)?;

        Ok(Proof {
            id: wire.id,
            solution: Solution::from_bytes(&wire.solution)?,
            nonce: wire.nonce,
        })
    }

    /// Serialise this [Proof] to a string of the form `id.solution.nonce`,
    /// with the solution and nonce encoded as unpadded URL-safe base64.
    pub fn to_string(&self) -> Result<String, TlphError> {
        let id = self.id.to_string();

        let mut solution_bytes = self.solution.to_bytes()?;
        let mut nonce_bytes = self.nonce.to_le_bytes();

        let mut solution = URL_SAFE_NO_PAD.encode(&solution_bytes);
        let mut nonce = URL_SAFE_NO_PAD.encode(&nonce_bytes);

        let proof_str = format!("{id}.{solution}.{nonce}");

        #[cfg(feature = "zeroize")]
        {
            solution_bytes.zeroize();
            nonce_bytes.zeroize();
            solution.zeroize();
            nonce.zeroize();
        }

        Ok(proof_str)
    }

    /// Parse a [Proof] from a string of the form `id.solution.nonce`, with the
    /// solution and nonce encoded as unpadded URL-safe base64.
    pub fn from_string(s: &str) -> Result<Self, TlphError> {
        let mut parts = s.split(".");
        let (Some(first), Some(second), Some(third), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(TlphError::ProofFormat);
        };

        let id =
            Ulid::from_string(first).map_err(|_| TlphError::ProofFormat)?;
        let solution = with_decoded(second, Solution::from_bytes)??;
        let mut nonce = with_decoded(third, |b| {
            <&[u8; 16]>::try_from(b).map(|a| u128::from_le_bytes(*a))
        })?
        .map_err(|_| TlphError::ProofFormat)?;

        let proof = Self {
            id,
            solution,
            nonce,
        };

        #[cfg(feature = "zeroize")]
        nonce.zeroize();

        Ok(proof)
    }

    /// Returns the session identifier.
    pub const fn id(&self) -> Ulid {
        self.id
    }

    /// Returns a reference to the solution.
    pub const fn solution(&self) -> &Solution {
        &self.solution
    }

    /// Returns the nonce.
    pub const fn nonce(&self) -> u128 {
        self.nonce
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Proof {
    fn zeroize(&mut self) {
        self.solution.zeroize();
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

fn host_query<'a>(uri: &'a Uri, host: &str) -> Result<&'a str, TlphError> {
    if uri.scheme_str() != Some("tlph") {
        return Err(TlphError::UriParse);
    }
    if uri.host() != Some(host) {
        return Err(TlphError::InvalidHost);
    }
    match uri.query() {
        Some(q) => Ok(q),
        None => return Err(TlphError::UriParse),
    }
}

fn with_decoded<T>(
    s: &str,
    f: impl FnOnce(&[u8]) -> T,
) -> Result<T, TlphError> {
    let mut bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| TlphError::ProofFormat)?;
    let out = f(&bytes);

    #[cfg(feature = "zeroize")]
    bytes.zeroize();

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Error = TlphError;

    const TIME: u64 = 1786558105;

    const CHALLENGE_NONCE: &[u8] = b"This is a challenge nonce";

    fn time_step() -> u64 {
        let params = Params::default();
        params.time_step(Some(TIME))
    }

    fn sample_challenge(id: Ulid, params: Params) -> Challenge {
        let step = time_step();
        Challenge::new(id, step, CHALLENGE_NONCE, params)
    }

    fn challenge_query() -> String {
        format!(
            "id={}&start={}&nonce={}",
            Ulid::generate(),
            time_step(),
            URL_SAFE_NO_PAD.encode(CHALLENGE_NONCE)
        )
    }

    fn parse_uri(authority: &str, query: &str) -> Uri {
        format!("tlph://{authority}/?{query}")
            .parse()
            .expect("valid URI")
    }

    fn sample_payload() -> Vec<u8> {
        b"This is a payload".to_vec()
    }

    fn sample_solution() -> Solution {
        let step = time_step();
        let payload = sample_payload();
        let solution = Solution::builder(step, payload)
            .claim("iss", "https://humanity.example")
            .claim("sub", "Homo sapiens")
            .claim("aud", "https://humans-only.example")
            .claim("iat", "1786554930")
            .claim("exp", "1786561137")
            .build();

        solution
    }

    fn sample_proof() -> Proof {
        let id = Ulid::generate();
        let solution = sample_solution();
        let nonce = 0u128;

        Proof::new(id, &solution, nonce)
    }

    #[test]
    fn challenge_uri_round_trip() {
        let default_params = Params::default();
        let tv = TvParams::new(16 * 1024, 2, 4, 12).expect("valid TV params");
        let custom_params = Params::new(tv, 60, 5, None).expect("valid params");

        for params in [default_params, custom_params] {
            let original = sample_challenge(Ulid::generate(), params);
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
        let challenge = sample_challenge(id, params);

        assert_eq!(challenge.id(), id);
        assert_eq!(challenge.start(), time_step());
        assert_eq!(challenge.nonce(), &CHALLENGE_NONCE.to_vec());
        assert_eq!(challenge.params(), params);
    }

    #[test]
    fn challenge_from_uri_rejects_missing_field() {
        let uri = parse_uri("challenge", "start=1");
        let result = Challenge::from_uri(&uri);
        assert!(matches!(result.err(), Some(Error::QueryString(_))));
    }

    #[test]
    fn challenge_from_uri_rejects_invalid_tv_params() {
        let uri =
            parse_uri("challenge", &format!("{}&m_cost=1", challenge_query()));
        let result = Challenge::from_uri(&uri);
        assert!(matches!(result.err(), Some(Error::TvParams(_))));
    }

    #[test]
    fn challenge_from_uri_rejects_invalid_params() {
        let uri = parse_uri("challenge", &format!("{}&x=0", challenge_query()));
        let result = Challenge::from_uri(&uri);
        assert!(matches!(result.err(), Some(Error::StepTooSmall)));
    }

    #[test]
    fn proof_uri_round_trip() {
        let original = sample_proof();
        let uri = original.to_uri().expect("valid Proof serialises to URI");

        let reconstructed =
            Proof::from_uri(&uri).expect("valid URI parses to Proof");
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn proof_string_round_trip() {
        let original = sample_proof();
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
        let solution = URL_SAFE_NO_PAD.encode(
            sample_solution()
                .to_bytes()
                .expect("valid Solution serialises to canonical JSON bytes"),
        );
        let nonce = URL_SAFE_NO_PAD.encode(0u128.to_le_bytes());

        for string in [
            format!("{nonce}.{solution}.{id}"),
            format!("{solution}.{id}.{nonce}"),
            format!("{id}.{solution}"),
            format!("{solution}.{nonce}"),
        ] {
            let result = Proof::from_string(&string);
            assert!(matches!(result.err(), Some(Error::ProofFormat)));
        }
    }

    #[test]
    fn proof_accessors_return_their_own_field() {
        let id = Ulid::generate();
        let solution = sample_solution();
        let nonce = 0u128;
        let proof = Proof::new(id, &solution, nonce);

        assert_eq!(proof.id(), id);
        assert_eq!(proof.solution(), &solution);
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
        let uri: Uri = "tlph://challenge/".parse().expect("valid URI");
        let result = host_query(&uri, "challenge");
        assert!(matches!(result.err(), Some(Error::UriParse)));
    }
}
