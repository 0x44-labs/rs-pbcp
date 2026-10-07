use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Uri;
use serde_qs;
use ulid::Ulid;

use crate::errors::TlphError;
use crate::model::{ChallengeWire, ProofWire, Solution, Wire};
use crate::params::{Params, TvParams};

pub struct Challenge {
    id: Ulid,
    start: u64,
    nonce: Vec<u8>,
    params: Params,
}

impl Challenge {
    pub fn new(id: Ulid, start: u64, nonce: &[u8], params: Params) -> Self {
        Self {
            id,
            start,
            nonce: nonce.to_vec(),
            params,
        }
    }

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

    pub const fn id(&self) -> Ulid {
        self.id
    }

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    pub const fn params(&self) -> Params {
        self.params
    }
}

pub struct Proof {
    id: Ulid,
    solution: Solution,
    nonce: u128,
}

impl Proof {
    pub fn new(id: Ulid, solution: &Solution, nonce: u128) -> Self {
        Self {
            id: id,
            solution: solution.clone(),
            nonce,
        }
    }

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

    pub fn from_uri(uri: &Uri) -> Result<Self, TlphError> {
        let query = host_query(uri, "proof")?;
        let wire: ProofWire = serde_qs::from_str(query)?;

        Ok(Proof {
            id: wire.id,
            solution: Solution::from_bytes(&wire.solution)?,
            nonce: wire.nonce,
        })
    }

    pub fn to_string(&self) -> Result<String, TlphError> {
        let id = self.id.to_string();
        let solution = URL_SAFE_NO_PAD.encode(self.solution.to_bytes()?);
        let nonce = URL_SAFE_NO_PAD.encode(self.nonce.to_le_bytes());

        Ok(format!("{id}.{solution}.{nonce}"))
    }

    pub fn from_string(s: &str) -> Result<Self, TlphError> {
        let mut parts = s.split(".");
        let (Some(first), Some(second), Some(third), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(TlphError::ProofFormat);
        };

        let id =
            Ulid::from_string(first).map_err(|_| TlphError::ProofFormat)?;

        let solution_bytes = URL_SAFE_NO_PAD
            .decode(second)
            .map_err(|_| TlphError::ProofFormat)?;
        let solution = Solution::from_bytes(&solution_bytes)?;

        let nonce_bytes: [u8; 16] = URL_SAFE_NO_PAD
            .decode(third)
            .map_err(|_| TlphError::ProofFormat)?
            .try_into()
            .map_err(|_| TlphError::ProofFormat)?;
        let nonce = u128::from_le_bytes(nonce_bytes);

        Ok(Self {
            id,
            solution,
            nonce,
        })
    }

    pub const fn id(&self) -> Ulid {
        self.id
    }

    pub fn solution(&self) -> Solution {
        self.solution.clone()
    }

    pub const fn nonce(&self) -> u128 {
        self.nonce
    }
}

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
