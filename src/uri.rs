use http::{Uri, uri::PathAndQuery};
use serde::{Deserialize, Serialize};
use serde_qs;
use std::str::FromStr;
use ulid::Ulid;

use crate::errors::TlphError;
use crate::nonce::Nonce;
use crate::params::Params;
use crate::solution::Solution;

trait Wire: Serialize {
    fn path_and_query(&self) -> Result<PathAndQuery, TlphError>
    where
        Self: Sized,
    {
        let querystring = serde_qs::to_string(self)?;
        let p_and_q = format!("/?{}", querystring);
        Ok(PathAndQuery::from_str(&p_and_q)?)
    }
}

pub struct Challenge {
    id: Ulid,
    nonce: Vec<u8>,
    start: u64,
    params: Params,
}

impl Challenge {
    pub fn build_uri(
        id: Ulid,
        nonce: &[u8],
        start: u64,
        params: &Params,
    ) -> Result<Uri, TlphError> {
        let tv = params.tv();
        let wire = ChallengeWire {
            id,
            nonce: nonce.to_vec(),
            start,
            m_cost: Some(tv.m_cost()),
            t_cost: Some(tv.t_cost()),
            e_cost: Some(tv.e_cost()),
            n_cost: Some(tv.n_cost()),
            x: Some(params.x()),
            l: Some(params.l()),
            t0: Some(params.t0()),
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
            nonce: wire.nonce,
            start: wire.start,
            params,
        })
    }

    pub fn id(&self) -> Ulid {
        self.id.clone()
    }

    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub fn params(&self) -> Params {
        self.params.clone()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeWire {
    id: Ulid,
    #[serde(with = "base64url")]
    nonce: Vec<u8>,
    start: u64,
    m_cost: Option<u32>,
    t_cost: Option<u32>,
    e_cost: Option<u32>,
    n_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    l: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    t0: Option<u64>,
}

impl Wire for ChallengeWire {}

pub struct Proof {
    id: Ulid,
    nonce: Nonce,
    solution: Solution,
}

impl Proof {
    pub fn build_uri(
        id: Ulid,
        nonce: Nonce,
        solution: &Solution,
    ) -> Result<Uri, TlphError> {
        let wire = ProofWire {
            id,
            nonce: u128::from(nonce),
            solution: solution.to_bytes()?,
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
            nonce: Nonce::from(wire.nonce),
            solution: Solution::from_bytes(&wire.solution)?,
        })
    }

    pub fn id(&self) -> Ulid {
        self.id.clone()
    }

    pub const fn nonce(&self) -> Nonce {
        self.nonce
    }

    pub fn solution(&self) -> Solution {
        self.solution.clone()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofWire {
    id: Ulid,
    #[serde(with = "base64url_u128")]
    nonce: u128,
    #[serde(with = "base64url")]
    solution: Vec<u8>,
}

impl Wire for ProofWire {}

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

mod base64url {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        v: &Vec<u8>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<u8>, D::Error> {
        let input = String::deserialize(d)?;
        URL_SAFE_NO_PAD
            .decode(&input)
            .map_err(|e| <D::Error as serde::de::Error>::custom(e))
    }
}

mod base64url_u128 {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(v.to_le_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<u128, D::Error> {
        let input = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&input)
            .map_err(|e| <D::Error as serde::de::Error>::custom(e))?;
        let nonce: [u8; 16] = bytes.try_into().map_err(|_| {
            <D::Error as serde::de::Error>::custom(
                "nonce must decode to 16 bytes",
            )
        })?;
        Ok(u128::from_le_bytes(nonce))
    }
}
