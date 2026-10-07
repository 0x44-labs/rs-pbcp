use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{Uri, uri::PathAndQuery};
use num_traits::ToBytes;
use serde::{Deserialize, Serialize};
use serde_qs;
use std::str::FromStr;
use ulid::Ulid;

use crate::errors::TlphError;
use crate::nonce::Nonce;
use crate::params::{Params, TvParams};
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

pub(crate) struct Challenge {
    id: Ulid,
    start: u64,
    nonce: Vec<u8>,
    params: Params,
}

impl Challenge {
    pub(crate) fn build_uri(
        id: Ulid,
        start: u64,
        nonce: &[u8],
        params: &Params,
    ) -> Result<Uri, TlphError> {
        let tv = params.tv();
        let wire = ChallengeWire {
            id,
            start,
            nonce: nonce.to_vec(),
            m_cost: non_default(tv.m_cost(), TvParams::DEFAULT_M),
            t_cost: non_default(tv.t_cost(), TvParams::DEFAULT_T),
            e_cost: non_default(tv.e_cost(), TvParams::DEFAULT_E),
            n_cost: non_default(tv.n_cost(), TvParams::DEFAULT_N),
            x: non_default(params.x(), Params::DEFAULT_X),
            l: non_default(params.l(), Params::DEFAULT_L),
            t0: non_default(params.t0(), Params::DEFAULT_T0),
        };

        let p_and_q = wire.path_and_query()?;
        let uri = Uri::builder()
            .scheme("tlph")
            .authority("challenge")
            .path_and_query(p_and_q)
            .build()?;

        Ok(uri)
    }

    pub(crate) fn from_uri(uri: &Uri) -> Result<Self, TlphError> {
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

    pub(crate) fn id(&self) -> Ulid {
        self.id.clone()
    }

    pub(crate) const fn start(&self) -> u64 {
        self.start
    }

    pub(crate) fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    pub(crate) fn params(&self) -> Params {
        self.params.clone()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeWire {
    id: Ulid,
    start: u64,
    #[serde(with = "base64url")]
    nonce: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    m_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    t_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    n_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    l: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    t0: Option<u64>,
}

impl Wire for ChallengeWire {}

pub(crate) struct Proof {
    id: Ulid,
    solution: Solution,
    nonce: Nonce,
}

impl Proof {
    pub fn new(id: Ulid, solution: &Solution, nonce: &Nonce) -> Self {
        Self {
            id,
            solution: solution.clone(),
            nonce: *nonce,
        }
    }

    pub(crate) fn to_uri(&self) -> Result<Uri, TlphError> {
        let wire = ProofWire {
            id: self.id,
            nonce: u128::from(self.nonce),
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

    pub(crate) fn from_uri(uri: &Uri) -> Result<Self, TlphError> {
        let query = host_query(uri, "proof")?;
        let wire: ProofWire = serde_qs::from_str(query)?;

        Ok(Proof {
            id: wire.id,
            solution: Solution::from_bytes(&wire.solution)?,
            nonce: Nonce::from(wire.nonce),
        })
    }

    pub(crate) fn to_string(&self) -> Result<String, TlphError> {
        let id = self.id.to_string();
        let solution = URL_SAFE_NO_PAD.encode(self.solution.to_bytes()?);
        let nonce = URL_SAFE_NO_PAD.encode(self.nonce.to_le_bytes());

        Ok(format!("{id}.{solution}.{nonce}"))
    }

    pub(crate) fn from_string(s: &str) -> Result<Self, TlphError> {
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
        let nonce = Nonce::from(u128::from_le_bytes(nonce_bytes));

        Ok(Self {
            id,
            solution,
            nonce,
        })
    }

    pub(crate) fn id(&self) -> Ulid {
        self.id.clone()
    }

    pub(crate) fn solution(&self) -> Solution {
        self.solution.clone()
    }

    pub(crate) const fn nonce(&self) -> Nonce {
        self.nonce
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofWire {
    id: Ulid,
    #[serde(with = "base64url")]
    solution: Vec<u8>,
    #[serde(with = "base64url_u128")]
    nonce: u128,
}

impl Wire for ProofWire {}

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

mod base64url {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        v: &Vec<u8>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(v))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
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

    pub(super) fn serialize<S: Serializer>(
        v: &u128,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(v.to_le_bytes()))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
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
