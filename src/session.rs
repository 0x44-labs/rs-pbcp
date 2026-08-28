use wasm_bindgen::prelude::*;

use crate::errors::TlphError;

const PROOF_VERSION: u8 = 0x01;
const PROOF_TAG_SID: u8 = 0x01;
const PROOF_TAG_ANSWER: u8 = 0x02;
const PROOF_TAG_NONCE: u8 = 0x03;

#[wasm_bindgen]
pub struct Session {
    sid: Vec<u8>,
    cid: Vec<u8>,
    params: Params,
    start_step: u64,
}

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(constructor)]
    pub fn new(
        sid: Vec<u8>,
        cid: Vec<u8>,
        params: Params,
        start_step: u64,
    ) -> Session {
        Session {
            sid,
            cid,
            params,
            start_step,
        }
    }

    pub fn sid(&self) -> Vec<u8> {
        self.sid.clone()
    }

    pub fn cid(&self) -> Vec<u8> {
        self.cid.clone()
    }

    pub fn params(&self) -> Params {
        self.params.clone()
    }

    pub fn start_step(&self) -> u64 {
        self.start_step
    }
}

#[derive(Clone)]
#[wasm_bindgen]
pub struct Params {
    /// PoW Constraint
    pub n: u8,
    /// Similarity Threshold
    pub s: f64,
    /// Time Step Width
    pub x: u64,
    /// Time Step Count
    pub l: u64,
}

#[wasm_bindgen]
impl Params {
    #[wasm_bindgen(constructor)]
    pub fn new(n: u8, s: f64, x: u64, l: u64) -> Params {
        Params { n, s, x, l }
    }
}

#[derive(Clone)]
#[wasm_bindgen]
pub struct Grid {
    size: usize,
    inner: Vec<u8>,
}

#[wasm_bindgen]
impl Grid {
    pub fn new(size: usize, data: &[u8]) -> Option<Grid> {
        (data.len() == size * size).then_some(Self {
            size,
            inner: data.to_vec(),
        })
    }

    pub fn data(&self) -> Vec<u8> {
        self.inner.clone()
    }

    pub fn get(&self, row: usize, col: usize) -> u8 {
        self.inner[row * self.size + col]
    }

    pub fn row(&self, row: usize) -> Vec<u8> {
        let start = row * self.size;
        self.inner[start..start + self.size].to_vec()
    }

    pub fn col(&self, col: usize) -> Vec<u8> {
        (0..self.size)
            .map(|row| self.inner[row * self.size + col])
            .collect()
    }
}

#[wasm_bindgen]
pub struct Proof {
    sid: Vec<u8>,
    answer: Grid,
    nonce: u128,
}

#[wasm_bindgen]
impl Proof {
    #[wasm_bindgen(constructor)]
    pub fn new(sid: Vec<u8>, answer: Grid, nonce: u128) -> Proof {
        Proof { sid, answer, nonce }
    }

    pub fn sid(&self) -> Vec<u8> {
        self.sid.clone()
    }

    pub fn answer(&self) -> Grid {
        self.answer.clone()
    }

    pub fn nonce(&self) -> u128 {
        self.nonce
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.push(PROOF_VERSION);
        Self::write(&mut encoded, PROOF_TAG_SID, &self.sid);
        Self::write(&mut encoded, PROOF_TAG_ANSWER, &self.answer.data());
        Self::write(&mut encoded, PROOF_TAG_NONCE, &self.nonce.to_le_bytes());

        encoded
    }

    pub fn decode(value: Vec<u8>) -> Result<Proof, TlphError> {
        let (&version, rest) =
            value.split_first().ok_or(TlphError::Truncated)?;
        if version != PROOF_VERSION {
            return Err(TlphError::UnsupportedVersion(version));
        }

        let (tag, sid, rest) = Self::read(rest)?;
        if tag != PROOF_TAG_SID {
            return Err(TlphError::UnexpectedTag {
                expected: PROOF_TAG_SID,
                found: tag,
            });
        }

        let (tag, answer_bytes, rest) = Self::read(rest)?;
        if tag != PROOF_TAG_ANSWER {
            return Err(TlphError::UnexpectedTag {
                expected: PROOF_TAG_ANSWER,
                found: tag,
            });
        }
        let side = (answer_bytes.len() as f64).sqrt() as usize;
        let answer =
            Grid::new(side, answer_bytes).ok_or(TlphError::InvalidAnswer)?;

        let (tag, nonce_bytes, _rest) = Self::read(rest)?;
        if tag != PROOF_TAG_NONCE {
            return Err(TlphError::UnexpectedTag {
                expected: PROOF_TAG_NONCE,
                found: tag,
            });
        }
        let nonce = u128::from_le_bytes(
            nonce_bytes
                .try_into()
                .map_err(|_| TlphError::InvalidNonce)?,
        );

        Ok(Proof {
            sid: sid.to_vec(),
            answer,
            nonce,
        })
    }

    fn write(dst: &mut Vec<u8>, tag: u8, value: &[u8]) {
        dst.push(tag);
        dst.extend_from_slice(&(value.len() as u16).to_le_bytes());
        dst.extend_from_slice(value);
    }

    fn read(value: &[u8]) -> Result<(u8, &[u8], &[u8]), TlphError> {
        let (&tag, rest) = value.split_first().ok_or(TlphError::Truncated)?;
        if rest.len() < 2 {
            return Err(TlphError::Truncated);
        }

        let (len_bytes, rest) = rest.split_at(2);
        let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
        if rest.len() < len {
            return Err(TlphError::Truncated);
        }

        let (value, rest) = rest.split_at(len);
        Ok((tag, value, rest))
    }
}
