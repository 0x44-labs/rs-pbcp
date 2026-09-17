use num_traits::{FromBytes, ToBytes};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use traversev::{Params, TraverseV};
use ulid::Ulid;

use crate::errors::TlphError;

pub struct Proof<T> {
    proof: u128,
    solution: Solution<T>,
}

impl<T> Proof<T>
where
    T: Copy + ToBytes + FromBytes + Serialize + for<'de> Deserialize<'de>,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    const CONTEXT: &str = "TLPH-PROOF";

    pub fn new(id: Ulid, solution: Solution<T>, params: Params) -> Self {
        let secret = id.to_bytes();
        let tv = TraverseV::new_permissioned(&secret, Self::CONTEXT, params);

        let input = solution.to_bytes().expect("serialisation should not fail");
        let proof = tv.mine(&input);

        Self { proof, solution }
    }
}

/*
impl<T> TryFrom<&[u8]> for Proof<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    type Error = TlphError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 36 {
            return Err(Self::Error::ProofTooSmall);
        }

        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&value[..16]);
        let id = Ulid::from(id_bytes);

        let mut nonce_bytes = [0u8; 16];
        nonce_bytes.copy_from_slice(&value[16..32]);
        let nonce = u128::from_le_bytes(nonce_bytes);

        let solution = Grid::try_from(&value[32..])?;

        Ok(Proof::new(id, nonce, solution))
    }
}

impl<T: Copy + ToBytes + FromBytes> From<Proof<T>> for Vec<u8> {
    fn from(value: Proof<T>) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&value.id.to_bytes());
        bytes.extend_from_slice(&value.nonce.to_le_bytes());
        bytes.extend(Vec::from(value.solution));
        bytes
    }
}
*/

#[derive(Clone, Serialize, Deserialize)]
pub struct Solution<T> {
    step: u64,
    grid: Vec<u8>,
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> Solution<T>
where
    T: Copy + ToBytes + FromBytes + Serialize + for<'de> Deserialize<'de>,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    pub fn new(step: u64, grid: Grid<T>) -> Self {
        Self {
            step,
            grid: grid.into(),
            _marker: PhantomData,
        }
    }

    pub fn grid(&self) -> Result<Grid<T>, TlphError> {
        Grid::<T>::try_from(self.grid.as_slice())
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Grid<T> {
    size: usize,
    inner: Vec<T>,
}

impl<T: Copy + ToBytes + FromBytes> Grid<T> {
    const MIN_SIZE: usize = 2;

    pub fn new(size: usize, data: &[T]) -> Result<Grid<T>, TlphError> {
        if size < Self::MIN_SIZE {
            return Err(TlphError::GridTooSmall);
        }

        if data.len() == size * size {
            return Err(TlphError::GridNotSquare);
        }

        Ok(Self {
            size,
            inner: data.to_vec(),
        })
    }

    pub fn data(&self) -> Vec<T> {
        self.inner.clone()
    }

    pub fn get(&self, row: usize, col: usize) -> T {
        self.inner[row * self.size + col]
    }

    pub fn row(&self, row: usize) -> Vec<T> {
        let start = row * self.size;
        self.inner[start..start + self.size].to_vec()
    }

    pub fn col(&self, col: usize) -> Vec<T> {
        (0..self.size)
            .map(|row| self.inner[row * self.size + col])
            .collect()
    }
}

impl<T> TryFrom<&[u8]> for Grid<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    type Error = TlphError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let num_size = std::mem::size_of::<T>();
        if num_size == 0 || value.len() % num_size != 0 {
            return Err(Self::Error::GridWrongSize);
        }

        let values: Vec<T> = value
            .chunks_exact(num_size)
            .map(|chunk| {
                let arr = <T as FromBytes>::Bytes::try_from(chunk)
                    .map_err(|_| Self::Error::GridWrongSize)?;
                Ok(T::from_le_bytes(&arr))
            })
            .collect::<Result<Vec<T>, Self::Error>>()?;
        let size = (values.len() as f64).sqrt().round() as usize;

        Grid::new(size, &values)
    }
}

impl<T: Copy + ToBytes + FromBytes> From<Grid<T>> for Vec<u8> {
    fn from(value: Grid<T>) -> Self {
        value
            .inner
            .iter()
            .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
            .collect()
    }
}
