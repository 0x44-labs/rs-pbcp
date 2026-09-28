use num_traits::{FromBytes, ToBytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, marker::PhantomData};

use crate::errors::TlphError;

#[derive(Clone, Serialize, Deserialize)]
pub struct Solution<T> {
    step: u64,
    grid: Vec<u8>,
    #[serde(flatten)]
    claims: BTreeMap<String, Value>,
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> Solution<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    pub fn new(step: u64, grid: Grid<T>) -> SolutionBuilder<T> {
        SolutionBuilder::new(step, grid)
    }
}

pub struct SolutionBuilder<T> {
    step: u64,
    grid: Grid<T>,
    claims: BTreeMap<String, Value>,
}

impl<T> SolutionBuilder<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    const RESERVED: [&str; 2] = ["step", "grid"];

    fn new(step: u64, grid: Grid<T>) -> Self {
        Self {
            step,
            grid,
            claims: BTreeMap::new(),
        }
    }

    pub fn claim(
        mut self,
        name: impl Into<String>,
        value: impl Into<Value>,
    ) -> Result<Self, TlphError> {
        let name = name.into();
        if Self::RESERVED.contains(&name.as_str()) {
            return Err(TlphError::ReservedClaim);
        }

        self.claims.insert(name.into(), value.into());
        Ok(self)
    }

    pub fn build(self) -> Solution<T> {
        Solution {
            step: self.step,
            grid: Vec::<u8>::from(self.grid),
            claims: self.claims,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone)]
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

        if data.len() != size * size {
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
