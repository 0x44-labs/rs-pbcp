use num_traits::{FromBytes, ToBytes};
use ulid::Ulid;

use crate::errors::TlphError;

pub struct Proof<T> {
    id: Ulid,
    nonce: u128,
    solution: Grid<T>,
}

impl<T: Copy + ToBytes + FromBytes> Proof<T> {
    pub fn new(id: Ulid, nonce: u128, solution: Grid<T>) -> Proof<T> {
        Proof {
            id,
            nonce,
            solution,
        }
    }

    pub fn id(&self) -> Ulid {
        self.id.clone()
    }

    pub const fn nonce(&self) -> u128 {
        self.nonce
    }

    pub fn solution(&self) -> Grid<T> {
        self.solution.clone()
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

impl<T> TryFrom<Vec<u8>> for Grid<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    type Error = TlphError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let num_size = std::mem::size_of::<T>();
        if num_size == 0 || value.len() % num_size != 0 {
            return Err(Self::Error::IncompatibleByteLen);
        }

        let values: Vec<T> = value
            .chunks_exact(num_size)
            .map(|chunk| {
                let arr = <T as FromBytes>::Bytes::try_from(chunk)
                    .map_err(|_| Self::Error::IncompatibleByteLen)?;
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
