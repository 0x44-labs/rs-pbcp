use num_traits::{FromBytes, ToBytes};

use crate::errors::TlphError;

pub struct Proof<T> {
    proof: u128,
    step: u64,
    grid: Grid<T>,
}

impl<T> Proof<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    pub fn new(proof: u128, step: u64, grid: Grid<T>) -> Self {
        Self { proof, step, grid }
    }

    pub const fn proof(&self) -> u128 {
        self.proof
    }

    pub const fn step(&self) -> u64 {
        self.step
    }

    pub fn grid(&self) -> Grid<T> {
        self.grid.clone()
    }
}

impl<T> TryFrom<&[u8]> for Proof<T>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    type Error = TlphError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // 16 proof + 8 step + 4 grid (min)
        const MIN_PROOF_BYTES: usize = 28;
        if value.len() < MIN_PROOF_BYTES {
            return Err(Self::Error::ProofTooSmall);
        }

        let mut proof_bytes = [0u8; 16];
        proof_bytes.copy_from_slice(&value[..16]);
        let proof = u128::from_le_bytes(proof_bytes);

        let mut step_bytes = [0u8; 8];
        step_bytes.copy_from_slice(&value[16..24]);
        let step = u64::from_le_bytes(step_bytes);

        let grid = Grid::<T>::try_from(&value[24..])?;

        Ok(Self { proof, step, grid })
    }
}

impl<T> From<Proof<T>> for Vec<u8>
where
    T: Copy + ToBytes + FromBytes,
    for<'a> <T as FromBytes>::Bytes: TryFrom<&'a [u8]>,
{
    fn from(value: Proof<T>) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&value.proof.to_le_bytes());
        bytes.extend_from_slice(&value.step.to_le_bytes());
        bytes.extend(Vec::<u8>::from(value.grid));
        bytes
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
