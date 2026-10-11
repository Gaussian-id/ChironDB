//! Admitted copies of visible Point output and native mutation inputs.
use super::context::AuthorizedRecord;
use crate::{
    GaussError, Point, Result, SparseVector,
    relational::wal_decode::{MetadataCharge, Reservation},
};
use std::{collections::HashMap, mem::size_of, ops::Deref};

pub(crate) struct ProjectedPoint {
    value: Point,
    payload: Reservation,
    memory: MetadataCharge,
}
impl Deref for ProjectedPoint {
    type Target = Point;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl ProjectedPoint {
    pub(crate) fn into_parts(self) -> (Point, [Reservation; 2]) {
        (self.value, [self.payload, self.memory.into_reservation()])
    }
}
fn full() -> GaussError {
    GaussError::ResourceExhausted("protected point memory is full".into())
}
fn add(total: &mut u64, bytes: u64) -> Result<()> {
    *total = total.checked_add(bytes).ok_or_else(full)?;
    Ok(())
}
fn array_bytes<T>(len: usize) -> Result<u64> {
    (len as u64)
        .checked_mul(size_of::<T>() as u64)
        .ok_or_else(full)
}
fn copy_vec<T: Copy>(source: &[T]) -> Result<Vec<T>> {
    let mut vector = Vec::new();
    vector.try_reserve_exact(source.len()).map_err(|_| full())?;
    vector.extend_from_slice(source);
    Ok(vector)
}
fn copy_string(source: &str) -> Result<String> {
    let mut value = String::new();
    value.try_reserve_exact(source.len()).map_err(|_| full())?;
    value.push_str(source);
    Ok(value)
}

pub(super) fn copy(record: AuthorizedRecord<'_>, source: &Point) -> Result<ProjectedPoint> {
    let dense = record.representation_visible("dense")?;
    let sparse = record.representation_visible("sparse")?;
    copy_fields(
        record.id(),
        if dense { &source.vector } else { &[] },
        source
            .vectors
            .iter()
            .map(|(name, vector)| (name.as_str(), vector.as_slice())),
        source.sparse_vector.as_ref().filter(|_| sparse),
        |name| Ok(record.representation_visible(name)?),
        || record.project(&source.payload),
    )
}

pub(crate) fn copy_new(id: &str, source: &super::NewPoint) -> Result<ProjectedPoint> {
    copy_fields(
        id,
        &source.vector,
        source
            .vectors
            .iter()
            .map(|(name, vector)| (name.as_str(), vector.as_slice())),
        source.sparse_vector.as_ref(),
        |_| Ok(true),
        || crate::relational::wal_decode::borrowed_json(&source.payload),
    )
}

pub(crate) fn copy_input(source: &Point) -> Result<ProjectedPoint> {
    copy_fields(
        &source.id,
        &source.vector,
        source
            .vectors
            .iter()
            .map(|(name, vector)| (name.as_str(), vector.as_slice())),
        source.sparse_vector.as_ref(),
        |_| Ok(true),
        || crate::relational::wal_decode::borrowed_json(&source.payload),
    )
}

fn copy_fields<'a>(
    id: &str,
    vector: &[f32],
    named: impl Iterator<Item = (&'a str, &'a [f32])> + Clone,
    sparse: Option<&SparseVector>,
    visible: impl Fn(&str) -> Result<bool>,
    project: impl FnOnce() -> Result<crate::relational::wal_decode::Owned<serde_json::Value>>,
) -> Result<ProjectedPoint> {
    let mut peak = 256u64;
    add(&mut peak, id.len() as u64)?;
    add(&mut peak, array_bytes::<f32>(vector.len())?)?;
    let mut names = 0usize;
    for (name, values) in named.clone() {
        if visible(name)? {
            names = names.checked_add(1).ok_or_else(full)?;
            add(&mut peak, name.len() as u64)?;
            add(&mut peak, array_bytes::<f32>(values.len())?)?;
        }
    }
    let width = size_of::<(String, Vec<f32>)>() + 64;
    if names > 0 {
        let capacity = names
            .checked_next_power_of_two()
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(full)?;
        add(
            &mut peak,
            (capacity as u64)
                .checked_mul(width as u64)
                .ok_or_else(full)?,
        )?;
    }
    if let Some(vector) = sparse {
        add(&mut peak, array_bytes::<u32>(vector.indices.len())?)?;
        add(&mut peak, array_bytes::<f32>(vector.values.len())?)?;
    }
    let mut output = ProjectedPoint {
        value: Point {
            id: String::new(),
            vector: Vec::new(),
            vectors: HashMap::new(),
            sparse_vector: None,
            payload: serde_json::Value::Null,
        },
        payload: Default::default(),
        memory: Default::default(),
    };
    output.memory.prepare(peak)?;
    output.value.id = copy_string(id)?;
    output.value.vector = copy_vec(vector)?;
    output
        .value
        .vectors
        .try_reserve(names)
        .map_err(|_| full())?;
    for (name, values) in named.clone() {
        if visible(name)? {
            output
                .value
                .vectors
                .insert(copy_string(name)?, copy_vec(values)?);
        }
    }
    if let Some(vector) = sparse {
        output.value.sparse_vector = Some(SparseVector {
            indices: copy_vec(&vector.indices)?,
            values: copy_vec(&vector.values)?,
        });
    }
    let mut retained = 128 + output.value.id.capacity() as u64;
    add(
        &mut retained,
        array_bytes::<f32>(output.value.vector.capacity())?,
    )?;
    add(
        &mut retained,
        (output.value.vectors.capacity() as u64)
            .checked_mul(width as u64)
            .ok_or_else(full)?,
    )?;
    for (name, vector) in &output.value.vectors {
        add(&mut retained, name.capacity() as u64)?;
        add(&mut retained, array_bytes::<f32>(vector.capacity())?)?;
    }
    if let Some(vector) = &output.value.sparse_vector {
        add(
            &mut retained,
            array_bytes::<u32>(vector.indices.capacity())?,
        )?;
        add(&mut retained, array_bytes::<f32>(vector.values.capacity())?)?;
    }
    if retained > peak {
        return Err(full());
    }
    output.memory.reduce(retained);
    let (payload, lease) = project()?.into_parts();
    output.value.payload = payload;
    output.payload = lease;
    Ok(output)
}
