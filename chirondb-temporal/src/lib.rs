//! Offline, immutable temporal segments. All timestamps are signed nanoseconds.
//! The experimental format is private to this crate.
//!
//! ```
//! use std::io::Cursor;
//! use chirondb_temporal::{encode_segment, Point, Segment, Series, Value};
//! let sensor = Series::new("factory", "pump-7", "pressure");
//! let event = Point { time: 42, value: Value::Float(3.5) };
//! let bytes = encode_segment([(sensor.clone(), event)])?;
//! let mut segment = Segment::open(Cursor::new(bytes))?;
//! assert_eq!(segment.scan(&sensor, 0, 42)?, vec![]);
//! assert_eq!(segment.scan(&sensor, 42, 43)?, vec![event]);
//! assert_eq!(segment.latest(&sensor)?, Some(event));
//! # Ok::<(), std::io::Error>(())
//! ```
mod codec;
mod segment;
pub use segment::{Segment, encode_segment};
use std::io::{Error, ErrorKind, Result};

const BLOCK_POINTS: usize = 1000;
fn bad(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Series {
    pub tenant: String,
    pub asset: String,
    pub property: String,
}
impl Series {
    pub fn new(
        tenant: impl Into<String>,
        asset: impl Into<String>,
        property: impl Into<String>,
    ) -> Self {
        Self {
            tenant: tenant.into(),
            asset: asset.into(),
            property: property.into(),
        }
    }
    fn key(&self) -> Result<Vec<u8>> {
        let mut key = Vec::new();
        for part in [&self.tenant, &self.asset, &self.property] {
            let len = u16::try_from(part.len()).map_err(|_| bad("series component too long"))?;
            key.extend(len.to_be_bytes());
            key.extend(part.as_bytes());
        }
        u16::try_from(key.len()).map_err(|_| bad("series key too long"))?;
        Ok(key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    Float(f64),
    Boolean(bool),
}
impl Value {
    /// Decode a typed value at an interchange boundary. TSM tags: float=0, boolean=2.
    pub fn from_bits(tag: u8, bits: u64) -> Result<Self> {
        match tag {
            0 if !f64::from_bits(bits).is_nan() => Ok(Self::Float(f64::from_bits(bits))),
            0 => Err(bad("NaN reserved by float codec")),
            2 if bits < 2 => Ok(Self::Boolean(bits != 0)),
            2 => Err(bad("invalid boolean")),
            _ => Err(bad("unsupported value type")),
        }
    }
    fn tag(self) -> u8 {
        match self {
            Self::Float(_) => 0,
            Self::Boolean(_) => 2,
        }
    }
    fn bits(self) -> u64 {
        match self {
            Self::Float(v) => v.to_bits(),
            Self::Boolean(v) => u64::from(v),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Point {
    pub time: i64,
    pub value: Value,
}

// TsFile TimeFilter.canSkip/allSatisfy, adapted to a half-open query and
// inclusive block statistics. Never add one to an i64 endpoint.
#[derive(Debug, PartialEq, Eq)]
enum Coverage {
    Skip,
    All,
    Partial,
}
fn coverage(start: i64, end: i64, min: i64, max: i64) -> Coverage {
    if start >= end || max < start || min >= end {
        Coverage::Skip
    } else if start <= min && max < end {
        Coverage::All
    } else {
        Coverage::Partial
    }
}

// IoTDB LastValueAccumulator's merge of partial results by event timestamp.
// An explicit None allows the first event to occur at i64::MIN.
fn merge_latest(last: &mut Option<Point>, candidate: Point) -> Result<()> {
    match *last {
        Some(prev)
            if prev.time == candidate.time
                && (prev.value.tag(), prev.value.bits())
                    != (candidate.value.tag(), candidate.value.bits()) =>
        {
            Err(bad("conflicting event"))
        }
        Some(prev) if prev.time >= candidate.time => Ok(()),
        _ => {
            *last = Some(candidate);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
