//! `edgeprop.gdx` typed EdgeId-keyed property columns (Rev 3.4 Appendix C.6).

use std::{collections::BTreeSet, path::Path};

use serde_json::{Map, Value};

use crate::{
    GaussError, Result,
    graph::{
        EdgeId, GRAPH_ALLOCATOR_MAX_COUNTER, GRAPH_ALLOCATOR_MAX_EPOCH, MAX_EDGE_PROPERTY_BYTES,
    },
    graph_artifact::{self, ArtifactSpec, CheckedArtifact, SectionPayload},
};

pub(crate) const EDGE_PROPERTY_FILE: &str = "edgeprop.gdx";
pub(crate) const EDGE_PROPERTY_MAGIC: &[u8; 8] = b"GAUSEP02";

const FLAG_JSON_SPILL: u32 = 1;
const FLAG_STRING_DATA: u32 = 1 << 1;

const SECTION_EDGE_IDS: u32 = 1;
const SECTION_COLUMN_DIRECTORY: u32 = 2;
const SECTION_PRESENCE_BITMAPS: u32 = 3;
const SECTION_NULL_BITMAPS: u32 = 4;
const SECTION_SCALAR_DATA: u32 = 5;
const SECTION_STRING_OFFSETS: u32 = 6;
const SECTION_STRING_BYTES: u32 = 7;
const SECTION_JSON_OFFSETS: u32 = 8;
const SECTION_JSON_BYTES: u32 = 9;

const REQUIRED_SECTIONS: &[u32] = &[
    SECTION_EDGE_IDS,
    SECTION_COLUMN_DIRECTORY,
    SECTION_PRESENCE_BITMAPS,
    SECTION_NULL_BITMAPS,
    SECTION_SCALAR_DATA,
    SECTION_STRING_OFFSETS,
];
const OPTIONAL_SECTIONS: &[u32] = &[
    SECTION_STRING_BYTES,
    SECTION_JSON_OFFSETS,
    SECTION_JSON_BYTES,
];

const SPEC: ArtifactSpec = ArtifactSpec {
    magic: EDGE_PROPERTY_MAGIC,
    allowed_flags: FLAG_JSON_SPILL | FLAG_STRING_DATA,
    required_sections: REQUIRED_SECTIONS,
    optional_sections: OPTIONAL_SECTIONS,
    max_file_len: u64::MAX,
};

const DIRECTORY_HEADER_BYTES: usize = 16;
const DIRECTORY_RECORD_BYTES: usize = 112;
// One usize per 32K rows/column; queries count at most 4 KiB of bitmap
// bytes instead of reading a prefix proportional to the requested EdgeId.
const RANK_BLOCK_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ColumnKind {
    Bool = 1,
    I64 = 2,
    U64 = 3,
    F64 = 4,
    String = 5,
    Json = 6,
}

impl ColumnKind {
    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Bool),
            2 => Some(Self::I64),
            3 => Some(Self::U64),
            4 => Some(Self::F64),
            5 => Some(Self::String),
            6 => Some(Self::Json),
            _ => None,
        }
    }

    fn scalar_width(self) -> Option<usize> {
        match self {
            Self::Bool => Some(1),
            Self::I64 | Self::U64 | Self::F64 => Some(8),
            Self::String | Self::Json => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EdgePropertyInput {
    pub(crate) edge_id: EdgeId,
    pub(crate) properties: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq)]
struct PropertyColumn {
    key: String,
    kind: ColumnKind,
    presence: Vec<u8>,
    nulls: Vec<u8>,
    values: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EdgePropertyTable {
    edge_ids: Vec<EdgeId>,
    columns: Vec<PropertyColumn>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ColumnDescriptor {
    key: String,
    kind: ColumnKind,
    presence_offset: usize,
    presence_len: usize,
    null_offset: usize,
    null_len: usize,
    value_offset: usize,
    value_len: usize,
    data_offset: usize,
    data_len: usize,
    value_count: usize,
}

pub(crate) struct OpenedEdgeProperties {
    artifact: CheckedArtifact,
    edge_count: usize,
    columns: Vec<ColumnDescriptor>,
    non_null_ranks: Vec<Vec<usize>>,
}

impl EdgePropertyTable {
    pub(crate) fn build(mut rows: Vec<EdgePropertyInput>) -> Result<Self> {
        rows.sort_unstable_by_key(|row| row.edge_id.raw());
        for row in &rows {
            validate_edge_id(row.edge_id)?;
            if serde_json::to_vec(&row.properties)?.len() > MAX_EDGE_PROPERTY_BYTES {
                return Err(invalid(
                    "edgeprop.gdx document exceeds the graph property limit",
                ));
            }
        }
        if rows
            .windows(2)
            .any(|pair| pair[0].edge_id == pair[1].edge_id)
        {
            return Err(invalid("edgeprop.gdx contains duplicate EdgeId rows"));
        }

        let mut keys = BTreeSet::new();
        for row in &rows {
            for key in row.properties.keys() {
                if key.is_empty() {
                    return Err(invalid("edgeprop.gdx property key is empty"));
                }
                keys.insert(key.clone());
            }
        }
        let bitmap_len = bitmap_len(rows.len())?;
        let mut columns = Vec::with_capacity(keys.len());
        for key in keys {
            let mut presence = vec![0_u8; bitmap_len];
            let mut nulls = vec![0_u8; bitmap_len];
            let mut values = Vec::new();
            let mut inferred = None;
            let mut mixed = false;
            for (row_index, row) in rows.iter().enumerate() {
                let Some(value) = row.properties.get(&key) else {
                    continue;
                };
                set_bit(&mut presence, row_index);
                if value.is_null() {
                    set_bit(&mut nulls, row_index);
                    continue;
                }
                let kind = classify_value(value)?;
                if inferred.is_some_and(|prior| prior != kind) {
                    mixed = true;
                } else if inferred.is_none() {
                    inferred = Some(kind);
                }
                values.push(value.clone());
            }
            let kind = if mixed {
                ColumnKind::Json
            } else {
                inferred.unwrap_or(ColumnKind::Json)
            };
            if kind == ColumnKind::Json {
                for value in &values {
                    canonical_json_bytes(value)?;
                }
            }
            columns.push(PropertyColumn {
                key,
                kind,
                presence,
                nulls,
                values,
            });
        }
        Ok(Self {
            edge_ids: rows.into_iter().map(|row| row.edge_id).collect(),
            columns,
        })
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.edge_ids.len()
    }

    pub(crate) fn column_count(&self) -> usize {
        self.columns.len()
    }
}

struct EncodedColumn {
    descriptor: ColumnDescriptor,
    scalar: Vec<u8>,
    offsets: Vec<u8>,
    data: Vec<u8>,
}

pub(crate) fn write(path: &Path, table: &EdgePropertyTable) -> Result<()> {
    let edge_ids = table
        .edge_ids
        .iter()
        .flat_map(|edge_id| edge_id.raw().to_le_bytes())
        .collect::<Vec<_>>();
    let mut presence = Vec::new();
    let mut nulls = Vec::new();
    let mut scalar = Vec::new();
    let mut string_offsets = Vec::new();
    let mut string_bytes = Vec::new();
    let mut json_offsets = Vec::new();
    let mut json_bytes = Vec::new();
    let mut encoded_columns = Vec::with_capacity(table.columns.len());

    for column in &table.columns {
        let presence_offset = presence.len();
        presence.extend_from_slice(&column.presence);
        let null_offset = nulls.len();
        nulls.extend_from_slice(&column.nulls);
        let value_count = column.values.len();
        let mut encoded = EncodedColumn {
            descriptor: ColumnDescriptor {
                key: column.key.clone(),
                kind: column.kind,
                presence_offset,
                presence_len: column.presence.len(),
                null_offset,
                null_len: column.nulls.len(),
                value_offset: 0,
                value_len: 0,
                data_offset: 0,
                data_len: 0,
                value_count,
            },
            scalar: Vec::new(),
            offsets: Vec::new(),
            data: Vec::new(),
        };
        match column.kind {
            ColumnKind::Bool | ColumnKind::I64 | ColumnKind::U64 | ColumnKind::F64 => {
                encoded.descriptor.value_offset = scalar.len();
                encode_scalars(column.kind, &column.values, &mut encoded.scalar)?;
                encoded.descriptor.value_len = encoded.scalar.len();
                scalar.extend_from_slice(&encoded.scalar);
            }
            ColumnKind::String => {
                encoded.descriptor.value_offset = string_offsets.len();
                encoded.descriptor.data_offset = string_bytes.len();
                encode_variable_values(
                    column.kind,
                    &column.values,
                    &mut encoded.offsets,
                    &mut encoded.data,
                )?;
                encoded.descriptor.value_len = encoded.offsets.len();
                encoded.descriptor.data_len = encoded.data.len();
                string_offsets.extend_from_slice(&encoded.offsets);
                string_bytes.extend_from_slice(&encoded.data);
            }
            ColumnKind::Json => {
                encoded.descriptor.value_offset = json_offsets.len();
                encoded.descriptor.data_offset = json_bytes.len();
                encode_variable_values(
                    column.kind,
                    &column.values,
                    &mut encoded.offsets,
                    &mut encoded.data,
                )?;
                encoded.descriptor.value_len = encoded.offsets.len();
                encoded.descriptor.data_len = encoded.data.len();
                json_offsets.extend_from_slice(&encoded.offsets);
                json_bytes.extend_from_slice(&encoded.data);
            }
        }
        encoded_columns.push(encoded);
    }

    let directory = encode_directory(table.edge_ids.len(), &encoded_columns)?;
    let has_strings = table
        .columns
        .iter()
        .any(|column| column.kind == ColumnKind::String);
    let has_json = table
        .columns
        .iter()
        .any(|column| column.kind == ColumnKind::Json);
    let flags =
        (u32::from(has_json) * FLAG_JSON_SPILL) | (u32::from(has_strings) * FLAG_STRING_DATA);
    let mut sections = vec![
        SectionPayload {
            id: SECTION_EDGE_IDS,
            elem_count: table.edge_ids.len() as u64,
            bytes: &edge_ids,
        },
        SectionPayload {
            id: SECTION_COLUMN_DIRECTORY,
            elem_count: table.columns.len() as u64,
            bytes: &directory,
        },
        SectionPayload {
            id: SECTION_PRESENCE_BITMAPS,
            elem_count: table.columns.len() as u64,
            bytes: &presence,
        },
        SectionPayload {
            id: SECTION_NULL_BITMAPS,
            elem_count: table.columns.len() as u64,
            bytes: &nulls,
        },
        SectionPayload {
            id: SECTION_SCALAR_DATA,
            elem_count: scalar.len() as u64,
            bytes: &scalar,
        },
        SectionPayload {
            id: SECTION_STRING_OFFSETS,
            elem_count: (string_offsets.len() / 8) as u64,
            bytes: &string_offsets,
        },
    ];
    if has_strings {
        sections.push(SectionPayload {
            id: SECTION_STRING_BYTES,
            elem_count: string_bytes.len() as u64,
            bytes: &string_bytes,
        });
    }
    if has_json {
        sections.push(SectionPayload {
            id: SECTION_JSON_OFFSETS,
            elem_count: (json_offsets.len() / 8) as u64,
            bytes: &json_offsets,
        });
        sections.push(SectionPayload {
            id: SECTION_JSON_BYTES,
            elem_count: json_bytes.len() as u64,
            bytes: &json_bytes,
        });
    }
    graph_artifact::write(path, SPEC, flags, &sections)
}

pub(crate) fn open(path: &Path) -> Result<OpenedEdgeProperties> {
    let artifact = graph_artifact::open(path, SPEC)?;
    let has_strings = artifact.flags() & FLAG_STRING_DATA != 0;
    let has_json = artifact.flags() & FLAG_JSON_SPILL != 0;
    if artifact.section(SECTION_STRING_BYTES).is_some() != has_strings
        || artifact.section(SECTION_JSON_OFFSETS).is_some() != has_json
        || artifact.section(SECTION_JSON_BYTES).is_some() != has_json
    {
        return Err(corruption(
            path,
            "edgeprop.gdx optional sections disagree with flags",
        ));
    }

    let edge_section = artifact
        .section(SECTION_EDGE_IDS)
        .expect("common loader requires edge property keys");
    let edge_count = usize::try_from(edge_section.elem_count)
        .map_err(|_| corruption(path, "edgeprop.gdx row count exceeds usize"))?;
    if edge_section.length != checked_mul(edge_count, 8, path, "EdgeId section length")? {
        return Err(corruption(
            path,
            "edgeprop.gdx EdgeId section length disagrees",
        ));
    }
    validate_edge_ids(path, &artifact, edge_count)?;

    let directory_section = artifact
        .section(SECTION_COLUMN_DIRECTORY)
        .expect("common loader requires property directory");
    let directory_bytes = artifact.read_section(SECTION_COLUMN_DIRECTORY)?;
    let columns = decode_directory(
        path,
        &directory_bytes,
        directory_section.elem_count,
        edge_count,
    )?;
    validate_section_counts(path, &artifact, columns.len())?;
    let non_null_ranks =
        validate_columns(path, &artifact, edge_count, &columns, has_strings, has_json)?;
    Ok(OpenedEdgeProperties {
        artifact,
        edge_count,
        columns,
        non_null_ranks,
    })
}

fn validate_section_counts(
    path: &Path,
    artifact: &CheckedArtifact,
    column_count: usize,
) -> Result<()> {
    for id in [SECTION_PRESENCE_BITMAPS, SECTION_NULL_BITMAPS] {
        if artifact
            .section(id)
            .expect("required bitmap section")
            .elem_count
            != column_count as u64
        {
            return Err(corruption(
                path,
                "edgeprop.gdx bitmap section count disagrees",
            ));
        }
    }
    for id in [
        SECTION_SCALAR_DATA,
        SECTION_STRING_BYTES,
        SECTION_JSON_BYTES,
    ] {
        if let Some(section) = artifact.section(id)
            && section.elem_count != section.length as u64
        {
            return Err(corruption(
                path,
                "edgeprop.gdx byte section count disagrees",
            ));
        }
    }
    for id in [SECTION_STRING_OFFSETS, SECTION_JSON_OFFSETS] {
        if let Some(section) = artifact.section(id)
            && section.elem_count.checked_mul(8) != Some(section.length as u64)
        {
            return Err(corruption(
                path,
                "edgeprop.gdx offset section count disagrees",
            ));
        }
    }
    Ok(())
}

impl OpenedEdgeProperties {
    pub(crate) fn edge_count(&self) -> usize {
        self.edge_count
    }

    pub(crate) fn column_count(&self) -> usize {
        self.columns.len()
    }

    pub(crate) fn edge_id_at(&self, path: &Path, row_index: usize) -> Result<EdgeId> {
        if row_index >= self.edge_count {
            return Err(invalid("edgeprop.gdx row index is out of bounds"));
        }
        let offset = row_index
            .checked_mul(8)
            .ok_or_else(|| invalid("edgeprop.gdx EdgeId offset overflow"))?;
        let bytes = self
            .artifact
            .read_section_range(SECTION_EDGE_IDS, offset..offset + 8)?;
        let edge_id = EdgeId::from_raw(read_u64(&bytes, 0));
        validate_edge_id(edge_id).map_err(|error| corruption(path, &error.to_string()))?;
        Ok(edge_id)
    }

    pub(crate) fn find_edge(&self, path: &Path, edge_id: EdgeId) -> Result<Option<usize>> {
        validate_edge_id(edge_id)?;
        let mut low = 0_usize;
        let mut high = self.edge_count;
        while low < high {
            let mid = low + (high - low) / 2;
            match self.edge_id_at(path, mid)?.cmp(&edge_id) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return Ok(Some(mid)),
            }
        }
        Ok(None)
    }

    pub(crate) fn read_properties(
        &self,
        path: &Path,
        row_index: usize,
    ) -> Result<Map<String, Value>> {
        if row_index >= self.edge_count {
            return Err(invalid("edgeprop.gdx row index is out of bounds"));
        }
        let mut properties = Map::new();
        let mut document_bytes = 2_usize; // Object braces.
        for (column_index, column) in self.columns.iter().enumerate() {
            if !self.bitmap_bit(SECTION_PRESENCE_BITMAPS, column.presence_offset, row_index)? {
                continue;
            }
            if column.key.len() > MAX_EDGE_PROPERTY_BYTES {
                return Err(corruption(path, "edgeprop.gdx key exceeds property limit"));
            }
            let value = if self.bitmap_bit(SECTION_NULL_BITMAPS, column.null_offset, row_index)? {
                Value::Null
            } else {
                let value_index = self.non_null_rank(column, column_index, row_index)?;
                self.read_value(path, column, value_index)?
            };
            document_bytes = document_bytes.saturating_add(
                serde_json::to_vec(&column.key)?.len()
                    + 1
                    + serde_json::to_vec(&value)?.len()
                    + usize::from(!properties.is_empty()),
            );
            if document_bytes > MAX_EDGE_PROPERTY_BYTES {
                return Err(corruption(
                    path,
                    "edgeprop.gdx document exceeds graph property limit",
                ));
            }
            properties.insert(column.key.clone(), value);
        }
        Ok(properties)
    }

    fn bitmap_bit(&self, section_id: u32, offset: usize, row_index: usize) -> Result<bool> {
        let byte_offset = offset
            .checked_add(row_index / 8)
            .ok_or_else(|| invalid("edgeprop.gdx bitmap offset overflow"))?;
        let byte = self
            .artifact
            .read_section_range(section_id, byte_offset..byte_offset + 1)?[0];
        Ok(byte & (1 << (row_index % 8)) != 0)
    }

    fn non_null_rank(
        &self,
        column: &ColumnDescriptor,
        column_index: usize,
        row_index: usize,
    ) -> Result<usize> {
        let byte_count = row_index / 8;
        let block = byte_count / RANK_BLOCK_BYTES;
        let start = block * RANK_BLOCK_BYTES;
        let mut rank = self.non_null_ranks[column_index][block];
        if byte_count != start {
            let presence = self.artifact.read_section_range(
                SECTION_PRESENCE_BITMAPS,
                column.presence_offset + start..column.presence_offset + byte_count,
            )?;
            let nulls = self.artifact.read_section_range(
                SECTION_NULL_BITMAPS,
                column.null_offset + start..column.null_offset + byte_count,
            )?;
            rank += presence
                .iter()
                .zip(nulls.iter())
                .map(|(present, null)| (present & !null).count_ones() as usize)
                .sum::<usize>();
        }
        let bit = row_index % 8;
        if bit != 0 {
            let mask = (1_u8 << bit) - 1;
            let present = self.artifact.read_section_range(
                SECTION_PRESENCE_BITMAPS,
                column.presence_offset + byte_count..column.presence_offset + byte_count + 1,
            )?[0];
            let null = self.artifact.read_section_range(
                SECTION_NULL_BITMAPS,
                column.null_offset + byte_count..column.null_offset + byte_count + 1,
            )?[0];
            rank += ((present & !null) & mask).count_ones() as usize;
        }
        Ok(rank)
    }

    fn read_value(
        &self,
        path: &Path,
        column: &ColumnDescriptor,
        value_index: usize,
    ) -> Result<Value> {
        if value_index >= column.value_count {
            return Err(corruption(
                path,
                "edgeprop.gdx compact value index exceeds column count",
            ));
        }
        if let Some(width) = column.kind.scalar_width() {
            let start =
                column
                    .value_offset
                    .checked_add(value_index.checked_mul(width).ok_or_else(|| {
                        corruption(path, "edgeprop.gdx scalar value offset overflow")
                    })?)
                    .ok_or_else(|| corruption(path, "edgeprop.gdx scalar value offset overflow"))?;
            let bytes = self
                .artifact
                .read_section_range(SECTION_SCALAR_DATA, start..start + width)?;
            return decode_scalar(path, column.kind, &bytes);
        }
        let offsets_section = match column.kind {
            ColumnKind::String => SECTION_STRING_OFFSETS,
            ColumnKind::Json => SECTION_JSON_OFFSETS,
            _ => unreachable!("scalar kinds returned above"),
        };
        let data_section = match column.kind {
            ColumnKind::String => SECTION_STRING_BYTES,
            ColumnKind::Json => SECTION_JSON_BYTES,
            _ => unreachable!("scalar kinds returned above"),
        };
        let offset_start =
            column
                .value_offset
                .checked_add(value_index.checked_mul(8).ok_or_else(|| {
                    corruption(path, "edgeprop.gdx variable value offset overflow")
                })?)
                .ok_or_else(|| corruption(path, "edgeprop.gdx variable value offset overflow"))?;
        let offsets = self
            .artifact
            .read_section_range(offsets_section, offset_start..offset_start + 16)?;
        let start = usize::try_from(read_u64(&offsets, 0))
            .map_err(|_| corruption(path, "edgeprop.gdx data offset exceeds usize"))?;
        let end = usize::try_from(read_u64(&offsets, 8))
            .map_err(|_| corruption(path, "edgeprop.gdx data offset exceeds usize"))?;
        let absolute_start = column
            .data_offset
            .checked_add(start)
            .ok_or_else(|| corruption(path, "edgeprop.gdx data range overflow"))?;
        let absolute_end = column
            .data_offset
            .checked_add(end)
            .ok_or_else(|| corruption(path, "edgeprop.gdx data range overflow"))?;
        if start > end || end > column.data_len || end - start > MAX_EDGE_PROPERTY_BYTES {
            return Err(corruption(
                path,
                "edgeprop.gdx value range exceeds property bounds",
            ));
        }
        let bytes = self
            .artifact
            .read_section_range(data_section, absolute_start..absolute_end)?;
        match column.kind {
            ColumnKind::String => Ok(Value::String(
                std::str::from_utf8(&bytes)
                    .map_err(|_| corruption(path, "edgeprop.gdx string is not UTF-8"))?
                    .to_string(),
            )),
            ColumnKind::Json => {
                let value: Value = serde_json::from_slice(&bytes)
                    .map_err(|_| corruption(path, "edgeprop.gdx JSON spill is invalid"))?;
                if canonical_json_bytes(&value)
                    .map_err(|error| corruption(path, &error.to_string()))?
                    != bytes.as_ref()
                {
                    return Err(corruption(path, "edgeprop.gdx JSON spill is not canonical"));
                }
                Ok(value)
            }
            _ => unreachable!("scalar kinds returned above"),
        }
    }
}

fn encode_directory(row_count: usize, columns: &[EncodedColumn]) -> Result<Vec<u8>> {
    let mut keys = Vec::new();
    let mut records = Vec::with_capacity(
        columns
            .len()
            .checked_mul(DIRECTORY_RECORD_BYTES)
            .ok_or_else(|| invalid("edgeprop.gdx directory length overflow"))?,
    );
    for column in columns {
        let descriptor = &column.descriptor;
        let key_offset =
            u32::try_from(keys.len()).map_err(|_| invalid("edgeprop.gdx key area exceeds u32"))?;
        let key_len = u32::try_from(descriptor.key.len())
            .map_err(|_| invalid("edgeprop.gdx property key exceeds u32"))?;
        records.extend_from_slice(&key_offset.to_le_bytes());
        records.extend_from_slice(&key_len.to_le_bytes());
        records.push(descriptor.kind as u8);
        records.push(descriptor.kind as u8);
        records.extend_from_slice(&0_u16.to_le_bytes());
        records.extend_from_slice(&0_u32.to_le_bytes());
        for value in [
            descriptor.presence_offset,
            descriptor.presence_len,
            descriptor.null_offset,
            descriptor.null_len,
            descriptor.value_offset,
            descriptor.value_len,
            descriptor.data_offset,
            descriptor.data_len,
            descriptor.value_count,
            row_count,
        ] {
            records.extend_from_slice(
                &u64::try_from(value)
                    .map_err(|_| invalid("edgeprop.gdx directory value exceeds u64"))?
                    .to_le_bytes(),
            );
        }
        records.extend_from_slice(&0_u64.to_le_bytes());
        records.extend_from_slice(&0_u64.to_le_bytes());
        keys.extend_from_slice(descriptor.key.as_bytes());
    }
    let mut bytes = Vec::with_capacity(DIRECTORY_HEADER_BYTES + records.len() + keys.len());
    bytes.extend_from_slice(
        &u32::try_from(columns.len())
            .map_err(|_| invalid("edgeprop.gdx column count exceeds u32"))?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&(DIRECTORY_RECORD_BYTES as u32).to_le_bytes());
    bytes.extend_from_slice(
        &u64::try_from(keys.len())
            .map_err(|_| invalid("edgeprop.gdx key area exceeds u64"))?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&records);
    bytes.extend_from_slice(&keys);
    Ok(bytes)
}

fn decode_directory(
    path: &Path,
    bytes: &[u8],
    table_count: u64,
    row_count: usize,
) -> Result<Vec<ColumnDescriptor>> {
    if bytes.len() < DIRECTORY_HEADER_BYTES {
        return Err(corruption(path, "truncated edgeprop.gdx directory header"));
    }
    let column_count = read_u32(bytes, 0) as usize;
    if table_count != column_count as u64 || read_u32(bytes, 4) as usize != DIRECTORY_RECORD_BYTES {
        return Err(corruption(
            path,
            "edgeprop.gdx directory metadata disagrees",
        ));
    }
    let record_len = checked_mul(
        column_count,
        DIRECTORY_RECORD_BYTES,
        path,
        "directory records",
    )?;
    let key_start = DIRECTORY_HEADER_BYTES
        .checked_add(record_len)
        .ok_or_else(|| corruption(path, "edgeprop.gdx key offset overflow"))?;
    let key_len = usize::try_from(read_u64(bytes, 8))
        .map_err(|_| corruption(path, "edgeprop.gdx key length exceeds usize"))?;
    if key_start.checked_add(key_len) != Some(bytes.len()) {
        return Err(corruption(path, "edgeprop.gdx key area length disagrees"));
    }
    let keys = &bytes[key_start..];
    let mut expected_key_offset = 0_usize;
    let mut previous_key: Option<&[u8]> = None;
    let mut columns = Vec::with_capacity(column_count);
    for index in 0..column_count {
        let start = DIRECTORY_HEADER_BYTES + index * DIRECTORY_RECORD_BYTES;
        let record = &bytes[start..start + DIRECTORY_RECORD_BYTES];
        let key_offset = read_u32(record, 0) as usize;
        let key_len = read_u32(record, 4) as usize;
        if key_offset != expected_key_offset || key_len == 0 {
            return Err(corruption(
                path,
                "edgeprop.gdx key ranges are non-canonical",
            ));
        }
        let key_end = key_offset
            .checked_add(key_len)
            .ok_or_else(|| corruption(path, "edgeprop.gdx key range overflow"))?;
        if key_end > keys.len() {
            return Err(corruption(path, "edgeprop.gdx key exceeds key area"));
        }
        let key_bytes = &keys[key_offset..key_end];
        if previous_key.is_some_and(|previous| previous >= key_bytes) {
            return Err(corruption(
                path,
                "edgeprop.gdx property keys are not strictly ordered",
            ));
        }
        previous_key = Some(key_bytes);
        let key = std::str::from_utf8(key_bytes)
            .map_err(|_| corruption(path, "edgeprop.gdx property key is not UTF-8"))?
            .to_string();
        let kind = ColumnKind::from_code(record[8])
            .ok_or_else(|| corruption(path, "edgeprop.gdx logical type is unknown"))?;
        if record[9] != kind as u8
            || read_u16(record, 10) != 0
            || read_u32(record, 12) != 0
            || read_u64(record, 96) != 0
            || read_u64(record, 104) != 0
        {
            return Err(corruption(
                path,
                "edgeprop.gdx directory encoding or reserved fields are invalid",
            ));
        }
        let encoded_row_count = usize::try_from(read_u64(record, 88))
            .map_err(|_| corruption(path, "edgeprop.gdx row count exceeds usize"))?;
        if encoded_row_count != row_count {
            return Err(corruption(path, "edgeprop.gdx column row count disagrees"));
        }
        columns.push(ColumnDescriptor {
            key,
            kind,
            presence_offset: read_usize(path, record, 16, "presence offset")?,
            presence_len: read_usize(path, record, 24, "presence length")?,
            null_offset: read_usize(path, record, 32, "null offset")?,
            null_len: read_usize(path, record, 40, "null length")?,
            value_offset: read_usize(path, record, 48, "value offset")?,
            value_len: read_usize(path, record, 56, "value length")?,
            data_offset: read_usize(path, record, 64, "data offset")?,
            data_len: read_usize(path, record, 72, "data length")?,
            value_count: read_usize(path, record, 80, "value count")?,
        });
        expected_key_offset = key_end;
    }
    if expected_key_offset != keys.len() {
        return Err(corruption(path, "edgeprop.gdx key area is not fully owned"));
    }
    Ok(columns)
}

fn validate_columns(
    path: &Path,
    artifact: &CheckedArtifact,
    row_count: usize,
    columns: &[ColumnDescriptor],
    has_strings: bool,
    has_json: bool,
) -> Result<Vec<Vec<usize>>> {
    let bitmap_bytes =
        bitmap_len(row_count).map_err(|error| corruption(path, &error.to_string()))?;
    let mut presence_cursor = 0_usize;
    let mut null_cursor = 0_usize;
    let mut scalar_cursor = 0_usize;
    let mut string_offset_cursor = 0_usize;
    let mut string_data_cursor = 0_usize;
    let mut json_offset_cursor = 0_usize;
    let mut json_data_cursor = 0_usize;
    let mut saw_string = false;
    let mut saw_json = false;
    let mut ranks = Vec::with_capacity(columns.len());

    for column in columns {
        if column.presence_offset != presence_cursor
            || column.presence_len != bitmap_bytes
            || column.null_offset != null_cursor
            || column.null_len != bitmap_bytes
        {
            return Err(corruption(
                path,
                "edgeprop.gdx bitmap ranges are non-canonical",
            ));
        }
        let mut checkpoints = vec![0];
        let mut value_count = 0;
        for start in (0..bitmap_bytes).step_by(RANK_BLOCK_BYTES) {
            let end = (start + RANK_BLOCK_BYTES).min(bitmap_bytes);
            let presence = artifact.read_section_range(
                SECTION_PRESENCE_BITMAPS,
                column.presence_offset + start..column.presence_offset + end,
            )?;
            let nulls = artifact.read_section_range(
                SECTION_NULL_BITMAPS,
                column.null_offset + start..column.null_offset + end,
            )?;
            validate_bitmaps(
                path,
                (row_count - start * 8).min(RANK_BLOCK_BYTES * 8),
                &presence,
                &nulls,
            )?;
            value_count += presence
                .iter()
                .zip(nulls.iter())
                .map(|(present, null)| (present & !null).count_ones() as usize)
                .sum::<usize>();
            checkpoints.push(value_count);
        }
        if value_count != column.value_count {
            return Err(corruption(
                path,
                "edgeprop.gdx compact value count disagrees with bitmaps",
            ));
        }
        presence_cursor += bitmap_bytes;
        null_cursor += bitmap_bytes;
        ranks.push(checkpoints);

        match column.kind {
            ColumnKind::Bool | ColumnKind::I64 | ColumnKind::U64 | ColumnKind::F64 => {
                let width = column.kind.scalar_width().expect("matched scalar kind");
                let expected_len =
                    checked_mul(column.value_count, width, path, "scalar column length")?;
                if column.value_offset != scalar_cursor
                    || column.value_len != expected_len
                    || column.data_offset != 0
                    || column.data_len != 0
                {
                    return Err(corruption(
                        path,
                        "edgeprop.gdx scalar range is non-canonical",
                    ));
                }
                for start in (0..column.value_len).step_by(64 * 1024) {
                    let end = (start + 64 * 1024).min(column.value_len);
                    let values = artifact.read_section_range(
                        SECTION_SCALAR_DATA,
                        column.value_offset + start..column.value_offset + end,
                    )?;
                    validate_scalar_bytes(path, column.kind, &values)?;
                }
                scalar_cursor += expected_len;
            }
            ColumnKind::String => {
                saw_string = true;
                validate_variable_column(
                    path,
                    artifact,
                    column,
                    SECTION_STRING_OFFSETS,
                    SECTION_STRING_BYTES,
                    &mut string_offset_cursor,
                    &mut string_data_cursor,
                )?;
            }
            ColumnKind::Json => {
                saw_json = true;
                validate_variable_column(
                    path,
                    artifact,
                    column,
                    SECTION_JSON_OFFSETS,
                    SECTION_JSON_BYTES,
                    &mut json_offset_cursor,
                    &mut json_data_cursor,
                )?;
            }
        }
    }
    let section_len = |id| artifact.section(id).map_or(0, |section| section.length);
    if presence_cursor != section_len(SECTION_PRESENCE_BITMAPS)
        || null_cursor != section_len(SECTION_NULL_BITMAPS)
        || scalar_cursor != section_len(SECTION_SCALAR_DATA)
        || string_offset_cursor != section_len(SECTION_STRING_OFFSETS)
        || string_data_cursor != section_len(SECTION_STRING_BYTES)
        || json_offset_cursor != section_len(SECTION_JSON_OFFSETS)
        || json_data_cursor != section_len(SECTION_JSON_BYTES)
        || saw_string != has_strings
        || saw_json != has_json
    {
        return Err(corruption(
            path,
            "edgeprop.gdx sections contain gaps or unowned bytes",
        ));
    }
    Ok(ranks)
}

fn validate_variable_column(
    path: &Path,
    artifact: &CheckedArtifact,
    column: &ColumnDescriptor,
    offsets_section: u32,
    data_section: u32,
    offsets_cursor: &mut usize,
    data_cursor: &mut usize,
) -> Result<()> {
    let offset_count = column
        .value_count
        .checked_add(1)
        .ok_or_else(|| corruption(path, "edgeprop.gdx offset count overflow"))?;
    let expected_offset_len = checked_mul(offset_count, 8, path, "variable offsets length")?;
    if column.value_offset != *offsets_cursor
        || column.value_len != expected_offset_len
        || column.data_offset != *data_cursor
    {
        return Err(corruption(
            path,
            "edgeprop.gdx variable ranges are non-canonical",
        ));
    }
    let mut previous = None;
    for block in (0..offset_count).step_by(8192) {
        let end = (block + 8192).min(offset_count);
        let offset_bytes = artifact.read_section_range(
            offsets_section,
            column.value_offset + block * 8..column.value_offset + end * 8,
        )?;
        for raw in offset_bytes.chunks_exact(8) {
            let end = usize::try_from(u64::from_le_bytes(raw.try_into().unwrap()))
                .map_err(|_| corruption(path, "edgeprop.gdx value offset exceeds usize"))?;
            let Some(start) = previous.replace(end) else {
                if end != 0 {
                    return Err(corruption(
                        path,
                        "edgeprop.gdx first variable offset is not zero",
                    ));
                }
                continue;
            };
            if start > end || end > column.data_len || end - start > MAX_EDGE_PROPERTY_BYTES {
                return Err(corruption(
                    path,
                    "edgeprop.gdx variable offsets are invalid or oversized",
                ));
            }
            let bytes = artifact.read_section_range(
                data_section,
                column.data_offset + start..column.data_offset + end,
            )?;
            let value = bytes.as_ref();
            match column.kind {
                ColumnKind::String => {
                    std::str::from_utf8(value)
                        .map_err(|_| corruption(path, "edgeprop.gdx string is not UTF-8"))?;
                }
                ColumnKind::Json => {
                    let parsed: Value = serde_json::from_slice(value)
                        .map_err(|_| corruption(path, "edgeprop.gdx JSON spill is invalid"))?;
                    if canonical_json_bytes(&parsed)
                        .map_err(|error| corruption(path, &error.to_string()))?
                        != value
                    {
                        return Err(corruption(path, "edgeprop.gdx JSON spill is not canonical"));
                    }
                }
                _ => unreachable!("only variable kinds call this validator"),
            }
        }
    }
    if previous != Some(column.data_len) {
        return Err(corruption(
            path,
            "edgeprop.gdx final variable offset disagrees with data",
        ));
    }
    *offsets_cursor += expected_offset_len;
    *data_cursor += column.data_len;
    Ok(())
}

fn validate_edge_ids(path: &Path, artifact: &CheckedArtifact, edge_count: usize) -> Result<()> {
    const KEYS_PER_BATCH: usize = (64 * 1024) / 8;
    let mut previous = None;
    for start in (0..edge_count).step_by(KEYS_PER_BATCH) {
        let end = (start + KEYS_PER_BATCH).min(edge_count);
        let bytes = artifact.read_section_range(SECTION_EDGE_IDS, start * 8..end * 8)?;
        for raw in bytes
            .chunks_exact(8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("checked EdgeId width")))
        {
            let edge_id = EdgeId::from_raw(raw);
            validate_edge_id(edge_id).map_err(|error| corruption(path, &error.to_string()))?;
            if previous.is_some_and(|prior| prior >= raw) {
                return Err(corruption(
                    path,
                    "edgeprop.gdx EdgeIds are not strictly increasing",
                ));
            }
            previous = Some(raw);
        }
    }
    Ok(())
}

fn validate_bitmaps(path: &Path, row_count: usize, presence: &[u8], nulls: &[u8]) -> Result<()> {
    if presence.len() != nulls.len()
        || presence
            .iter()
            .zip(nulls)
            .any(|(present, null)| null & !present != 0)
    {
        return Err(corruption(
            path,
            "edgeprop.gdx null bitmap is not a presence subset",
        ));
    }
    if !row_count.is_multiple_of(8) && !presence.is_empty() {
        let valid_mask = (1_u8 << (row_count % 8)) - 1;
        if presence[presence.len() - 1] & !valid_mask != 0
            || nulls[nulls.len() - 1] & !valid_mask != 0
        {
            return Err(corruption(
                path,
                "edgeprop.gdx bitmap tail bits are non-zero",
            ));
        }
    }
    Ok(())
}

fn validate_scalar_bytes(path: &Path, kind: ColumnKind, bytes: &[u8]) -> Result<()> {
    match kind {
        ColumnKind::Bool if bytes.iter().any(|value| *value > 1) => Err(corruption(
            path,
            "edgeprop.gdx bool scalar is not zero or one",
        )),
        ColumnKind::F64
            if bytes.chunks_exact(8).any(|raw| {
                !f64::from_le_bytes(raw.try_into().expect("checked f64 width")).is_finite()
            }) =>
        {
            Err(corruption(path, "edgeprop.gdx f64 scalar is non-finite"))
        }
        _ => Ok(()),
    }
}

fn encode_scalars(kind: ColumnKind, values: &[Value], bytes: &mut Vec<u8>) -> Result<()> {
    for value in values {
        match kind {
            ColumnKind::Bool => {
                bytes.push(u8::from(value.as_bool().ok_or_else(|| {
                    invalid("edgeprop.gdx bool column contains another type")
                })?))
            }
            ColumnKind::I64 => bytes.extend_from_slice(
                &value
                    .as_i64()
                    .ok_or_else(|| invalid("edgeprop.gdx i64 column contains another type"))?
                    .to_le_bytes(),
            ),
            ColumnKind::U64 => bytes.extend_from_slice(
                &value
                    .as_u64()
                    .ok_or_else(|| invalid("edgeprop.gdx u64 column contains another type"))?
                    .to_le_bytes(),
            ),
            ColumnKind::F64 => {
                let value = value
                    .as_f64()
                    .filter(|value| value.is_finite())
                    .ok_or_else(|| invalid("edgeprop.gdx f64 column contains an invalid value"))?;
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            ColumnKind::String | ColumnKind::Json => {
                return Err(invalid("edgeprop.gdx variable kind used as scalar"));
            }
        }
    }
    Ok(())
}

fn encode_variable_values(
    kind: ColumnKind,
    values: &[Value],
    offsets: &mut Vec<u8>,
    data: &mut Vec<u8>,
) -> Result<()> {
    offsets.extend_from_slice(&0_u64.to_le_bytes());
    for value in values {
        match kind {
            ColumnKind::String => data.extend_from_slice(
                value
                    .as_str()
                    .ok_or_else(|| invalid("edgeprop.gdx string column contains another type"))?
                    .as_bytes(),
            ),
            ColumnKind::Json => data.extend_from_slice(&canonical_json_bytes(value)?),
            _ => return Err(invalid("edgeprop.gdx scalar kind used as variable")),
        }
        offsets.extend_from_slice(
            &u64::try_from(data.len())
                .map_err(|_| invalid("edgeprop.gdx variable data exceeds u64"))?
                .to_le_bytes(),
        );
    }
    Ok(())
}

fn decode_scalar(path: &Path, kind: ColumnKind, bytes: &[u8]) -> Result<Value> {
    match kind {
        ColumnKind::Bool => match bytes[0] {
            0 => Ok(Value::Bool(false)),
            1 => Ok(Value::Bool(true)),
            _ => Err(corruption(path, "edgeprop.gdx bool scalar is invalid")),
        },
        ColumnKind::I64 => Ok(Value::from(i64::from_le_bytes(
            bytes.try_into().expect("checked i64 width"),
        ))),
        ColumnKind::U64 => Ok(Value::from(u64::from_le_bytes(
            bytes.try_into().expect("checked u64 width"),
        ))),
        ColumnKind::F64 => {
            let value = f64::from_le_bytes(bytes.try_into().expect("checked f64 width"));
            serde_json::Number::from_f64(value)
                .map(Value::Number)
                .ok_or_else(|| corruption(path, "edgeprop.gdx f64 scalar is non-finite"))
        }
        ColumnKind::String | ColumnKind::Json => Err(corruption(
            path,
            "edgeprop.gdx variable kind read as scalar",
        )),
    }
}

fn classify_value(value: &Value) -> Result<ColumnKind> {
    match value {
        Value::Null => Err(invalid(
            "edgeprop.gdx cannot classify explicit null as data",
        )),
        Value::Bool(_) => Ok(ColumnKind::Bool),
        Value::Number(number) if number.as_i64().is_some() => Ok(ColumnKind::I64),
        Value::Number(number) if number.as_u64().is_some() => Ok(ColumnKind::U64),
        Value::Number(number) if number.as_f64().is_some_and(|number| number.is_finite()) => {
            Ok(ColumnKind::F64)
        }
        Value::Number(_) => Err(invalid("edgeprop.gdx contains a non-finite number")),
        Value::String(_) => Ok(ColumnKind::String),
        Value::Array(_) | Value::Object(_) => Ok(ColumnKind::Json),
    }
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            Value::Object(object) => {
                let mut entries = object.iter().collect::<Vec<_>>();
                entries.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
                let mut result = Map::new();
                for (key, value) in entries {
                    result.insert(key.clone(), canonical(value));
                }
                Value::Object(result)
            }
            scalar => scalar.clone(),
        }
    }
    serde_json::to_vec(&canonical(value)).map_err(GaussError::from)
}

fn bitmap_len(row_count: usize) -> Result<usize> {
    row_count
        .checked_add(7)
        .map(|count| count / 8)
        .ok_or_else(|| invalid("edgeprop.gdx bitmap length overflow"))
}

fn set_bit(bitmap: &mut [u8], index: usize) {
    bitmap[index / 8] |= 1 << (index % 8);
}

fn validate_edge_id(edge_id: EdgeId) -> Result<()> {
    if edge_id.raw() == 0
        || edge_id.epoch() == 0
        || edge_id.epoch() > GRAPH_ALLOCATOR_MAX_EPOCH
        || edge_id.counter() == 0
        || edge_id.counter() > GRAPH_ALLOCATOR_MAX_COUNTER
    {
        return Err(invalid("edgeprop.gdx contains an invalid EdgeId"));
    }
    Ok(())
}

fn checked_mul(left: usize, right: usize, path: &Path, field: &str) -> Result<usize> {
    left.checked_mul(right)
        .ok_or_else(|| corruption(path, &format!("edgeprop.gdx {field} overflow")))
}

fn read_usize(path: &Path, bytes: &[u8], offset: usize, field: &str) -> Result<usize> {
    usize::try_from(read_u64(bytes, offset))
        .map_err(|_| corruption(path, &format!("edgeprop.gdx {field} exceeds usize")))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("checked u16 width"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked u32 width"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("checked u64 width"),
    )
}

fn invalid(message: impl Into<String>) -> GaussError {
    GaussError::InvalidRequest(message.into())
}

fn corruption(path: &Path, message: &str) -> GaussError {
    GaussError::SegmentCorruption {
        path: path.display().to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, process::Command};

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;

    use super::*;

    const ENCRYPTED_HELPER_ENV: &str = "CHIRONDB_GRAPH_EDGEPROP_ENCRYPTED_HELPER_DIR";

    fn edge_id(counter: u64) -> EdgeId {
        EdgeId::from_parts(43, counter).unwrap()
    }

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn fixture() -> EdgePropertyTable {
        EdgePropertyTable::build(vec![
            EdgePropertyInput {
                edge_id: edge_id(2),
                properties: object(json!({
                    "big": u64::MAX - 1,
                    "count": 3,
                    "flag": true,
                    "mixed": "scalar",
                    "name": "beta",
                    "ratio": 1.25,
                })),
            },
            EdgePropertyInput {
                edge_id: edge_id(1),
                properties: object(json!({
                    "big": u64::MAX,
                    "count": -2,
                    "flag": false,
                    "mixed": {"z": 1, "a": [2]},
                    "name": "alpha",
                    "nullish": null,
                })),
            },
        ])
        .unwrap()
    }

    #[test]
    fn typed_columns_round_trip_absent_null_scalar_string_and_canonical_json() {
        let table = fixture();
        assert_eq!(table.edge_count(), 2);
        assert_eq!(table.column_count(), 7);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_PROPERTY_FILE);
        write(&path, &table).unwrap();
        let opened = open(&path).unwrap();
        assert_eq!(opened.edge_count(), 2);
        assert_eq!(opened.column_count(), 7);
        assert_eq!(opened.edge_id_at(&path, 0).unwrap(), edge_id(1));
        assert_eq!(opened.find_edge(&path, edge_id(2)).unwrap(), Some(1));
        assert_eq!(opened.find_edge(&path, edge_id(9)).unwrap(), None);

        let first = opened.read_properties(&path, 0).unwrap();
        assert_eq!(first["flag"], json!(false));
        assert_eq!(first["count"], json!(-2));
        assert_eq!(first["big"], json!(u64::MAX));
        assert_eq!(first["name"], json!("alpha"));
        assert_eq!(first["nullish"], Value::Null);
        assert_eq!(first["mixed"], json!({"a": [2], "z": 1}));
        assert!(!first.contains_key("ratio"));

        let second = opened.read_properties(&path, 1).unwrap();
        assert_eq!(second["ratio"], json!(1.25));
        assert!(!second.contains_key("nullish"));
        assert_eq!(second["mixed"], json!("scalar"));
    }

    #[test]
    fn empty_property_artifact_is_required_peer_and_round_trips() {
        let table = EdgePropertyTable::build(vec![]).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_PROPERTY_FILE);
        write(&path, &table).unwrap();
        let opened = open(&path).unwrap();
        assert_eq!(opened.edge_count(), 0);
        assert_eq!(opened.column_count(), 0);
    }

    fn assert_ranked_lookup(path: &Path) {
        // Cross two rank-block boundaries and a partial final byte. Sparse,
        // explicit-null and mixed columns must share exactly the same ranks
        // in plaintext and authenticated modes.
        let rows = RANK_BLOCK_BYTES * 8 * 2 + 13;
        let document = |row: usize| {
            let mut properties = object(json!({"ordinal":row}));
            if !row.is_multiple_of(3) {
                properties.insert(
                    "sparse".into(),
                    if row.is_multiple_of(5) {
                        Value::Null
                    } else {
                        json!(row)
                    },
                );
            }
            if row.is_multiple_of(17) {
                properties.insert(
                    "mixed".into(),
                    if row.is_multiple_of(2) {
                        json!([row])
                    } else {
                        json!("text")
                    },
                );
            }
            properties
        };
        let table = EdgePropertyTable::build(
            (0..rows)
                .map(|row| EdgePropertyInput {
                    edge_id: edge_id(row as u64 + 1),
                    properties: document(row),
                })
                .collect(),
        )
        .unwrap();
        write(path, &table).unwrap();
        drop(table);
        let reader = open(path).unwrap();
        assert!(reader.non_null_ranks.iter().all(|ranks| ranks.len() == 4));
        for row in [
            0,
            1,
            7,
            8,
            15,
            16,
            32767,
            32768,
            32769,
            65535,
            65536,
            rows - 1,
        ] {
            let found = reader
                .find_edge(path, edge_id(row as u64 + 1))
                .unwrap()
                .unwrap();
            assert_eq!(found, row);
            assert_eq!(
                reader.read_properties(path, row).unwrap(),
                document(row),
                "row {row}"
            );
            for (index, column) in reader.columns.iter().enumerate() {
                let expected = (0..row)
                    .filter(|row| {
                        document(*row)
                            .get(&column.key)
                            .is_some_and(|v| !v.is_null())
                    })
                    .count();
                assert_eq!(reader.non_null_rank(column, index, row).unwrap(), expected);
            }
        }
        assert!(reader.read_properties(path, rows).is_err());
        assert!(
            reader
                .find_edge(path, edge_id(rows as u64 + 1))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn property_lookup_uses_bounded_rank_checkpoints() {
        let temp = tempfile::tempdir().unwrap();
        assert_ranked_lookup(&temp.path().join(EDGE_PROPERTY_FILE));
    }

    #[test]
    fn builder_rejects_duplicate_invalid_edge_ids_and_empty_keys() {
        assert!(
            EdgePropertyTable::build(vec![EdgePropertyInput {
                edge_id: EdgeId::from_raw(0),
                properties: Map::new(),
            }])
            .is_err()
        );
        assert!(
            EdgePropertyTable::build(vec![
                EdgePropertyInput {
                    edge_id: edge_id(1),
                    properties: Map::new(),
                },
                EdgePropertyInput {
                    edge_id: edge_id(1),
                    properties: Map::new(),
                },
            ])
            .is_err()
        );
        let mut properties = Map::new();
        properties.insert(String::new(), json!(1));
        assert!(
            EdgePropertyTable::build(vec![EdgePropertyInput {
                edge_id: edge_id(1),
                properties,
            }])
            .is_err()
        );
        assert!(
            EdgePropertyTable::build(vec![EdgePropertyInput {
                edge_id: edge_id(1),
                properties: object(json!({"too_large":"x".repeat(MAX_EDGE_PROPERTY_BYTES)})),
            }])
            .is_err()
        );
    }

    #[test]
    fn loader_rejects_directory_bitmap_and_noncanonical_json_corruption() {
        let table = fixture();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_PROPERTY_FILE);
        write(&path, &table).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        let directory = artifact.section(SECTION_COLUMN_DIRECTORY).unwrap();
        let mut bad_encoding = fs::read(&path).unwrap();
        bad_encoding[directory.offset + DIRECTORY_HEADER_BYTES + 9] = ColumnKind::Json as u8;
        fs::write(&path, bad_encoding).unwrap();
        assert!(open(&path).is_err());

        write(&path, &table).unwrap();
        let artifact = graph_artifact::open(&path, SPEC).unwrap();
        let nulls = artifact.section(SECTION_NULL_BITMAPS).unwrap();
        let mut bad_null = fs::read(&path).unwrap();
        bad_null[nulls.offset + 5] |= 1 << 1;
        fs::write(&path, bad_null).unwrap();
        assert!(open(&path).is_err());

        write(&path, &table).unwrap();
        let mut bad_json = fs::read(&path).unwrap();
        let canonical = br#"{"a":[2],"z":1}"#;
        let replacement = br#"{"z":1,"a":[2]}"#;
        let start = bad_json
            .windows(canonical.len())
            .position(|window| window == canonical)
            .expect("fixture has canonical JSON object");
        bad_json[start..start + canonical.len()].copy_from_slice(replacement);
        fs::write(&path, bad_json).unwrap();
        assert!(open(&path).is_err());
    }

    #[test]
    fn loader_rejects_oversized_variable_value_before_reading_it() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(EDGE_PROPERTY_FILE);
        // Bypass the builder to represent malformed on-disk input.
        let table = EdgePropertyTable {
            edge_ids: vec![edge_id(1)],
            columns: vec![PropertyColumn {
                key: "oversized".into(),
                kind: ColumnKind::String,
                presence: vec![1],
                nulls: vec![0],
                values: vec![json!("x".repeat(MAX_EDGE_PROPERTY_BYTES + 1))],
            }],
        };
        write(&path, &table).unwrap();
        assert!(open(&path).err().unwrap().to_string().contains("oversized"));
    }

    #[test]
    fn property_artifact_uses_authenticated_chunks_when_encryption_is_enabled() {
        if env::var_os(ENCRYPTED_HELPER_ENV).is_some() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let status = Command::new(env::current_exe().unwrap())
            .arg("--exact")
            .arg("graph_edgeprop::tests::encrypted_property_artifact_helper")
            .arg("--nocapture")
            .env(ENCRYPTED_HELPER_ENV, temp.path())
            .env("RUST_TEST_THREADS", "1")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "encrypted edgeprop helper failed: {status}"
        );
    }

    #[test]
    fn encrypted_property_artifact_helper() {
        let Some(root) = env::var_os(ENCRYPTED_HELPER_ENV) else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let keyring_path = root.join("keyring.json");
        fs::write(
            &keyring_path,
            json!({
                "version": 1,
                "active_key_id": "g1-edgeprop",
                "keys": [{
                    "id": "g1-edgeprop",
                    "key_base64": STANDARD.encode([67_u8; 32]),
                }],
            })
            .to_string(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&keyring_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        crate::encryption::install_process_keyring(
            crate::encryption::Keyring::load(&keyring_path).unwrap(),
            true,
        )
        .unwrap();
        let path = root.join(EDGE_PROPERTY_FILE);
        write(&path, &fixture()).unwrap();
        assert_eq!(&fs::read(&path).unwrap()[..8], crate::encryption::MAGIC);
        let opened = open(&path).unwrap();
        assert_eq!(opened.read_properties(&path, 0).unwrap()["name"], "alpha");
        let mut ciphertext = fs::read(&path).unwrap();
        *ciphertext
            .last_mut()
            .expect("encrypted edgeprop is non-empty") ^= 1;
        fs::write(&path, ciphertext).unwrap();
        assert!(open(&path).is_err());
        assert_ranked_lookup(&root.join("ranked.gdx"));
    }
}
