//! Stream canonical, kind-first journal mutations into typed rows. Serde's
//! internally tagged derive buffers the entire mutation as Content, including
//! every numeric cell map. Its generic admission then retains that transient
//! tree's reservation for the lifetime of the complete transaction DTO.
//!
//! Keep the persisted representation unchanged. Noncanonical field order uses
//! a guarded prefix buffer only until the tag is encountered; unknown fields,
//! duplicate fields and required fields are still handled by derived visitors.
use super::{RelationalMutation, StoredRow, TableDefinition};
use serde::{
    Deserialize,
    de::{self, DeserializeSeed, EnumAccess, MapAccess, VariantAccess, Visitor},
};
use std::fmt;
mod prefix;

#[cfg(test)]
mod tests;

// An externally tagged remote derive supplies typed variant-body visitors;
// Tagged below provides the existing internal `kind` as its discriminant.
#[derive(Deserialize)]
#[serde(remote = "RelationalMutation", rename_all = "snake_case")]
enum Body {
    RowSecurity {
        delta: chirondb_types::relational::RelationalSecurityDelta,
    },
    CreateTable {
        definition: TableDefinition,
    },
    DropTable {
        name: String,
    },
    AlterTable {
        definition: TableDefinition,
    },
    RenameTable {
        old_name: String,
        definition: TableDefinition,
    },
    RewriteTable {
        definition: TableDefinition,
        rows: Vec<StoredRow>,
    },
    Insert {
        table: String,
        rows: Vec<StoredRow>,
    },
    Update {
        table: String,
        rows: Vec<StoredRow>,
    },
    Delete {
        table: String,
        row_ids: Vec<u64>,
    },
}

impl<'de> Deserialize<'de> for RelationalMutation {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        decoder.deserialize_map(Mutation)
    }
}

struct Mutation;
impl<'de> Visitor<'de> for Mutation {
    type Value = RelationalMutation;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a relational mutation with a kind tag")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut prefix = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if key == "kind" {
                let kind = map.next_value::<String>()?;
                return Body::deserialize(de::value::EnumAccessDeserializer::new(Tagged {
                    kind,
                    map: Fields {
                        prefix: prefix.into_iter(),
                        pending: None,
                        map,
                    },
                }));
            }
            // The enclosing guarded MapAccess admits keys, values and prefix
            // capacity before growth. Canonical writers always put kind first.
            prefix.push((key, map.next_value::<prefix::Value>()?));
        }
        Err(de::Error::missing_field("kind"))
    }
}

struct Fields<A> {
    prefix: std::vec::IntoIter<(String, prefix::Value)>,
    pending: Option<prefix::Value>,
    map: A,
}
impl<'de, A: MapAccess<'de>> MapAccess<'de> for Fields<A> {
    type Error = A::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        if let Some((key, value)) = self.prefix.next() {
            self.pending = Some(value);
            return seed
                .deserialize(de::value::StringDeserializer::new(key))
                .map(Some);
        }
        // Unlike an unknown body field, a second tag must never be ignored.
        match self.map.next_key::<String>()? {
            Some(key) if key == "kind" => Err(de::Error::duplicate_field("kind")),
            Some(key) => seed
                .deserialize(de::value::StringDeserializer::new(key))
                .map(Some),
            None => Ok(None),
        }
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        if let Some(value) = self.pending.take() {
            seed.deserialize(value).map_err(de::Error::custom)
        } else {
            self.map.next_value_seed(seed)
        }
    }
}

struct Tagged<A> {
    kind: String,
    map: Fields<A>,
}
impl<'de, A: MapAccess<'de>> EnumAccess<'de> for Tagged<A> {
    type Error = A::Error;
    type Variant = Fields<A>;
    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Self::Error> {
        Ok((
            seed.deserialize(de::value::StringDeserializer::new(self.kind))?,
            self.map,
        ))
    }
}
impl<'de, A: MapAccess<'de>> VariantAccess<'de> for Fields<A> {
    type Error = A::Error;
    fn struct_variant<V: Visitor<'de>>(
        self,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_map(self)
    }
    fn unit_variant(self) -> Result<(), Self::Error> {
        Err(de::Error::custom("expected a mutation body"))
    }
    fn newtype_variant_seed<V: DeserializeSeed<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
        Err(de::Error::custom("expected a mutation body"))
    }
    fn tuple_variant<V: Visitor<'de>>(self, _: usize, _: V) -> Result<V::Value, Self::Error> {
        Err(de::Error::custom("expected a mutation body"))
    }
}
