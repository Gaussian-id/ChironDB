//! Opaque public EdgeId token codec.
//!
//! The encoded form is a fixed-width v1 record:
//! `version:u8 | database_uuid:[u8;16] | edge_id:u64(le) | crc32c:u32(le)`,
//! serialized with URL-safe base64 and no padding. Decode errors deliberately
//! collapse to one graph error so callers cannot probe another incarnation.

#![cfg_attr(
    not(test),
    allow(dead_code, reason = "consumed by the following typed graph API slice")
)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use uuid::Uuid;

use crate::{
    Result,
    graph::{EdgeId, EdgeToken, GraphError, GraphErrorCode},
};

const EDGE_TOKEN_VERSION: u8 = 1;
const EDGE_TOKEN_PAYLOAD_BYTES: usize = 1 + 16 + 8;
const EDGE_TOKEN_BYTES: usize = EDGE_TOKEN_PAYLOAD_BYTES + 4;
const EDGE_TOKEN_ENCODED_BYTES: usize = 39;

pub(crate) fn encode(database_id: Uuid, edge_id: EdgeId) -> Result<EdgeToken> {
    if database_id.is_nil() || !valid_edge_id(edge_id) {
        return Err(invalid_token().into());
    }
    let mut bytes = [0_u8; EDGE_TOKEN_BYTES];
    bytes[0] = EDGE_TOKEN_VERSION;
    bytes[1..17].copy_from_slice(database_id.as_bytes());
    bytes[17..25].copy_from_slice(&edge_id.raw().to_le_bytes());
    let checksum = crc_fast::crc32_iscsi(&bytes[..EDGE_TOKEN_PAYLOAD_BYTES]);
    bytes[EDGE_TOKEN_PAYLOAD_BYTES..].copy_from_slice(&checksum.to_le_bytes());
    Ok(EdgeToken::from_encoded(URL_SAFE_NO_PAD.encode(bytes)))
}

pub(crate) fn decode(database_id: Uuid, token: &EdgeToken) -> Result<EdgeId> {
    if database_id.is_nil() || token.as_str().len() != EDGE_TOKEN_ENCODED_BYTES {
        return Err(invalid_token().into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(token.as_str())
        .map_err(|_| invalid_token())?;
    let bytes: [u8; EDGE_TOKEN_BYTES] = bytes.try_into().map_err(|_| invalid_token())?;
    if bytes[0] != EDGE_TOKEN_VERSION {
        return Err(invalid_token().into());
    }
    let expected = u32::from_le_bytes(
        bytes[EDGE_TOKEN_PAYLOAD_BYTES..]
            .try_into()
            .expect("fixed EdgeToken CRC"),
    );
    if crc_fast::crc32_iscsi(&bytes[..EDGE_TOKEN_PAYLOAD_BYTES]) != expected {
        return Err(invalid_token().into());
    }
    if bytes[1..17] != *database_id.as_bytes() {
        return Err(invalid_token().into());
    }
    let edge_id = EdgeId::from_raw(u64::from_le_bytes(
        bytes[17..25].try_into().expect("fixed EdgeToken EdgeId"),
    ));
    if !valid_edge_id(edge_id) {
        return Err(invalid_token().into());
    }
    Ok(edge_id)
}

fn valid_edge_id(edge_id: EdgeId) -> bool {
    edge_id.epoch() != 0 && edge_id.counter() != 0
}

fn invalid_token() -> GraphError {
    GraphError::new(
        GraphErrorCode::EdgeNotFound,
        "edge token is invalid or belongs to another database incarnation",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database_id() -> Uuid {
        Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap()
    }

    fn edge_id() -> EdgeId {
        EdgeId::from_parts(0x12_3456, 0x12_3456_789a).unwrap()
    }

    #[test]
    fn token_is_fixed_url_safe_and_round_trips() {
        let token = encode(database_id(), edge_id()).unwrap();
        assert_eq!(token.as_str().len(), EDGE_TOKEN_ENCODED_BYTES);
        assert!(
            token
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        assert!(!token.as_str().contains('='));
        assert_eq!(decode(database_id(), &token).unwrap(), edge_id());
        assert_eq!(
            serde_json::from_str::<EdgeToken>(&serde_json::to_string(&token).unwrap()).unwrap(),
            token
        );
    }

    #[test]
    fn wrong_incarnation_and_tampering_fail_with_one_stable_error() {
        let token = encode(database_id(), edge_id()).unwrap();
        let wrong_database = Uuid::parse_str("10112233-4455-6677-8899-aabbccddeeff").unwrap();
        for invalid in [
            token.clone(),
            EdgeToken::from_encoded(format!("A{}", &token.as_str()[1..])),
            EdgeToken::from_encoded("not-a-token"),
        ] {
            let database = if invalid == token {
                wrong_database
            } else {
                database_id()
            };
            let error = decode(database, &invalid).unwrap_err();
            assert!(matches!(
                error,
                crate::GaussError::Graph(GraphError {
                    code: GraphErrorCode::EdgeNotFound,
                    ..
                })
            ));
        }
    }

    #[test]
    fn invalid_internal_identity_is_never_encoded_or_decoded() {
        assert!(encode(database_id(), EdgeId::from_raw(0)).is_err());

        let valid = encode(database_id(), edge_id()).unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(valid.as_str()).unwrap();
        bytes[17..25].fill(0);
        let checksum = crc_fast::crc32_iscsi(&bytes[..EDGE_TOKEN_PAYLOAD_BYTES]);
        bytes[EDGE_TOKEN_PAYLOAD_BYTES..].copy_from_slice(&checksum.to_le_bytes());
        assert!(
            decode(
                database_id(),
                &EdgeToken::from_encoded(URL_SAFE_NO_PAD.encode(bytes)),
            )
            .is_err()
        );
    }
}
