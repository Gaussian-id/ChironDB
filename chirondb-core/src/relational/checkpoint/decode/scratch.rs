//! Bound serde_json's reusable slice-parser scratch without allocating. Strings
//! and long numbers use at most their encoded token length; IgnoredAny uses one
//! byte per enclosing container. Three times the high water covers geometric
//! growth while both allocations coexist. Input and retained DTOs have separate
//! owners. The reader decoder keeps its whole-payload bound (no prepass).
use super::*;

pub(super) fn slice_bound(input: &[u8]) -> Result<u64> {
    let mut in_string = false;
    let mut escaped = false;
    let mut token = 0_u64;
    let mut longest = 0_u64;
    let mut depth = 0_u64;
    let mut deepest = 0_u64;
    for (offset, &byte) in input.iter().enumerate() {
        if offset % BUFFER_BYTES == 0 {
            check_sql_cancelled()?;
        }
        if in_string {
            token += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
                longest = longest.max(token);
                token = 0;
            }
        } else {
            match byte {
                b'"' => {
                    longest = longest.max(token);
                    token = 1;
                    in_string = true;
                }
                b'[' | b'{' => {
                    longest = longest.max(token);
                    token = 0;
                    depth += 1;
                    deepest = deepest.max(depth);
                }
                b']' | b'}' => {
                    longest = longest.max(token);
                    token = 0;
                    depth = depth.saturating_sub(1);
                }
                b',' | b':' | b' ' | b'\n' | b'\r' | b'\t' => {
                    longest = longest.max(token);
                    token = 0;
                }
                _ => token += 1,
            }
        }
    }
    // Unterminated tokens still need scratch before the parser reports an error.
    longest
        .max(token)
        .checked_add(deepest)
        .and_then(|bytes| bytes.checked_mul(3))
        .and_then(|bytes| bytes.checked_add(4096))
        .ok_or_else(sql_overloaded)
}
