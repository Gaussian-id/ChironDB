//! Bounded PostgreSQL SASL/SCRAM-SHA-256 exchange over an already verified TLS stream.
use std::{io, time::Duration};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use chirondb_core::security::SqlVerifier;

const MAX_AUTH_MESSAGE: usize = 4096;
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) enum ScramOutcome {
    Authenticated,
    Failed,
    UnsupportedMechanism,
}

pub(super) async fn authenticate<R, W>(
    reader: &mut R,
    writer: &mut W,
    verifier: &SqlVerifier,
) -> io::Result<ScramOutcome>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Two bounded authentication frames, derived strings/base64 and cryptographic
    // scratch are small but concurrent exchanges still need aggregate admission.
    let _scratch = super::output::reserve(32 * 1024)?;
    write_auth(writer, 10, b"SCRAM-SHA-256\0\0").await?;
    let initial = read_password_payload(reader).await?;
    let initial = initial.as_ref();
    let Some(method_end) = initial.iter().position(|byte| *byte == 0) else {
        return Ok(ScramOutcome::Failed);
    };
    if &initial[..method_end] != b"SCRAM-SHA-256" {
        return Ok(ScramOutcome::UnsupportedMechanism);
    }
    let rest = &initial[method_end + 1..];
    if rest.len() < 4 {
        return Ok(ScramOutcome::Failed);
    }
    let data_len = i32::from_be_bytes(rest[..4].try_into().expect("four bytes"));
    if data_len < 0 || rest.len() != 4 + data_len as usize {
        return Ok(ScramOutcome::Failed);
    }
    let Ok(first) = std::str::from_utf8(&rest[4..]) else {
        return Ok(ScramOutcome::Failed);
    };
    let (gs2, first_bare) = if let Some(bare) = first.strip_prefix("n,,") {
        ("n,,", bare)
    } else if let Some(bare) = first.strip_prefix("y,,") {
        ("y,,", bare)
    } else {
        return Ok(ScramOutcome::Failed);
    };
    let Some((name, client_nonce)) = first_bare.split_once(",r=") else {
        return Ok(ScramOutcome::Failed);
    };
    if !name.starts_with("n=")
        || name.len() > 256
        || client_nonce.is_empty()
        || client_nonce.len() > 256
        || !client_nonce
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b',')
    {
        return Ok(ScramOutcome::Failed);
    }

    let mut random = [0u8; 18];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("SCRAM nonce unavailable"))?;
    let nonce = format!("{client_nonce}{}", URL_SAFE_NO_PAD.encode(random));
    let server_first = format!(
        "r={nonce},s={},i={}",
        STANDARD.encode(verifier.salt),
        verifier.iterations
    );
    write_auth(writer, 11, server_first.as_bytes()).await?;
    let final_payload = read_password_payload(reader).await?;
    let Ok(client_final) = std::str::from_utf8(final_payload.as_ref()) else {
        return Ok(ScramOutcome::Failed);
    };
    let Some((without_proof, proof_b64)) = client_final.rsplit_once(",p=") else {
        return Ok(ScramOutcome::Failed);
    };
    let expected_binding = STANDARD.encode(gs2);
    if without_proof != format!("c={expected_binding},r={nonce}") {
        return Ok(ScramOutcome::Failed);
    }
    let Ok(proof) = STANDARD.decode(proof_b64) else {
        return Ok(ScramOutcome::Failed);
    };
    if proof.len() != 32 {
        return Ok(ScramOutcome::Failed);
    }
    let auth_message = format!("{first_bare},{server_first},{without_proof}");
    let Some(server_signature) = verify_proof(verifier, auth_message.as_bytes(), &proof) else {
        return Ok(ScramOutcome::Failed);
    };
    let server_final = format!("v={}", STANDARD.encode(server_signature));
    write_auth(writer, 12, server_final.as_bytes()).await?;
    Ok(ScramOutcome::Authenticated)
}

fn verify_proof(verifier: &SqlVerifier, auth_message: &[u8], proof: &[u8]) -> Option<[u8; 32]> {
    if proof.len() != 32 {
        return None;
    }
    let client_signature = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, &verifier.stored_key),
        auth_message,
    );
    let mut client_key = [0u8; 32];
    for (i, value) in client_key.iter_mut().enumerate() {
        *value = proof[i] ^ client_signature.as_ref()[i];
    }
    let derived_key = digest::digest(&digest::SHA256, &client_key);
    if !bool::from(derived_key.as_ref().ct_eq(&verifier.stored_key)) {
        return None;
    }
    Some(
        hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &verifier.server_key),
            auth_message,
        )
        .as_ref()
        .try_into()
        .expect("SHA-256 signature"),
    )
}

async fn read_password_payload<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<crate::response_buffer::ResponseBuffer> {
    let mut header = [0u8; 5];
    tokio::time::timeout(AUTH_TIMEOUT, reader.read_exact(&mut header))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SCRAM message timed out"))??;
    let len = u32::from_be_bytes(header[1..].try_into().expect("four bytes")) as usize;
    if header[0] != b'p' || !(4..=MAX_AUTH_MESSAGE).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SCRAM message",
        ));
    }
    super::frontend::read(reader, len - 4, MAX_AUTH_MESSAGE).await
}

async fn write_auth<W: AsyncWrite + Unpin>(
    writer: &mut W,
    code: u32,
    payload: &[u8],
) -> io::Result<()> {
    let mut body =
        super::output::prepare(writer, super::output::control(b'R', 4 + payload.len())).await?;
    body.as_mut()[5..9].copy_from_slice(&code.to_be_bytes());
    body.as_mut()[9..].copy_from_slice(payload);
    tokio::io::AsyncWriteExt::write_all(writer, body.as_ref()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::pbkdf2;

    #[test]
    fn rfc7677_scram_sha256_example() {
        // RFC 7677 section 3: user / pencil, fixed nonce and salt.
        let salt = STANDARD.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let mut salted = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(4096).unwrap(),
            &salt,
            b"pencil",
            &mut salted,
        );
        let client_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Client Key");
        let stored_key = digest::digest(&digest::SHA256, client_key.as_ref());
        let server_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Server Key");
        let verifier = SqlVerifier {
            id: "test".into(),
            salt: salt.try_into().unwrap(),
            stored_key: stored_key.as_ref().try_into().unwrap(),
            server_key: server_key.as_ref().try_into().unwrap(),
            iterations: 4096,
        };
        let auth_message = concat!(
            "n=user,r=rOprNGfwEbeRWgbNEkqO,",
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,",
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
        );
        let proof = STANDARD
            .decode("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
            .unwrap();
        assert_eq!(
            STANDARD.encode(verify_proof(&verifier, auth_message.as_bytes(), &proof).unwrap()),
            "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
        );
        let mut invalid = proof;
        invalid[0] ^= 1;
        assert!(verify_proof(&verifier, auth_message.as_bytes(), &invalid).is_none());
    }
}
