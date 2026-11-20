//! Validate the same normalized URL and environment options used by object_store.
use object_store::{ClientConfigKey, ObjectStoreScheme, aws::AmazonS3ConfigKey};
use url::Url;

use crate::{GaussError, Result};

/// Secure installations permit local stores and HTTPS-only remote stores.
/// Option values and URLs may contain credentials, so errors never echo them.
pub fn validate_secure_object_store_url(raw_url: &str) -> Result<()> {
    let url = Url::parse(raw_url).map_err(|_| invalid("invalid object-store URL"))?;
    validate_options(&url, &std::env::vars().collect::<Vec<_>>())
}

pub(super) fn validate_options(url: &Url, options: &[(String, String)]) -> Result<()> {
    let (scheme, _) = ObjectStoreScheme::parse(url)
        .map_err(|_| invalid("invalid object-store URL or backend"))?;
    match scheme {
        ObjectStoreScheme::Local | ObjectStoreScheme::Memory => return Ok(()),
        ObjectStoreScheme::Http if url.scheme() != "https" => {
            return Err(invalid("secure mode requires HTTPS object-store URLs"));
        }
        ObjectStoreScheme::Http | ObjectStoreScheme::AmazonS3 => {}
        _ => return Err(invalid("unsupported secure object-store backend")),
    }
    for (name, value) in options {
        let name = name.to_ascii_lowercase();
        // parse_url_opts lowercases and parses these exact keys before building.
        let client = if scheme == ObjectStoreScheme::AmazonS3 {
            match name.parse::<AmazonS3ConfigKey>() {
                Ok(AmazonS3ConfigKey::Client(key)) => Some(key),
                Ok(
                    AmazonS3ConfigKey::Endpoint
                    | AmazonS3ConfigKey::S3Endpoint
                    | AmazonS3ConfigKey::StsEndpoint,
                ) => {
                    if !Url::parse(value).is_ok_and(|endpoint| endpoint.scheme() == "https") {
                        return Err(invalid("secure mode requires HTTPS object-store endpoints"));
                    }
                    None
                }
                _ => None,
            }
        } else {
            name.parse::<ClientConfigKey>().ok()
        };
        if matches!(
            client,
            Some(ClientConfigKey::AllowHttp | ClientConfigKey::AllowInvalidCertificates)
        ) && value.parse::<bool>() != Ok(false)
        {
            return Err(invalid(
                "secure mode forbids insecure object-store transport options",
            ));
        }
    }
    Ok(())
}

fn invalid(message: &str) -> GaussError {
    GaussError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(raw_url: &str, values: &[(&str, &str)]) -> Result<()> {
        validate_options(
            &Url::parse(raw_url).unwrap(),
            &values
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn rejects_normalized_http_and_keeps_local_and_https_backends() {
        for value in ["http", "HTTP", "hTtP"] {
            assert!(options(&format!(" {value}://localhost:1/objects\n"), &[]).is_err());
        }
        for value in [
            "https://objects.example/root",
            "HTTPS://objects.example/root",
            "s3://bucket/root",
            "file:///tmp/root",
            "memory:///",
        ] {
            options(value, &[]).unwrap();
        }
    }

    #[test]
    fn rejects_s3_plaintext_endpoint_and_client_overrides() {
        for key in [
            "AWS_ENDPOINT",
            "AWS_ENDPOINT_URL",
            "aws_endpoint_url_s3",
            "ENDPOINT_URL",
            "endpoint",
            "AWS_ENDPOINT_URL_STS",
        ] {
            assert!(options("s3://bucket/root", &[(key, "hTtP://localhost:1")]).is_err());
            options("s3://bucket/root", &[(key, "HTTPS://objects.example")]).unwrap();
        }
        for key in [
            "AWS_ALLOW_HTTP",
            "allow_http",
            "aws_allow_invalid_certificates",
            "ALLOW_INVALID_CERTIFICATES",
        ] {
            assert!(options("s3://bucket/root", &[(key, "true")]).is_err());
            options("s3://bucket/root", &[(key, "false")]).unwrap();
        }
        // Local storage does not consume remote transport environment options.
        options(
            "file:///tmp/root",
            &[("AWS_ENDPOINT", "http://localhost:1")],
        )
        .unwrap();
    }

    #[test]
    fn rejects_http_backend_tls_bypass_and_does_not_echo_options() {
        for key in ["allow_http", "ALLOW_INVALID_CERTIFICATES"] {
            let error = options(
                "https://objects.example",
                &[(key, "invalid-sensitive-value")],
            )
            .unwrap_err();
            assert!(!error.to_string().contains("invalid-sensitive-value"));
            options("https://objects.example", &[(key, "false")]).unwrap();
        }
    }
}
