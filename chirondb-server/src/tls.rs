use std::{
    path::{Path, PathBuf},
    sync::{Arc, Once},
    time::Duration,
};

use parking_lot::RwLock;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier},
    sign::CertifiedKey,
};
use sha2::{Digest, Sha256};

static INSTALL_PROVIDER: Once = Once::new();

#[derive(Debug)]
struct ReloadingCertificateResolver {
    current: RwLock<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for ReloadingCertificateResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().clone())
    }
}

/// One certificate resolver shared by HTTP, gRPC, ChironWire and pgwire.
/// Replacements affect only new TLS handshakes; established connections keep
/// the certificate and traffic keys with which they were negotiated.
#[derive(Clone, Debug)]
pub struct ReloadingTlsConfig {
    config: Arc<ServerConfig>,
    resolver: Arc<ReloadingCertificateResolver>,
    cert_path: PathBuf,
    key_path: PathBuf,
    observed_digest: Arc<RwLock<[u8; 32]>>,
}

impl ReloadingTlsConfig {
    pub async fn load(
        cert_path: PathBuf,
        key_path: PathBuf,
        client_ca: Option<PathBuf>,
    ) -> std::io::Result<Self> {
        install_default_crypto_provider();
        let (certified_key, digest) = load_certified_key(&cert_path, &key_path).await?;
        let resolver = Arc::new(ReloadingCertificateResolver {
            current: RwLock::new(Arc::new(certified_key)),
        });
        let builder = ServerConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS13,
            &rustls::version::TLS12,
        ]);
        let builder = match client_ca {
            Some(client_ca) => {
                let roots = client_root_store(client_ca).await?;
                let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(std::io::Error::other)?;
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let mut config = builder.with_cert_resolver(resolver.clone());
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.max_early_data_size = 0;
        Ok(Self {
            config: Arc::new(config),
            resolver,
            cert_path,
            key_path,
            observed_digest: Arc::new(RwLock::new(digest)),
        })
    }

    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.config.clone()
    }

    pub async fn reload_if_changed(&self) -> std::io::Result<bool> {
        let cert = tokio::fs::read(&self.cert_path).await?;
        let key = tokio::fs::read(&self.key_path).await?;
        let digest = certificate_digest(&cert, &key);
        if digest == *self.observed_digest.read() {
            return Ok(false);
        }
        // Remember the attempted atomic replacement. An invalid pair must not
        // cause a log/audit storm, but any subsequent file replacement gets a
        // fresh digest and is retried.
        *self.observed_digest.write() = digest;
        let certified_key = certified_key_from_pem(&cert, &key)?;
        *self.resolver.current.write() = Arc::new(certified_key);
        Ok(true)
    }

    pub fn spawn_reloader(&self, db: chirondb_core::Db) -> tokio::task::JoinHandle<()> {
        let config = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                match config.reload_if_changed().await {
                    Ok(false) => {}
                    Ok(true) => {
                        metrics::counter!("chirondb_tls_certificate_reload_total", "outcome" => "success")
                            .increment(1);
                        if let Err(error) = db.audit_access_event(
                            "admin",
                            "tls_certificate_reload",
                            "success",
                            None,
                            "server",
                            None,
                            "internal",
                            None,
                            None,
                        ) {
                            tracing::error!(%error, "TLS reload audit write failed");
                        }
                        tracing::info!("TLS certificate and key reloaded for new connections");
                    }
                    Err(error) => {
                        metrics::counter!("chirondb_tls_certificate_reload_total", "outcome" => "failure")
                            .increment(1);
                        if let Err(audit_error) = db.audit_access_event(
                            "admin",
                            "tls_certificate_reload",
                            "failure",
                            None,
                            "server",
                            None,
                            "internal",
                            None,
                            Some("invalid_certificate_rotation"),
                        ) {
                            tracing::error!(%audit_error, "TLS reload failure audit write failed");
                        }
                        tracing::error!(%error, "invalid TLS certificate rotation; retaining last valid certificate");
                    }
                }
            }
        })
    }
}

pub fn install_default_crypto_provider() {
    INSTALL_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub async fn server_config(
    cert: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
) -> std::io::Result<ServerConfig> {
    install_default_crypto_provider();
    let certs = load_certs(cert).await?;
    let key = load_private_key(key).await?;
    let builder = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ]);
    let builder = match client_ca {
        Some(client_ca) => {
            let roots = client_root_store(client_ca).await?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(std::io::Error::other)?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    builder
        .with_single_cert(certs, key)
        .map_err(std::io::Error::other)
}

async fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> std::io::Result<(CertifiedKey, [u8; 32])> {
    let cert = tokio::fs::read(cert_path).await?;
    let key = tokio::fs::read(key_path).await?;
    let digest = certificate_digest(&cert, &key);
    Ok((certified_key_from_pem(&cert, &key)?, digest))
}

fn certified_key_from_pem(cert: &[u8], key: &[u8]) -> std::io::Result<CertifiedKey> {
    let certs = CertificateDer::pem_slice_iter(cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(std::io::Error::other)?;
    let key = PrivateKeyDer::from_pem_slice(key).map_err(std::io::Error::other)?;
    CertifiedKey::from_der(certs, key, &rustls::crypto::ring::default_provider())
        .map_err(std::io::Error::other)
}

fn certificate_digest(cert: &[u8], key: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update((cert.len() as u64).to_be_bytes());
    digest.update(cert);
    digest.update(key);
    digest.finalize().into()
}

pub async fn client_config(
    ca_cert: PathBuf,
    client_identity: Option<(PathBuf, PathBuf)>,
) -> std::io::Result<ClientConfig> {
    install_default_crypto_provider();
    let roots = client_root_store(ca_cert).await?;
    let builder = ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_root_certificates(roots);
    match client_identity {
        Some((cert, key)) => {
            let certs = load_certs(cert).await?;
            let key = load_private_key(key).await?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(std::io::Error::other)
        }
        None => Ok(builder.with_no_client_auth()),
    }
}

pub async fn client_root_store(ca_cert: PathBuf) -> std::io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca_cert).await? {
        roots.add(cert).map_err(std::io::Error::other)?;
    }
    Ok(roots)
}

pub async fn load_certs(path: impl AsRef<Path>) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let bytes = tokio::fs::read(path).await?;
    CertificateDer::pem_slice_iter(bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(std::io::Error::other)
}

pub async fn load_private_key(path: impl AsRef<Path>) -> std::io::Result<PrivateKeyDer<'static>> {
    let bytes = tokio::fs::read(path).await?;
    PrivateKeyDer::from_pem_slice(bytes.as_slice()).map_err(std::io::Error::other)
}
