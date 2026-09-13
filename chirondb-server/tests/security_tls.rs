use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use chirondb::{
    Db, api,
    auth::AuthConfig,
    grpc::{
        self, chiron_pb,
        pb::{self, HealthRequest, WireRequest, wire_request::Operation},
    },
    tls::{self, ReloadingTlsConfig},
    wire,
    wire_postgres::{PROTOCOL_V3, SSL_REQUEST_MAGIC},
};
use prost::Message;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SigningKey,
};
use rustls::{ClientConfig, ProtocolVersion, ServerConfig, pki_types::ServerName};
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

struct TestPki {
    _temp: TempDir,
    ca: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    replacement_cert: PathBuf,
    replacement_key: PathBuf,
    replacement_der: Vec<u8>,
    initial_der: Vec<u8>,
    client_cert: PathBuf,
    client_key: PathBuf,
}

#[tokio::test]
async fn tls_policy_accepts_only_tls12_tls13_and_requires_client_identity_when_configured() {
    let pki = test_pki();
    let server = tls::server_config(pki.server_cert.clone(), pki.server_key.clone(), None)
        .await
        .unwrap();
    assert_eq!(server.max_early_data_size, 0, "0-RTT must stay disabled");

    for (version, expected) in [
        (&rustls::version::TLS12, ProtocolVersion::TLSv1_2),
        (&rustls::version::TLS13, ProtocolVersion::TLSv1_3),
    ] {
        let roots = tls::client_root_store(pki.ca.clone()).await.unwrap();
        let client = ClientConfig::builder_with_protocol_versions(&[version])
            .with_root_certificates(roots)
            .with_no_client_auth();
        let (negotiated, peer) = handshake(Arc::new(server.clone()), Arc::new(client))
            .await
            .unwrap();
        assert_eq!(negotiated, expected);
        assert_eq!(peer, pki.initial_der);
    }

    let mtls_server = tls::server_config(
        pki.server_cert.clone(),
        pki.server_key.clone(),
        Some(pki.ca.clone()),
    )
    .await
    .unwrap();
    let anonymous = tls::client_config(pki.ca.clone(), None).await.unwrap();
    assert!(
        handshake(Arc::new(mtls_server.clone()), Arc::new(anonymous))
            .await
            .is_err(),
        "mandatory mTLS accepted an anonymous client"
    );

    let identified = tls::client_config(
        pki.ca.clone(),
        Some((pki.client_cert.clone(), pki.client_key.clone())),
    )
    .await
    .unwrap();
    handshake(Arc::new(mtls_server), Arc::new(identified))
        .await
        .unwrap();
}

#[tokio::test]
async fn certificate_reload_is_atomic_and_invalid_rotation_keeps_last_identity() {
    let pki = test_pki();
    let reloadable =
        ReloadingTlsConfig::load(pki.server_cert.clone(), pki.server_key.clone(), None)
            .await
            .unwrap();
    assert!(!reloadable.reload_if_changed().await.unwrap());

    let client = Arc::new(tls::client_config(pki.ca.clone(), None).await.unwrap());
    let (_, first_peer) = handshake(reloadable.server_config(), client.clone())
        .await
        .unwrap();
    assert_eq!(first_peer, pki.initial_der);

    chirondb::fs_util::atomic_write(&pki.server_cert, &fs::read(&pki.replacement_cert).unwrap())
        .unwrap();
    chirondb::fs_util::atomic_write(&pki.server_key, &fs::read(&pki.replacement_key).unwrap())
        .unwrap();
    assert!(reloadable.reload_if_changed().await.unwrap());
    let (_, replacement_peer) = handshake(reloadable.server_config(), client.clone())
        .await
        .unwrap();
    assert_eq!(replacement_peer, pki.replacement_der);

    chirondb::fs_util::atomic_write(&pki.server_cert, b"invalid certificate").unwrap();
    chirondb::fs_util::atomic_write(&pki.server_key, b"invalid private key").unwrap();
    assert!(reloadable.reload_if_changed().await.is_err());
    let (_, retained_peer) = handshake(reloadable.server_config(), client).await.unwrap();
    assert_eq!(retained_peer, pki.replacement_der);
}

#[tokio::test]
async fn wire_listener_supports_direct_tls_libpq_sslrequest_and_rejects_plaintext() {
    let pki = test_pki();
    let data = tempfile::tempdir().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(wire::serve_tls_listener_with_auth(
        db,
        AuthConfig::disabled(),
        listener,
        pki.server_cert.clone(),
        pki.server_key.clone(),
        None,
    ));

    let response = wire::send_request_tls(
        &addr.to_string(),
        "localhost",
        pki.ca.clone(),
        None,
        health_request(7),
    )
    .await
    .unwrap();
    assert_eq!(response.request_id, 7);
    assert!(response.error_code.is_empty());

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(&8_u32.to_be_bytes()).await.unwrap();
    tcp.write_all(&SSL_REQUEST_MAGIC.to_be_bytes())
        .await
        .unwrap();
    tcp.flush().await.unwrap();
    let mut ssl_reply = [0_u8; 1];
    tcp.read_exact(&mut ssl_reply).await.unwrap();
    assert_eq!(ssl_reply, [b'S']);

    let connector = TlsConnector::from(Arc::new(
        tls::client_config(pki.ca.clone(), None).await.unwrap(),
    ));
    let mut pg_tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    pg_tls
        .write_all(&startup_message("tls-user", "tls-db"))
        .await
        .unwrap();
    loop {
        let (kind, _) = read_pg_message(&mut pg_tls).await.unwrap();
        if kind == b'Z' {
            break;
        }
    }

    let mut plaintext = TcpStream::connect(addr).await.unwrap();
    plaintext
        .write_all(&startup_message("plain-user", "plain-db"))
        .await
        .unwrap();
    plaintext.shutdown().await.unwrap();
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), plaintext.read(&mut byte))
        .await
        .unwrap();
    if let Ok(1) = read {
        assert_ne!(
            byte[0], b'R',
            "plaintext received PostgreSQL authentication"
        );
    }

    task.abort();
}

#[tokio::test]
async fn direct_wire_mtls_rejects_anonymous_and_accepts_identified_client() {
    let pki = test_pki();
    let data = tempfile::tempdir().unwrap();
    let db = Db::open(data.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(wire::serve_tls_listener_with_auth(
        db,
        AuthConfig::disabled(),
        listener,
        pki.server_cert.clone(),
        pki.server_key.clone(),
        Some(pki.ca.clone()),
    ));

    assert!(
        wire::send_request_tls(
            &addr.to_string(),
            "localhost",
            pki.ca.clone(),
            None,
            health_request(11),
        )
        .await
        .is_err()
    );
    let response = wire::send_request_tls(
        &addr.to_string(),
        "localhost",
        pki.ca,
        Some((pki.client_cert, pki.client_key)),
        health_request(12),
    )
    .await
    .unwrap();
    assert_eq!(response.request_id, 12);
    assert!(response.error_code.is_empty());

    task.abort();
}

#[tokio::test]
async fn grpc_tls_mtls_serves_both_primary_and_compatibility_namespaces() {
    let pki = test_pki();
    let data = tempfile::tempdir().unwrap();
    let addr = unused_loopback_addr().await;
    let task = tokio::spawn(grpc::serve_tls_with_auth(
        Db::open(data.path()).unwrap(),
        AuthConfig::disabled(),
        addr,
        pki.server_cert.clone(),
        pki.server_key.clone(),
        Some(pki.ca.clone()),
    ));

    let ca = Certificate::from_pem(fs::read(&pki.ca).unwrap());
    let identity = Identity::from_pem(
        fs::read(&pki.client_cert).unwrap(),
        fs::read(&pki.client_key).unwrap(),
    );
    let channel = connect_grpc_tls(
        addr,
        ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(ca.clone())
            .identity(identity),
    )
    .await;

    let mut compatibility = pb::gauss_db_client::GaussDbClient::new(channel.clone());
    let compat_health = compatibility
        .health(HealthRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(compat_health.status, "ok");

    let mut primary = chiron_pb::chiron_db_client::ChironDbClient::new(channel);
    let primary_health = primary.health(HealthRequest {}).await.unwrap().into_inner();
    assert_eq!(primary_health.status, "ok");

    let anonymous = Endpoint::from_shared(format!("https://{addr}"))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(ca),
        )
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(3), anonymous.connect())
        .await
        .unwrap()
    {
        Err(_) => {}
        Ok(channel) => {
            let mut client = pb::gauss_db_client::GaussDbClient::new(channel);
            assert!(
                client.health(HealthRequest {}).await.is_err(),
                "gRPC mTLS accepted an anonymous client request"
            );
        }
    }

    task.abort();
}

#[tokio::test]
async fn http_and_grpc_web_are_served_over_tls_with_explicit_cors() {
    let pki = test_pki();
    let data = tempfile::tempdir().unwrap();
    let db = Db::open(data.path()).unwrap();
    let http_addr = unused_loopback_addr().await;
    let grpc_addr = unused_loopback_addr().await;
    let http_task = tokio::spawn(api::serve_tls_with_auth(
        db.clone(),
        AuthConfig::disabled(),
        http_addr,
        pki.server_cert.clone(),
        pki.server_key.clone(),
        None,
    ));
    let grpc_task = tokio::spawn(grpc::serve_tls_with_options(
        db,
        AuthConfig::disabled(),
        grpc_addr,
        pki.server_cert,
        pki.server_key,
        None,
        grpc::GrpcServerOptions {
            grpc_web_enabled: true,
            cors_origins: vec!["https://ui.example".to_string()],
            ..Default::default()
        },
    ));

    let client = reqwest::Client::builder()
        .http1_only()
        .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(&pki.ca).unwrap()).unwrap())
        .build()
        .unwrap();
    let health = retry_http_get(
        &client,
        format!("https://localhost:{}/health", http_addr.port()),
    )
    .await;
    assert_eq!(health.status(), reqwest::StatusCode::OK);
    let health_json: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_json["status"], "ok");
    assert!(health_json.get("data_dir").is_none());
    assert!(health_json.get("collections").is_none());

    let response = retry_grpc_web(&client, grpc_addr).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok()),
        Some("https://ui.example")
    );
    let body = response.bytes().await.unwrap();
    assert!(body.len() >= 5);
    assert_eq!(body[0], 0, "expected a gRPC-Web data frame");
    let message_len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    assert!(body.len() >= 5 + message_len);
    let health = pb::HealthResponse::decode(&body[5..5 + message_len]).unwrap();
    assert_eq!(health.status, "ok");

    http_task.abort();
    grpc_task.abort();
}

async fn handshake(
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
) -> Result<(ProtocolVersion, Vec<u8>), String> {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let accept = TlsAcceptor::from(server).accept(server_io);
    let connect =
        TlsConnector::from(client).connect(ServerName::try_from("localhost").unwrap(), client_io);
    let (server_result, client_result) = tokio::join!(accept, connect);
    server_result.map_err(|error| format!("server handshake: {error}"))?;
    let client = client_result.map_err(|error| format!("client handshake: {error}"))?;
    let connection = &client.get_ref().1;
    let version = connection
        .protocol_version()
        .ok_or_else(|| "missing negotiated TLS version".to_string())?;
    let peer = connection
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| "missing server certificate".to_string())?
        .to_vec();
    Ok((version, peer))
}

async fn unused_loopback_addr() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn connect_grpc_tls(
    addr: std::net::SocketAddr,
    tls: ClientTlsConfig,
) -> tonic::transport::Channel {
    let endpoint = Endpoint::from_shared(format!("https://{addr}"))
        .unwrap()
        .tls_config(tls)
        .unwrap();
    for _ in 0..40 {
        if let Ok(channel) = endpoint.connect().await {
            return channel;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    endpoint.connect().await.unwrap()
}

async fn retry_http_get(client: &reqwest::Client, url: String) -> reqwest::Response {
    for _ in 0..40 {
        if let Ok(response) = client.get(&url).send().await {
            return response;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    client.get(url).send().await.unwrap()
}

async fn retry_grpc_web(client: &reqwest::Client, addr: std::net::SocketAddr) -> reqwest::Response {
    let url = format!(
        "https://localhost:{}/gaussdb.v1.GaussDb/Health",
        addr.port()
    );
    for _ in 0..40 {
        let response = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/grpc-web+proto")
            .header("x-grpc-web", "1")
            .header(reqwest::header::ORIGIN, "https://ui.example")
            .body(vec![0_u8; 5])
            .send()
            .await;
        if let Ok(response) = response {
            return response;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .header(reqwest::header::ORIGIN, "https://ui.example")
        .body(vec![0_u8; 5])
        .send()
        .await
        .unwrap()
}

fn health_request(request_id: u64) -> WireRequest {
    WireRequest {
        request_id,
        api_key: String::new(),
        operation: Some(Operation::Health(HealthRequest {})),
    }
}

fn startup_message(user: &str, database: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(database.as_bytes());
    body.push(0);
    body.push(0);
    let mut message = Vec::with_capacity(8 + body.len());
    message.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
    message.extend_from_slice(&PROTOCOL_V3.to_be_bytes());
    message.extend_from_slice(&body);
    message
}

async fn read_pg_message<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header[1..5].try_into().expect("fixed header")) as usize;
    let payload_len = length
        .checked_sub(4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid pgwire length"))?;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok((header[0], payload))
}

fn test_pki() -> TestPki {
    let temp = tempfile::tempdir().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();

    let (server_pem, server_key_pem, initial_der) =
        leaf(&ca, "localhost", ExtendedKeyUsagePurpose::ServerAuth);
    let (replacement_pem, replacement_key_pem, replacement_der) =
        leaf(&ca, "localhost", ExtendedKeyUsagePurpose::ServerAuth);
    let (client_pem, client_key_pem, _) = leaf(&ca, "client", ExtendedKeyUsagePurpose::ClientAuth);

    let ca_path = write_file(temp.path(), "ca.pem", ca.pem().as_bytes());
    let server_cert = write_file(temp.path(), "server.pem", server_pem.as_bytes());
    let server_key = write_file(temp.path(), "server.key", server_key_pem.as_bytes());
    let replacement_cert = write_file(temp.path(), "replacement.pem", replacement_pem.as_bytes());
    let replacement_key = write_file(
        temp.path(),
        "replacement.key",
        replacement_key_pem.as_bytes(),
    );
    let client_cert = write_file(temp.path(), "client.pem", client_pem.as_bytes());
    let client_key = write_file(temp.path(), "client.key", client_key_pem.as_bytes());
    TestPki {
        _temp: temp,
        ca: ca_path,
        server_cert,
        server_key,
        replacement_cert,
        replacement_key,
        replacement_der,
        initial_der,
        client_cert,
        client_key,
    }
}

fn leaf(
    issuer: &rcgen::Issuer<'_, impl SigningKey>,
    name: &str,
    usage: ExtendedKeyUsagePurpose,
) -> (String, String, Vec<u8>) {
    let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap();
    (cert.pem(), key.serialize_pem(), cert.der().to_vec())
}

fn write_file(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, bytes).unwrap();
    path
}
