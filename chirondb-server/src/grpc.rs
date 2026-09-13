use std::{io, net::SocketAddr, path::PathBuf, time::Duration};

use axum::http::{
    HeaderName, HeaderValue, Method,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_stream::{StreamExt, wrappers::TcpListenerStream};
use tonic::{
    Request, Response, Status, service::interceptor::InterceptedService, transport::Server,
};
use tonic_web::GrpcWebLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::{
    Db, DistanceMetric, Filter, GaussError,
    auth::{AuthConfig, GrpcAuthInterceptor},
    model::{
        CollectionConfig, HybridFusion, HybridSearchRequest, MultiSearchRequest, PayloadType,
        Point, RecommendRequest, SearchRequest, SearchResponse, SparseVector,
    },
    rbac::{Action, Permission, authorize, authorize_graph},
    security_paths::StoragePolicy,
    segment::ColdObjectStoreConfig,
};

const MAX_GRPC_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

pub mod protocol {
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("gaussdb_descriptor");

    pub mod gaussdb {
        pub mod v1 {
            tonic::include_proto!("gaussdb.v1");
        }
    }

    pub mod chirondb {
        pub mod v1 {
            tonic::include_proto!("chirondb.v1");
        }
    }
}

pub use protocol::chirondb::v1 as chiron_pb;
pub use protocol::gaussdb::v1 as pb;

fn grpc_principal<T>(request: &Request<T>) -> Result<Permission, Status> {
    request
        .extensions()
        .get::<Permission>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("authenticated principal is missing"))
}

fn authorize_grpc(
    db: &Db,
    principal: &Permission,
    action: Action,
    collection: Option<&str>,
) -> Result<(), Status> {
    match authorize(principal, action, collection) {
        Ok(()) => {
            if action == Action::Read {
                db.audit_access_event(
                    "access",
                    "grpc_request",
                    "authorized",
                    collection,
                    &principal.id,
                    principal.tenant_id.as_deref(),
                    "grpc",
                    None,
                    None,
                )
                .map_err(status_from_error)?;
            }
            Ok(())
        }
        Err(_) => {
            db.audit_access_event(
                "authorization",
                "grpc_request",
                "denied",
                collection,
                &principal.id,
                principal.tenant_id.as_deref(),
                "grpc",
                None,
                Some("permission_denied"),
            )
            .map_err(status_from_error)?;
            Err(Status::permission_denied("operation is not permitted"))
        }
    }
}

fn authorize_graph_grpc(
    db: &Db,
    principal: &Permission,
    capability: crate::graph::GraphCapability,
    collection: &str,
) -> Result<(), Status> {
    match authorize_graph(principal, capability, collection) {
        Ok(()) => {
            if capability == crate::graph::GraphCapability::Read {
                db.audit_access_event(
                    "access",
                    "grpc_graph_request",
                    "authorized",
                    Some(collection),
                    &principal.id,
                    principal.tenant_id.as_deref(),
                    "grpc",
                    None,
                    None,
                )
                .map_err(status_from_error)?;
            }
            Ok(())
        }
        Err(error) => {
            db.audit_access_event(
                "authorization",
                "grpc_graph_authorize",
                "denied",
                Some(collection),
                &principal.id,
                principal.tenant_id.as_deref(),
                "grpc",
                None,
                Some("graph.permission_denied"),
            )
            .map_err(status_from_error)?;
            let message = format!(
                "{} is required for collection '{collection}': {error:?}",
                capability.as_str()
            );
            let details = serde_json::to_vec(&json!({
                "error": "forbidden",
                "code": "graph.permission_denied",
                "message": message,
            }))
            .unwrap_or_default();
            Err(Status::with_details(
                tonic::Code::PermissionDenied,
                message,
                details.into(),
            ))
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GrpcServerOptions {
    pub grpc_web_enabled: bool,
    pub cors_origins: Vec<String>,
    pub storage_policy: StoragePolicy,
}

pub async fn serve(db: Db, addr: SocketAddr) -> Result<(), tonic::transport::Error> {
    serve_with_auth(db, AuthConfig::disabled(), addr).await
}

pub async fn serve_with_auth(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
) -> Result<(), tonic::transport::Error> {
    serve_with_storage_policy(db, auth, addr, StoragePolicy::default()).await
}

async fn serve_with_storage_policy(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    storage_policy: StoragePolicy,
) -> Result<(), tonic::transport::Error> {
    let interceptor = GrpcAuthInterceptor::new(auth, db.clone());
    let chiron_service = InterceptedService::new(
        chiron_pb::chiron_db_server::ChironDbServer::new(ChironDbService {
            db: db.clone(),
            storage_policy: storage_policy.clone(),
        })
        .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        interceptor.clone(),
    );
    let service = InterceptedService::new(
        pb::gauss_db_server::GaussDbServer::new(ChironDbService { db, storage_policy })
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        interceptor.clone(),
    );
    let reflection = InterceptedService::new(reflection_service(), interceptor);
    Server::builder()
        .add_service(chiron_service)
        .add_service(service)
        .add_service(reflection)
        .serve(addr)
        .await
}

pub async fn serve_with_options(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    options: GrpcServerOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !options.grpc_web_enabled {
        return serve_with_storage_policy(db, auth, addr, options.storage_policy)
            .await
            .map_err(Into::into);
    }

    let cors = grpc_web_cors(&options.cors_origins)?;
    let interceptor = GrpcAuthInterceptor::new(auth, db.clone());
    let chiron_service = InterceptedService::new(
        chiron_pb::chiron_db_server::ChironDbServer::new(ChironDbService {
            db: db.clone(),
            storage_policy: options.storage_policy.clone(),
        })
        .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        interceptor.clone(),
    );
    let service = InterceptedService::new(
        pb::gauss_db_server::GaussDbServer::new(ChironDbService {
            db,
            storage_policy: options.storage_policy,
        })
        .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        interceptor.clone(),
    );
    let reflection = InterceptedService::new(reflection_service(), interceptor);
    Server::builder()
        .accept_http1(true)
        .layer(cors)
        .layer(GrpcWebLayer::new())
        .add_service(chiron_service)
        .add_service(service)
        .add_service(reflection)
        .serve(addr)
        .await?;
    Ok(())
}

pub async fn serve_tls_with_auth(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_tls_with_storage_policy(
        db,
        auth,
        addr,
        cert,
        key,
        client_ca,
        StoragePolicy::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn serve_tls_with_storage_policy(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
    storage_policy: StoragePolicy,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tls = crate::tls::ReloadingTlsConfig::load(cert, key, client_ca).await?;
    serve_tls_config_with_options(
        db,
        auth,
        addr,
        tls,
        GrpcServerOptions {
            storage_policy,
            ..Default::default()
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_tls_with_options(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
    options: GrpcServerOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tls = crate::tls::ReloadingTlsConfig::load(cert, key, client_ca).await?;
    serve_tls_config_with_options(db, auth, addr, tls, options).await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_tls_config_with_options(
    db: Db,
    auth: AuthConfig,
    addr: SocketAddr,
    tls: crate::tls::ReloadingTlsConfig,
    options: GrpcServerOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls.server_config());
    let incoming = TcpListenerStream::new(listener).then(move |socket| {
        let acceptor = acceptor.clone();
        async move {
            let socket = socket?;
            tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "gRPC TLS handshake timed out")
                })?
        }
    });
    let interceptor = GrpcAuthInterceptor::new(auth, db.clone());
    let chiron_service = InterceptedService::new(
        chiron_pb::chiron_db_server::ChironDbServer::new(ChironDbService {
            db: db.clone(),
            storage_policy: options.storage_policy.clone(),
        })
        .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        interceptor.clone(),
    );
    let service = InterceptedService::new(
        pb::gauss_db_server::GaussDbServer::new(ChironDbService {
            db,
            storage_policy: options.storage_policy,
        })
        .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        interceptor.clone(),
    );
    let reflection = InterceptedService::new(reflection_service(), interceptor);
    if options.grpc_web_enabled {
        let cors = grpc_web_cors(&options.cors_origins)?;
        Server::builder()
            .accept_http1(true)
            .layer(cors)
            .layer(GrpcWebLayer::new())
            .add_service(chiron_service)
            .add_service(service)
            .add_service(reflection)
            .serve_with_incoming(incoming)
            .await?;
    } else {
        Server::builder()
            .add_service(chiron_service)
            .add_service(service)
            .add_service(reflection)
            .serve_with_incoming(incoming)
            .await?;
    }
    Ok(())
}

fn grpc_web_cors(
    origins: &[String],
) -> Result<CorsLayer, Box<dyn std::error::Error + Send + Sync>> {
    if origins.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gRPC-Web requires at least one explicit CORS origin",
        )
        .into());
    }
    if origins.iter().any(|origin| origin == "*") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gRPC-Web does not allow wildcard CORS origins",
        )
        .into());
    }
    let origins = origins
        .iter()
        .map(|origin| origin.parse::<HeaderValue>())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::POST, Method::OPTIONS])
        .allow_headers([
            CONTENT_TYPE,
            AUTHORIZATION,
            HeaderName::from_static("x-chirondb-api-key"),
            HeaderName::from_static("x-gaussdb-api-key"),
            HeaderName::from_static("x-grpc-web"),
            HeaderName::from_static("x-user-agent"),
            HeaderName::from_static("grpc-timeout"),
        ])
        .expose_headers([
            HeaderName::from_static("grpc-status"),
            HeaderName::from_static("grpc-message"),
            HeaderName::from_static("grpc-status-details-bin"),
        ]))
}

fn reflection_service() -> tonic_reflection::server::v1::ServerReflectionServer<
    impl tonic_reflection::server::v1::ServerReflection,
> {
    tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(protocol::FILE_DESCRIPTOR_SET)
        .build_v1()
        .expect("embedded gRPC descriptor set must build reflection service")
}

#[derive(Debug)]
pub struct ChironDbService {
    db: Db,
    storage_policy: StoragePolicy,
}

#[tonic::async_trait]
impl pb::gauss_db_server::GaussDb for ChironDbService {
    async fn health(
        &self,
        request: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(&self.db, &principal, Action::Read, None)?;
        if !self.db.durability_ready() {
            return Err(Status::unavailable(
                "WAL durability is degraded or restore maintenance is active",
            ));
        }
        Ok(Response::new(pb::HealthResponse {
            status: "ok".to_string(),
            data_dir: String::new(),
            collections: 0,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }

    async fn create_collection(
        &self,
        request: Request<pb::CreateCollectionRequest>,
    ) -> Result<Response<pb::CollectionConfig>, Status> {
        let principal = grpc_principal(&request)?;
        let config = request
            .into_inner()
            .config
            .ok_or_else(|| Status::invalid_argument("config is required"))
            .and_then(collection_config_from_proto)?;
        authorize_grpc(&self.db, &principal, Action::Write, Some(&config.name))?;
        if let Some(limit) = principal.max_collections {
            let current = self
                .db
                .list_collections()
                .iter()
                .filter(|config| principal.allows_collection(&config.name))
                .count();
            if current >= limit {
                return Err(Status::permission_denied("collection quota exceeded"));
            }
        }
        self.db
            .create_collection(config)
            .map(collection_config_to_proto)
            .map(Response::new)
            .map_err(status_from_error)
    }

    async fn list_collections(
        &self,
        request: Request<pb::ListCollectionsRequest>,
    ) -> Result<Response<pb::ListCollectionsResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(&self.db, &principal, Action::Read, None)?;
        Ok(Response::new(pb::ListCollectionsResponse {
            collections: self
                .db
                .list_collections()
                .into_iter()
                .filter(|config| principal.allows_collection(&config.name))
                .map(collection_config_to_proto)
                .collect(),
        }))
    }

    async fn delete_collection(
        &self,
        request: Request<pb::DeleteCollectionRequest>,
    ) -> Result<Response<pb::DeleteCollectionResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Write,
            Some(&request.get_ref().collection),
        )?;
        self.db
            .delete_collection(&request.into_inner().collection)
            .map(|deleted| Response::new(pb::DeleteCollectionResponse { deleted }))
            .map_err(status_from_error)
    }

    async fn update_payload_schema(
        &self,
        request: Request<pb::UpdatePayloadSchemaRequest>,
    ) -> Result<Response<pb::CollectionConfig>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Write,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        let payload_schema = request
            .payload_schema
            .into_iter()
            .map(|(field, value_type)| {
                payload_type_from_proto(&value_type).map(|value_type| (field, value_type))
            })
            .collect::<Result<_, _>>()?;
        self.db
            .update_payload_schema(&request.collection, payload_schema)
            .map(collection_config_to_proto)
            .map(Response::new)
            .map_err(status_from_error)
    }

    async fn upsert(
        &self,
        request: Request<pb::UpsertRequest>,
    ) -> Result<Response<pb::UpsertResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Write,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        if request.points.len() > crate::MAX_UPSERT_POINTS_PER_REQUEST {
            return Err(Status::resource_exhausted(format!(
                "upsert contains {} points; maximum is {}",
                request.points.len(),
                crate::MAX_UPSERT_POINTS_PER_REQUEST
            )));
        }
        // no_wait=false (proto3 default) means wait=true (safe durable write)
        let wait = !request.no_wait;
        let points = request
            .points
            .into_iter()
            .map(point_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let scope = principal.tenant_scope(principal.id.clone());
        self.db
            .upsert_scoped(&request.collection, points, wait, &scope)
            .map(|total| {
                Response::new(pb::UpsertResponse {
                    total: total as u64,
                })
            })
            .map_err(status_from_error)
    }

    async fn delete(
        &self,
        request: Request<pb::DeleteRequest>,
    ) -> Result<Response<pb::DeleteResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Write,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        let scope = principal.tenant_scope(principal.id.clone());
        self.db
            .delete_scoped(&request.collection, &request.ids, &scope)
            .map(|deleted| {
                Response::new(pb::DeleteResponse {
                    deleted: deleted as u64,
                })
            })
            .map_err(status_from_error)
    }

    async fn get_points(
        &self,
        request: Request<pb::GetPointsRequest>,
    ) -> Result<Response<pb::GetPointsResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Read,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        let scope = principal.tenant_scope(principal.id.clone());
        self.db
            .get_points_scoped(&request.collection, &request.ids, &scope)
            .and_then(|points| {
                Ok(pb::GetPointsResponse {
                    points: points
                        .into_iter()
                        .map(point_to_proto)
                        .collect::<crate::Result<Vec<_>>>()?,
                })
            })
            .map(Response::new)
            .map_err(status_from_error)
    }

    async fn set_payload(
        &self,
        request: Request<pb::SetPayloadRequest>,
    ) -> Result<Response<pb::SetPayloadResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Write,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        let payload: serde_json::Value = if request.payload_json.is_empty() {
            serde_json::Value::Object(Default::default())
        } else {
            serde_json::from_str(&request.payload_json)
                .map_err(|e| Status::invalid_argument(format!("invalid payload_json: {e}")))?
        };
        let scope = principal.tenant_scope(principal.id.clone());
        self.db
            .set_payload_scoped(
                &request.collection,
                &request.id,
                payload,
                request.merge,
                &scope,
            )
            .and_then(|point| {
                Ok(pb::SetPayloadResponse {
                    point: Some(point_to_proto(point)?),
                })
            })
            .map(Response::new)
            .map_err(status_from_error)
    }

    async fn delete_by_filter(
        &self,
        request: Request<pb::DeleteByFilterRequest>,
    ) -> Result<Response<pb::DeleteByFilterResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Write,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        let filter: crate::Filter = serde_json::from_str(&request.filter_json)
            .map_err(|e| Status::invalid_argument(format!("invalid filter_json: {e}")))?;
        let scope = principal.tenant_scope(principal.id.clone());
        self.db
            .delete_by_filter_scoped(&request.collection, &filter, &scope)
            .map(|deleted| {
                Response::new(pb::DeleteByFilterResponse {
                    deleted: deleted as u64,
                })
            })
            .map_err(status_from_error)
    }

    async fn search(
        &self,
        request: Request<pb::SearchRequest>,
    ) -> Result<Response<pb::SearchResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Read,
            Some(&request.get_ref().collection),
        )?;
        if request
            .get_ref()
            .query
            .as_ref()
            .and_then(|query| query.graph_json.as_deref())
            .is_some_and(|graph| !graph.trim().is_empty())
        {
            authorize_graph_grpc(
                &self.db,
                &principal,
                crate::graph::GraphCapability::Read,
                &request.get_ref().collection,
            )?;
        }
        let request = request.into_inner();
        let query = request
            .query
            .ok_or_else(|| Status::invalid_argument("query is required"))?;
        let search_req = search_request_from_proto(query)?;
        let db = self.db.clone();
        let collection = request.collection;
        let scope = principal.tenant_scope(principal.id.clone());
        let response = crate::dispatch::dispatch_search(move || {
            db.search_scoped(&collection, search_req, &scope)
        })
        .map_err(status_from_error)?;
        search_response_to_proto(response)
            .map(Response::new)
            .map_err(status_from_error)
    }

    async fn text_hybrid_search(
        &self,
        request: Request<pb::TextHybridSearchRequest>,
    ) -> Result<Response<pb::SearchResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Read,
            Some(&request.get_ref().collection),
        )?;
        let scope = principal.tenant_scope(principal.id.clone());
        let request = request.into_inner();
        let query = text_hybrid_from_proto(&request)?;
        let db = self.db.clone();
        let response = tokio::task::spawn_blocking(move || {
            db.text_hybrid_search_scoped(&request.collection, query, &scope)
        })
        .await
        .map_err(|_| Status::internal("search worker failed"))?
        .map_err(status_from_error)?;
        search_response_to_proto(response)
            .map(Response::new)
            .map_err(status_from_error)
    }

    async fn hybrid_search(
        &self,
        request: Request<pb::HybridSearchRequest>,
    ) -> Result<Response<pb::SearchResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Read,
            Some(&request.get_ref().collection),
        )?;
        if request
            .get_ref()
            .graph_json
            .as_deref()
            .is_some_and(|graph| !graph.trim().is_empty())
        {
            authorize_graph_grpc(
                &self.db,
                &principal,
                crate::graph::GraphCapability::Read,
                &request.get_ref().collection,
            )?;
        }
        let request = request.into_inner();
        let hybrid_req = HybridSearchRequest {
            graph: graph_constraint_from_json(request.graph_json.as_deref())?,
            vector: request.use_dense_vector.then_some(request.vector),
            vector_name: optional_string(request.vector_name),
            sparse_vector: request.sparse_vector.map(sparse_vector_from_proto),
            k: k_or_default(request.k)?,
            filter: filter_from_json(&request.filter_json)?,
            budget_ms: request.budget_ms,
            fusion: fusion_from_proto(&request.fusion)?,
            dense_weight: weight_or_default(request.dense_weight),
            sparse_weight: weight_or_default(request.sparse_weight),
        };
        let db = self.db.clone();
        let collection = request.collection;
        let scope = principal.tenant_scope(principal.id.clone());
        let response = crate::dispatch::dispatch_search(move || {
            db.hybrid_search_scoped(&collection, hybrid_req, &scope)
        })
        .map_err(status_from_error)?;
        search_response_to_proto(response)
            .map(Response::new)
            .map_err(status_from_error)
    }

    async fn multi_search(
        &self,
        request: Request<pb::MultiSearchRequest>,
    ) -> Result<Response<pb::MultiSearchResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Read,
            Some(&request.get_ref().collection),
        )?;
        if request.get_ref().searches.iter().any(|query| {
            query
                .graph_json
                .as_deref()
                .is_some_and(|graph| !graph.trim().is_empty())
        }) {
            authorize_graph_grpc(
                &self.db,
                &principal,
                crate::graph::GraphCapability::Read,
                &request.get_ref().collection,
            )?;
        }
        let request = request.into_inner();
        let searches = request
            .searches
            .into_iter()
            .map(search_request_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let multi_req = MultiSearchRequest {
            searches,
            fusion: optional_fusion_from_proto(&request.fusion)?,
            fused_k: optional_usize_from_u64(request.fused_k, "fused_k")?,
            weights: request.weights,
        };
        let db = self.db.clone();
        let collection = request.collection;
        let scope = principal.tenant_scope(principal.id.clone());
        let response = crate::dispatch::dispatch_multi_search(move || {
            db.multi_search_scoped(&collection, multi_req, &scope)
        })
        .map_err(status_from_error)?;
        let pb_response = pb::MultiSearchResponse {
            results: response
                .results
                .into_iter()
                .map(search_response_to_proto)
                .collect::<crate::Result<Vec<_>>>()
                .map_err(status_from_error)?,
            fused: response
                .fused
                .map(search_response_to_proto)
                .transpose()
                .map_err(status_from_error)?,
        };
        Ok(Response::new(pb_response))
    }

    async fn recommend(
        &self,
        request: Request<pb::RecommendRequest>,
    ) -> Result<Response<pb::SearchResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Read,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        let recommend_req = RecommendRequest {
            positive: request.positive,
            negative: request.negative,
            vector_name: optional_string(request.vector_name),
            k: k_or_default(request.k)?,
            filter: filter_from_json(&request.filter_json)?,
            budget_ms: request.budget_ms,
        };
        let db = self.db.clone();
        let collection = request.collection;
        let scope = principal.tenant_scope(principal.id.clone());
        let response = crate::dispatch::dispatch_search(move || {
            db.recommend_scoped(&collection, recommend_req, &scope)
        })
        .map_err(status_from_error)?;
        search_response_to_proto(response)
            .map(Response::new)
            .map_err(status_from_error)
    }

    async fn count(
        &self,
        request: Request<pb::CountRequest>,
    ) -> Result<Response<pb::CountResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Read,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        let scope = principal.tenant_scope(principal.id.clone());
        self.db
            .count_scoped(
                &request.collection,
                filter_from_json(&request.filter_json)?,
                &scope,
            )
            .map(|response| {
                Response::new(pb::CountResponse {
                    count: response.count as u64,
                })
            })
            .map_err(status_from_error)
    }

    async fn scroll(
        &self,
        request: Request<pb::ScrollRequest>,
    ) -> Result<Response<pb::ScrollResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Read,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        let offset = optional_string(request.offset);
        let scope = principal.tenant_scope(principal.id.clone());
        self.db
            .scroll_scoped(
                &request.collection,
                offset.as_deref(),
                scroll_limit_or_default(request.limit)?,
                filter_from_json(&request.filter_json)?,
                &scope,
            )
            .and_then(|response| {
                Ok(pb::ScrollResponse {
                    points: response
                        .points
                        .into_iter()
                        .map(point_to_proto)
                        .collect::<crate::Result<Vec<_>>>()?,
                    next_offset: response.next_offset.unwrap_or_default(),
                })
            })
            .map(Response::new)
            .map_err(status_from_error)
    }

    async fn compact(
        &self,
        request: Request<pb::CompactRequest>,
    ) -> Result<Response<pb::CompactResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Write,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        self.db
            .compact_collection(&request.collection)
            .map(|response| {
                Response::new(pb::CompactResponse {
                    collection: response.collection,
                    segment_id: response.segment_id,
                    points: response.points as u64,
                    h2qg_cells: response.h2qg_cells as u64,
                    named_h2qg_fields: response.named_h2qg_fields as u64,
                    sparse_dimensions: response.sparse_dimensions as u64,
                    sparse_postings: response.sparse_postings as u64,
                    payload_fields: response.payload_fields as u64,
                    payload_values: response.payload_values as u64,
                    payload_postings: response.payload_postings as u64,
                    tombstones: response.tombstones as u64,
                    wal_archived_segments: response.wal_archived_segments as u64,
                    wal_archived_bytes: response.wal_archived_bytes,
                    wal_external_archived_segments: response.wal_external_archived_segments as u64,
                    wal_external_archived_bytes: response.wal_external_archived_bytes,
                    wal_archive_command_executed: response.wal_archive_command_executed,
                    wal_object_archived_segments: response.wal_object_archived_segments as u64,
                    wal_object_archived_bytes: response.wal_object_archived_bytes,
                    wal_auto_retained_archives: response.wal_auto_retained_archives as u64,
                    wal_auto_pruned_archives: response.wal_auto_pruned_archives as u64,
                    wal_auto_pruned_bytes: response.wal_auto_pruned_bytes,
                })
            })
            .map_err(status_from_error)
    }

    async fn tier_cold(
        &self,
        request: Request<pb::ColdTierRequest>,
    ) -> Result<Response<pb::ColdTierResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Write,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        self.db
            .tier_collection_to_cold(&request.collection)
            .map(|response| {
                Response::new(pb::ColdTierResponse {
                    collection: response.collection,
                    segments: response.segments as u64,
                    files: response.files as u64,
                    bytes: response.bytes,
                    points: response.points as u64,
                })
            })
            .map_err(status_from_error)
    }

    async fn prune_wal_archive(
        &self,
        request: Request<pb::PruneWalArchiveRequest>,
    ) -> Result<Response<pb::WalArchivePruneResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(
            &self.db,
            &principal,
            Action::Write,
            Some(&request.get_ref().collection),
        )?;
        let request = request.into_inner();
        self.db
            .prune_wal_archive(
                &request.collection,
                usize_from_u64(request.retain_last, "retain_last")?,
            )
            .map(|response| {
                Response::new(pb::WalArchivePruneResponse {
                    collection: response.collection,
                    retained_archives: response.retained_archives as u64,
                    pruned_archives: response.pruned_archives as u64,
                    pruned_bytes: response.pruned_bytes,
                })
            })
            .map_err(status_from_error)
    }

    async fn snapshot(
        &self,
        request: Request<pb::SnapshotRequest>,
    ) -> Result<Response<pb::StatusResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(&self.db, &principal, Action::Admin, None)?;
        let path = self
            .storage_policy
            .resolve_path(request.into_inner().path)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        self.db
            .snapshot(path)
            .map(|()| {
                Response::new(pb::StatusResponse {
                    status: "snapshotted".to_string(),
                })
            })
            .map_err(status_from_error)
    }

    async fn restore(
        &self,
        request: Request<pb::RestoreRequest>,
    ) -> Result<Response<pb::StatusResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(&self.db, &principal, Action::Admin, None)?;
        let request = request.into_inner();
        let path = self
            .storage_policy
            .resolve_path(&request.path)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let wal_restore_archive_dir = (!request.wal_restore_archive_dir.is_empty())
            .then(|| {
                self.storage_policy
                    .resolve_path(&request.wal_restore_archive_dir)
                    .map_err(|error| Status::invalid_argument(error.to_string()))
            })
            .transpose()?;
        let wal_restore_object_store = restore_object_store_config(
            &self.storage_policy,
            &request.wal_restore_object_store_dir,
            &request.wal_restore_object_store_url,
        )?;
        self.db
            .restore_to_wal_targets_with_archive_sources(
                path,
                &request.target_wal_lsns,
                &request.target_wal_unix_ms,
                wal_restore_archive_dir.as_deref(),
                wal_restore_object_store.as_ref(),
            )
            .map(|()| {
                Response::new(pb::StatusResponse {
                    status: "restored".to_string(),
                })
            })
            .map_err(status_from_error)
    }

    async fn shard_move(
        &self,
        request: Request<pb::ShardMoveRequest>,
    ) -> Result<Response<pb::StatusResponse>, Status> {
        let principal = grpc_principal(&request)?;
        authorize_grpc(&self.db, &principal, Action::Admin, None)?;
        self.db
            .audit_admin_event(
                "shard_move",
                serde_json::json!({
                    "mode": "single_node_noop",
                    "transport": "grpc",
                }),
            )
            .map_err(status_from_error)?;
        Ok(Response::new(pb::StatusResponse {
            status: "accepted_single_node_noop".to_string(),
        }))
    }
}

impl ChironDbService {
    fn set_graph_lifecycle(
        &self,
        request: Request<chiron_pb::GraphLifecycleRequest>,
        enabled: bool,
    ) -> Result<Response<chiron_pb::GraphLifecycleResponse>, Status> {
        let principal = grpc_principal(&request)?;
        let request = request.into_inner();
        authorize_graph_grpc(
            &self.db,
            &principal,
            crate::graph::GraphCapability::Admin,
            &request.collection,
        )?;
        let scope = principal.tenant_scope(principal.id.clone());
        self.db
            .set_graph_lifecycle_scoped(&request.collection, enabled, !request.no_wait, &scope)
            .map(graph_lifecycle_to_proto)
            .map(Response::new)
            .map_err(status_from_error)
    }

    fn finish_deferred_graph_session(
        &self,
        request: Request<chiron_pb::GraphDeferredSessionRequest>,
        commit: bool,
    ) -> Result<Response<chiron_pb::GraphDeferredSessionResponse>, Status> {
        let principal = grpc_principal(&request)?;
        let request = request.into_inner();
        authorize_graph_grpc(
            &self.db,
            &principal,
            crate::graph::GraphCapability::Write,
            &request.collection,
        )?;
        let session_id = request
            .session_id
            .ok_or_else(|| Status::invalid_argument("session_id is required"))?;
        let session_id = crate::graph::GraphDeferredSessionId::from_encoded(session_id);
        let scope = principal.tenant_scope(principal.id.clone());
        let result = if commit {
            self.db.commit_deferred_graph_session_scoped(
                &request.collection,
                &session_id,
                !request.no_wait,
                &scope,
            )
        } else {
            self.db.abort_deferred_graph_session_scoped(
                &request.collection,
                &session_id,
                !request.no_wait,
                &scope,
            )
        };
        result
            .map(graph_deferred_session_to_proto)
            .map(Response::new)
            .map_err(status_from_error)
    }
}

fn graph_lifecycle_to_proto(
    result: crate::graph::GraphLifecycleResult,
) -> chiron_pb::GraphLifecycleResponse {
    chiron_pb::GraphLifecycleResponse {
        enabled: result.enabled,
        graph_epoch: result.graph_epoch.map(crate::graph::GraphEpoch::raw),
        operation_lsn: result.operation_lsn,
        durable: result.durable,
        transitioned: result.transitioned,
        backfill_in_progress: result.backfill_in_progress,
    }
}

fn graph_receipt_to_proto(
    receipt: crate::graph::GraphMutationReceipt,
) -> chiron_pb::GraphMutationReceipt {
    chiron_pb::GraphMutationReceipt {
        graph_epoch: receipt.graph_epoch.raw(),
        operation_lsn: receipt.operation_lsn,
        durable: receipt.durable,
        replayed: receipt.replayed,
    }
}

fn graph_edge_type_to_proto(edge_type: crate::graph::GraphEdgeType) -> chiron_pb::GraphEdgeType {
    chiron_pb::GraphEdgeType {
        name: edge_type.name,
        weight_property: edge_type.weight_property,
    }
}

fn graph_relate_request_from_proto(
    request: chiron_pb::GraphRelateRequest,
) -> Result<crate::graph::RelateRequest, Status> {
    let scope = match request.scope.as_str() {
        "" | "local" => crate::graph::GraphRelationScope::Local,
        "admin_cross_tenant" => crate::graph::GraphRelationScope::AdminCrossTenant,
        value => {
            return Err(Status::invalid_argument(format!(
                "unknown graph relation scope: {value}"
            )));
        }
    };
    Ok(crate::graph::RelateRequest {
        source_point_id: request.source_point_id,
        target_point_id: request.target_point_id,
        edge_type: request.edge_type,
        properties: json_from_optional_str(&request.properties_json)?,
        scope,
        idempotency_key: request.idempotency_key,
    })
}

fn graph_relate_response_to_proto(
    result: crate::graph::RelateResult,
) -> chiron_pb::GraphRelateResponse {
    chiron_pb::GraphRelateResponse {
        edge_id: result.edge_id.into_encoded(),
        receipt: Some(graph_receipt_to_proto(result.receipt)),
    }
}

fn graph_edge_mode_from_proto(raw: &str) -> Result<crate::graph::EdgePropertyMode, Status> {
    match raw {
        "merge" => Ok(crate::graph::EdgePropertyMode::Merge),
        "replace" => Ok(crate::graph::EdgePropertyMode::Replace),
        value => Err(Status::invalid_argument(format!(
            "unknown edge property mode: {value}"
        ))),
    }
}

fn graph_deferred_session_to_proto(
    result: crate::graph::GraphDeferredSessionResult,
) -> chiron_pb::GraphDeferredSessionResponse {
    chiron_pb::GraphDeferredSessionResponse {
        session_id: result.session_id.to_string(),
        state: match result.state {
            crate::graph::GraphDeferredSessionState::Open => "open",
            crate::graph::GraphDeferredSessionState::Committed => "committed",
            crate::graph::GraphDeferredSessionState::Aborted => "aborted",
        }
        .to_string(),
        receipt: Some(graph_receipt_to_proto(result.receipt)),
    }
}

fn graph_enum_to_string(value: &impl serde::Serialize) -> Result<String, Status> {
    serde_json::to_value(value)
        .map_err(|error| Status::internal(error.to_string()))?
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| Status::internal("graph enum did not serialize as a string"))
}

macro_rules! impl_chiron_service {
    ($(($name:ident, $request:ty, $response:ty)),+ $(,)?) => {
        #[tonic::async_trait]
        impl chiron_pb::chiron_db_server::ChironDb for ChironDbService {
            $(
                async fn $name(
                    &self,
                    request: Request<$request>,
                ) -> Result<Response<$response>, Status> {
                    <Self as pb::gauss_db_server::GaussDb>::$name(self, request).await
                }
            )+

            async fn enable_graph(
                &self,
                request: Request<chiron_pb::GraphLifecycleRequest>,
            ) -> Result<Response<chiron_pb::GraphLifecycleResponse>, Status> {
                self.set_graph_lifecycle(request, true)
            }

            async fn drop_graph(
                &self,
                request: Request<chiron_pb::GraphLifecycleRequest>,
            ) -> Result<Response<chiron_pb::GraphLifecycleResponse>, Status> {
                self.set_graph_lifecycle(request, false)
            }

            async fn list_edge_types(
                &self,
                request: Request<chiron_pb::ListEdgeTypesRequest>,
            ) -> Result<Response<chiron_pb::ListEdgeTypesResponse>, Status> {
                let principal = grpc_principal(&request)?;
                let request = request.into_inner();
                authorize_graph_grpc(
                    &self.db,
                    &principal,
                    crate::graph::GraphCapability::Read,
                    &request.collection,
                )?;
                let scope = principal.tenant_scope(principal.id.clone());
                self.db
                    .list_edge_types_scoped(&request.collection, &scope)
                    .map(|edge_types| chiron_pb::ListEdgeTypesResponse {
                        edge_types: edge_types
                            .into_iter()
                            .map(graph_edge_type_to_proto)
                            .collect(),
                    })
                    .map(Response::new)
                    .map_err(status_from_error)
            }

            async fn configure_edge_type(
                &self,
                request: Request<chiron_pb::ConfigureEdgeTypeRequest>,
            ) -> Result<Response<chiron_pb::ConfigureEdgeTypeResponse>, Status> {
                let principal = grpc_principal(&request)?;
                let request = request.into_inner();
                authorize_graph_grpc(
                    &self.db,
                    &principal,
                    crate::graph::GraphCapability::TypeConfigure,
                    &request.collection,
                )?;
                let scope = principal.tenant_scope(principal.id.clone());
                self.db
                    .configure_edge_type_scoped(
                        &request.collection,
                        crate::graph::ConfigureEdgeTypeRequest {
                            name: request.name,
                            weight_property: request.weight_property,
                        },
                        !request.no_wait,
                        &scope,
                    )
                    .map(|result| chiron_pb::ConfigureEdgeTypeResponse {
                        edge_type: Some(graph_edge_type_to_proto(result.edge_type)),
                        receipt: Some(graph_receipt_to_proto(result.receipt)),
                        changed: result.changed,
                    })
                    .map(Response::new)
                    .map_err(status_from_error)
            }

            async fn relate(
                &self,
                request: Request<chiron_pb::GraphRelateRequest>,
            ) -> Result<Response<chiron_pb::GraphRelateResponse>, Status> {
                let principal = grpc_principal(&request)?;
                let request = request.into_inner();
                authorize_graph_grpc(
                    &self.db,
                    &principal,
                    crate::graph::GraphCapability::Write,
                    &request.collection,
                )?;
                let wait = !request.no_wait;
                let collection = request.collection.clone();
                let scope = principal.tenant_scope(principal.id.clone());
                self.db
                    .relate_scoped(
                        &collection,
                        graph_relate_request_from_proto(request)?,
                        wait,
                        &scope,
                    )
                    .map(graph_relate_response_to_proto)
                    .map(Response::new)
                    .map_err(status_from_error)
            }

            async fn unrelate(
                &self,
                request: Request<chiron_pb::GraphUnrelateRequest>,
            ) -> Result<Response<chiron_pb::GraphUnrelateResponse>, Status> {
                let principal = grpc_principal(&request)?;
                let request = request.into_inner();
                authorize_graph_grpc(
                    &self.db,
                    &principal,
                    crate::graph::GraphCapability::Write,
                    &request.collection,
                )?;
                let scope = principal.tenant_scope(principal.id.clone());
                let edge_id = crate::graph::EdgeToken::from_encoded(request.edge_id);
                self.db
                    .unrelate_many_scoped(
                        &request.collection,
                        &[edge_id],
                        !request.no_wait,
                        &scope,
                    )
                    .map(|(receipt, deleted)| chiron_pb::GraphUnrelateResponse {
                        deleted: deleted as u64,
                        receipt: Some(graph_receipt_to_proto(receipt)),
                    })
                    .map(Response::new)
                    .map_err(status_from_error)
            }

            async fn update_edge(
                &self,
                request: Request<chiron_pb::GraphUpdateEdgeRequest>,
            ) -> Result<Response<chiron_pb::GraphMutationReceipt>, Status> {
                let principal = grpc_principal(&request)?;
                let request = request.into_inner();
                authorize_graph_grpc(
                    &self.db,
                    &principal,
                    crate::graph::GraphCapability::Write,
                    &request.collection,
                )?;
                let scope = principal.tenant_scope(principal.id.clone());
                let edge_id = crate::graph::EdgeToken::from_encoded(request.edge_id);
                let mode = graph_edge_mode_from_proto(&request.mode)?;
                let properties = json_from_optional_str(&request.properties_json)?;
                self.db
                    .update_edge_scoped(
                        &request.collection,
                        &edge_id,
                        crate::graph::UpdateEdgeRequest { mode, properties },
                        !request.no_wait,
                        &scope,
                    )
                    .map(graph_receipt_to_proto)
                    .map(Response::new)
                    .map_err(status_from_error)
            }

            async fn traverse(
                &self,
                request: Request<chiron_pb::GraphTraverseRequest>,
            ) -> Result<Response<chiron_pb::GraphTraverseResponse>, Status> {
                let principal = grpc_principal(&request)?;
                let request = request.into_inner();
                authorize_graph_grpc(
                    &self.db,
                    &principal,
                    crate::graph::GraphCapability::Read,
                    &request.collection,
                )?;
                let traversal: crate::graph::GraphTraversalQueryRequest =
                    serde_json::from_str(&request.request_json).map_err(|error| {
                        Status::invalid_argument(format!("invalid request_json: {error}"))
                    })?;
                let scope = principal.tenant_scope(principal.id.clone());
                let result = self
                    .db
                    .traverse_query_scoped(&request.collection, traversal, &scope)
                    .map_err(status_from_error)?;
                let result_json = serde_json::to_string(&result)
                    .map_err(|error| Status::internal(error.to_string()))?;
                let stats_json = serde_json::to_string(&result.stats)
                    .map_err(|error| Status::internal(error.to_string()))?;
                let truncation = result
                    .truncation
                    .as_ref()
                    .map(graph_enum_to_string)
                    .transpose()?;
                let warnings = result
                    .warnings
                    .iter()
                    .map(graph_enum_to_string)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Response::new(chiron_pb::GraphTraverseResponse {
                    result_json,
                    graph_epoch: result.graph_epoch.raw(),
                    stats_json,
                    truncation,
                    warnings,
                }))
            }

            async fn open_deferred_graph_session(
                &self,
                request: Request<chiron_pb::GraphDeferredSessionRequest>,
            ) -> Result<Response<chiron_pb::GraphDeferredSessionResponse>, Status> {
                let principal = grpc_principal(&request)?;
                let request = request.into_inner();
                authorize_graph_grpc(
                    &self.db,
                    &principal,
                    crate::graph::GraphCapability::Write,
                    &request.collection,
                )?;
                if request.session_id.is_some() {
                    return Err(Status::invalid_argument(
                        "session_id must be absent when opening a deferred graph session",
                    ));
                }
                let scope = principal.tenant_scope(principal.id.clone());
                self.db
                    .open_deferred_graph_session_scoped(
                        &request.collection,
                        !request.no_wait,
                        &scope,
                    )
                    .map(graph_deferred_session_to_proto)
                    .map(Response::new)
                    .map_err(status_from_error)
            }

            async fn deferred_upsert(
                &self,
                request: Request<chiron_pb::GraphDeferredUpsertRequest>,
            ) -> Result<Response<chiron_pb::GraphDeferredUpsertResponse>, Status> {
                let principal = grpc_principal(&request)?;
                let request = request.into_inner();
                authorize_graph_grpc(
                    &self.db,
                    &principal,
                    crate::graph::GraphCapability::Write,
                    &request.collection,
                )?;
                if request.points.len() > crate::MAX_UPSERT_POINTS_PER_REQUEST {
                    return Err(Status::resource_exhausted(format!(
                        "upsert contains {} points; maximum is {}",
                        request.points.len(),
                        crate::MAX_UPSERT_POINTS_PER_REQUEST
                    )));
                }
                let points = request
                    .points
                    .into_iter()
                    .map(point_from_proto)
                    .collect::<Result<Vec<_>, _>>()?;
                let session_id =
                    crate::graph::GraphDeferredSessionId::from_encoded(request.session_id);
                let scope = principal.tenant_scope(principal.id.clone());
                self.db
                    .upsert_deferred_scoped(
                        &request.collection,
                        &session_id,
                        points,
                        !request.no_wait,
                        &scope,
                    )
                    .map(|result| chiron_pb::GraphDeferredUpsertResponse {
                        total_points: result.total_points as u64,
                        bound_endpoints: result.bound_endpoints as u64,
                        receipt: Some(graph_receipt_to_proto(result.receipt)),
                    })
                    .map(Response::new)
                    .map_err(status_from_error)
            }

            async fn deferred_relate(
                &self,
                request: Request<chiron_pb::GraphDeferredRelateRequest>,
            ) -> Result<Response<chiron_pb::GraphRelateResponse>, Status> {
                let principal = grpc_principal(&request)?;
                let request = request.into_inner();
                authorize_graph_grpc(
                    &self.db,
                    &principal,
                    crate::graph::GraphCapability::Write,
                    &request.collection,
                )?;
                let relate = request
                    .relate
                    .ok_or_else(|| Status::invalid_argument("relate is required"))?;
                if !relate.collection.is_empty() && relate.collection != request.collection {
                    return Err(Status::invalid_argument(
                        "relate.collection must be empty or match collection",
                    ));
                }
                let wait = !relate.no_wait;
                let session_id =
                    crate::graph::GraphDeferredSessionId::from_encoded(request.session_id);
                let scope = principal.tenant_scope(principal.id.clone());
                self.db
                    .relate_deferred_scoped(
                        &request.collection,
                        &session_id,
                        graph_relate_request_from_proto(relate)?,
                        wait,
                        &scope,
                    )
                    .map(graph_relate_response_to_proto)
                    .map(Response::new)
                    .map_err(status_from_error)
            }

            async fn commit_deferred_graph_session(
                &self,
                request: Request<chiron_pb::GraphDeferredSessionRequest>,
            ) -> Result<Response<chiron_pb::GraphDeferredSessionResponse>, Status> {
                self.finish_deferred_graph_session(request, true)
            }

            async fn abort_deferred_graph_session(
                &self,
                request: Request<chiron_pb::GraphDeferredSessionRequest>,
            ) -> Result<Response<chiron_pb::GraphDeferredSessionResponse>, Status> {
                self.finish_deferred_graph_session(request, false)
            }

            /// ChironQL over gRPC.
            ///
            /// Hand-written rather than forwarded, because this rpc exists only
            /// on `chirondb.v1`: the legacy `gaussdb.v1.GaussDb` service is
            /// frozen at the surface it shipped with. It goes through the same
            /// `chironql_exec::execute` entry point as the console and HTTP.
            async fn execute_query(
                &self,
                request: Request<chiron_pb::ChironQlRequest>,
            ) -> Result<Response<chiron_pb::ChironQlResponse>, Status> {
                // The auth interceptor put the resolved principal here. When
                // RBAC is not configured there is no principal to scope by, so
                // the request is refused under enforcement rather than served
                // unscoped — the same fail-closed rule the core applies.
                let permission = request.extensions().get::<crate::rbac::Permission>().cloned();
                let request = request.into_inner();
                let db = self.db.clone();
                let mut session = crate::chironql_exec::Session {
                    collection: request.collection.clone(),
                    ..crate::chironql_exec::Session::default()
                };
                let mut ctx = crate::chironql_exec::ExecContext {
                    db: &db,
                    session: &mut session,
                    // gRPC auth is enforced by the interceptor before the
                    // request reaches here; it does not carry a per-key role
                    // the way the HTTP layer does, so the caller is treated as
                    // it is for every other rpc on this service.
                    role: permission
                        .as_ref()
                        .map(|perm| perm.role)
                        .unwrap_or(crate::rbac::Role::Admin),
                    allowed_collections: permission
                        .as_ref()
                        .filter(|perm| perm.is_restricted())
                        .map(|perm| perm.allowed_collections().into_iter().collect()),
                    want_trace: request.trace,
                    confirm: request.confirm,
                    tenant: match &permission {
                        Some(perm) => perm.tenant_scope(
                            perm.id.clone(),
                        ),
                        // No principal at all: act as an untenanted caller,
                        // which reads nothing once enforcement is on.
                        None => chirondb_core::tenant::TenantScope::untenanted("grpc")
                            .with_graph_capabilities([
                                chirondb_types::graph::GraphCapability::Read,
                                chirondb_types::graph::GraphCapability::Write,
                                chirondb_types::graph::GraphCapability::Admin,
                                chirondb_types::graph::GraphCapability::TypeConfigure,
                            ]),
                    },
                };

                match crate::chironql_exec::execute(&mut ctx, &request.query) {
                    Ok(response) => Ok(Response::new(chiron_pb::ChironQlResponse {
                        kind: match response.kind {
                            chirondb_types::chironql::ChironQlKind::Rows => "rows",
                            chirondb_types::chironql::ChironQlKind::Affected => "affected",
                            chirondb_types::chironql::ChironQlKind::Empty => "empty",
                        }
                        .to_string(),
                        columns: response.columns,
                        rows_json: response
                            .rows
                            .iter()
                            .map(|row| row.to_string())
                            .collect(),
                        stats_json: serde_json::to_string(&response.stats)
                            .unwrap_or_else(|_| "{}".to_string()),
                        next: response.next,
                        query_id: response.query_id,
                        trace_json: response
                            .trace
                            .as_ref()
                            .and_then(|trace| serde_json::to_string(trace).ok()),
                    })),
                    Err(error) => Err(chironql_status(error)),
                }
            }
        }
    };
}

/// Maps a ChironQL failure onto a gRPC status, carrying the full error - code,
/// hint, caret position and the trace up to the failing stage - in the status
/// details so a client loses nothing by using gRPC instead of HTTP.
pub(crate) fn chironql_status(error: chirondb_types::chironql::ChironQlError) -> Status {
    use tonic::Code;

    let code = match error.code.as_str() {
        "chironql.permission_denied" => Code::PermissionDenied,
        "chironql.collection_not_found"
        | "chironql.collection_forbidden"
        | "chironql.point_not_found"
        | "chironql.vector_not_found"
        | "graph.endpoint_not_found"
        | "graph.edge_not_found"
        | "graph.type_unknown"
        | "graph.deferred_session_not_found" => Code::NotFound,
        "chironql.confirmation_required" => Code::FailedPrecondition,
        "chironql.not_implemented" => Code::Unimplemented,
        "chironql.resource_exhausted" | "graph.overloaded" => Code::ResourceExhausted,
        "graph.cancelled" => Code::Cancelled,
        "graph.slo_unavailable" | "chironql.storage_unavailable" => Code::Unavailable,
        "chironql.storage_corruption" | "chironql.io_error" | "chironql.engine_error" => {
            Code::Internal
        }
        _ => Code::InvalidArgument,
    };

    let details = serde_json::to_vec(&error).unwrap_or_default();
    Status::with_details(code, error.error.clone(), details.into())
}

impl_chiron_service!(
    (health, pb::HealthRequest, pb::HealthResponse),
    (
        create_collection,
        pb::CreateCollectionRequest,
        pb::CollectionConfig
    ),
    (
        list_collections,
        pb::ListCollectionsRequest,
        pb::ListCollectionsResponse
    ),
    (
        delete_collection,
        pb::DeleteCollectionRequest,
        pb::DeleteCollectionResponse
    ),
    (
        update_payload_schema,
        pb::UpdatePayloadSchemaRequest,
        pb::CollectionConfig
    ),
    (upsert, pb::UpsertRequest, pb::UpsertResponse),
    (delete, pb::DeleteRequest, pb::DeleteResponse),
    (get_points, pb::GetPointsRequest, pb::GetPointsResponse),
    (set_payload, pb::SetPayloadRequest, pb::SetPayloadResponse),
    (
        delete_by_filter,
        pb::DeleteByFilterRequest,
        pb::DeleteByFilterResponse
    ),
    (search, pb::SearchRequest, pb::SearchResponse),
    (hybrid_search, pb::HybridSearchRequest, pb::SearchResponse),
    (
        text_hybrid_search,
        pb::TextHybridSearchRequest,
        pb::SearchResponse
    ),
    (
        multi_search,
        pb::MultiSearchRequest,
        pb::MultiSearchResponse
    ),
    (recommend, pb::RecommendRequest, pb::SearchResponse),
    (count, pb::CountRequest, pb::CountResponse),
    (scroll, pb::ScrollRequest, pb::ScrollResponse),
    (compact, pb::CompactRequest, pb::CompactResponse),
    (tier_cold, pb::ColdTierRequest, pb::ColdTierResponse),
    (
        prune_wal_archive,
        pb::PruneWalArchiveRequest,
        pb::WalArchivePruneResponse
    ),
    (snapshot, pb::SnapshotRequest, pb::StatusResponse),
    (restore, pb::RestoreRequest, pb::StatusResponse),
    (shard_move, pb::ShardMoveRequest, pb::StatusResponse),
);

pub(crate) fn restore_object_store_config(
    storage_policy: &StoragePolicy,
    store_dir: &str,
    store_url: &str,
) -> Result<Option<ColdObjectStoreConfig>, Status> {
    let store_dir = (!store_dir.is_empty()).then_some(store_dir);
    let store_url = (!store_url.is_empty()).then_some(store_url);
    if store_dir.is_some() && store_url.is_some() {
        return Err(Status::invalid_argument(
            "set only one of wal_restore_object_store_dir or wal_restore_object_store_url",
        ));
    }
    if let Some(url) = store_url {
        let url = storage_policy
            .resolve_url(url)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        return Ok(Some(ColdObjectStoreConfig::Url(url)));
    }
    store_dir
        .map(|dir| {
            storage_policy
                .resolve_path(dir)
                .map(ColdObjectStoreConfig::LocalDir)
                .map_err(|error| Status::invalid_argument(error.to_string()))
        })
        .transpose()
}

pub(crate) fn collection_config_from_proto(
    config: pb::CollectionConfig,
) -> Result<CollectionConfig, Status> {
    let metric = match config.metric.as_str() {
        "" | "cosine" => DistanceMetric::Cosine,
        "l2" => DistanceMetric::L2,
        "dot" => DistanceMetric::Dot,
        value => return Err(Status::invalid_argument(format!("unknown metric: {value}"))),
    };
    Ok(CollectionConfig {
        name: config.name,
        vector_dim: usize_from_u64(config.vector_dim, "vector_dim")?,
        metric,
        shards: config.shards,
        replicas: config.replicas,
        quantization: if config.quantization.is_empty() {
            None
        } else {
            Some(config.quantization)
        },
        payload_schema: config
            .payload_schema
            .into_iter()
            .map(|(field, value_type)| {
                payload_type_from_proto(&value_type).map(|value_type| (field, value_type))
            })
            .collect::<Result<_, _>>()?,
        named_vector_dims: Default::default(),
        hnsw_m: config.hnsw_m,
        hnsw_ef_construction: config.hnsw_ef_construction,
        hnsw_ef_search: config.hnsw_ef_search,
        recall_sla: config.recall_sla,
        index_kind: None,
        streamer_max_bytes: usize_from_u64(config.streamer_max_bytes, "streamer_max_bytes")?,
    })
}

pub(crate) fn collection_config_to_proto(config: CollectionConfig) -> pb::CollectionConfig {
    pb::CollectionConfig {
        name: config.name,
        vector_dim: config.vector_dim as u64,
        metric: match config.metric {
            DistanceMetric::L2 => "l2",
            DistanceMetric::Cosine => "cosine",
            DistanceMetric::Dot => "dot",
        }
        .to_string(),
        shards: config.shards,
        replicas: config.replicas,
        quantization: config.quantization.unwrap_or_default(),
        payload_schema: config
            .payload_schema
            .into_iter()
            .map(|(field, value_type)| (field, value_type.to_string()))
            .collect(),
        hnsw_m: config.hnsw_m,
        hnsw_ef_construction: config.hnsw_ef_construction,
        hnsw_ef_search: config.hnsw_ef_search,
        recall_sla: config.recall_sla,
        streamer_max_bytes: config.streamer_max_bytes as u64,
    }
}

pub(crate) fn payload_type_from_proto(value: &str) -> Result<PayloadType, Status> {
    match value {
        "string" => Ok(PayloadType::String),
        "number" => Ok(PayloadType::Number),
        "bool" => Ok(PayloadType::Bool),
        "object" => Ok(PayloadType::Object),
        "array" => Ok(PayloadType::Array),
        "optional_string" | "string?" => Ok(PayloadType::OptionalString),
        "optional_number" | "number?" => Ok(PayloadType::OptionalNumber),
        "optional_bool" | "bool?" => Ok(PayloadType::OptionalBool),
        "optional_object" | "object?" => Ok(PayloadType::OptionalObject),
        "optional_array" | "array?" => Ok(PayloadType::OptionalArray),
        "nullable_string" => Ok(PayloadType::NullableString),
        "nullable_number" => Ok(PayloadType::NullableNumber),
        "nullable_bool" => Ok(PayloadType::NullableBool),
        "nullable_object" => Ok(PayloadType::NullableObject),
        "nullable_array" => Ok(PayloadType::NullableArray),
        value => Err(Status::invalid_argument(format!(
            "unknown payload type: {value}"
        ))),
    }
}

pub(crate) fn point_from_proto(point: pb::Point) -> Result<Point, Status> {
    Ok(Point {
        id: point.id,
        vector: point.vector,
        vectors: point
            .vectors
            .into_iter()
            .map(|(name, vector)| (name, vector.values))
            .collect(),
        sparse_vector: point.sparse_vector.map(sparse_vector_from_proto),
        payload: json_from_optional_str(&point.payload_json)?,
    })
}

pub(crate) fn point_to_proto(point: Point) -> crate::Result<pb::Point> {
    Ok(pb::Point {
        id: point.id,
        vector: point.vector,
        payload_json: serde_json::to_string(&point.payload)?,
        sparse_vector: point.sparse_vector.map(sparse_vector_to_proto),
        vectors: point
            .vectors
            .into_iter()
            .map(|(name, values)| (name, pb::DenseVector { values }))
            .collect(),
    })
}

pub(crate) fn sparse_vector_from_proto(sparse_vector: pb::SparseVector) -> SparseVector {
    SparseVector {
        indices: sparse_vector.indices,
        values: sparse_vector.values,
    }
}

pub(crate) fn sparse_vector_to_proto(sparse_vector: SparseVector) -> pb::SparseVector {
    pb::SparseVector {
        indices: sparse_vector.indices,
        values: sparse_vector.values,
    }
}

pub(crate) fn search_request_from_proto(query: pb::SearchQuery) -> Result<SearchRequest, Status> {
    Ok(SearchRequest {
        graph: graph_constraint_from_json(query.graph_json.as_deref())?,
        vector: query.vector,
        vector_name: optional_string(query.vector_name),
        k: k_or_default(query.k)?,
        filter: filter_from_json(&query.filter_json)?,
        budget_ms: query.budget_ms,
        consistency: None,
        ef_search: query.ef_search,
        recall_target: query.recall_target,
        with_payload: None,
    })
}

pub(crate) fn search_response_to_proto(
    response: SearchResponse,
) -> crate::Result<pb::SearchResponse> {
    let graph_json = response
        .graph
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    Ok(pb::SearchResponse {
        hits: response
            .hits
            .into_iter()
            .map(|hit| {
                Ok(pb::SearchHit {
                    id: hit.id,
                    score: hit.score,
                    payload_json: serde_json::to_string(&hit.payload)?,
                })
            })
            .collect::<crate::Result<Vec<_>>>()?,
        degraded: response.degraded,
        searched: response.searched as u64,
        elapsed_ms: response.elapsed_ms as u64,
        graph_json,
    })
}

pub(crate) fn graph_constraint_from_json(
    raw: Option<&str>,
) -> Result<Option<crate::graph::GraphConstraint>, Status> {
    let Some(raw) = raw.filter(|raw| !raw.trim().is_empty()) else {
        return Ok(None);
    };
    serde_json::from_str(raw)
        .map(Some)
        .map_err(|error| Status::invalid_argument(format!("invalid graph_json: {error}")))
}

pub(crate) fn filter_from_json(raw: &str) -> Result<Option<Filter>, Status> {
    if raw.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(Filter(json_from_str(raw)?)))
}

pub(crate) fn json_from_optional_str(raw: &str) -> Result<Value, Status> {
    if raw.trim().is_empty() {
        return Ok(json!({}));
    }
    json_from_str(raw)
}

pub(crate) fn json_from_str(raw: &str) -> Result<Value, Status> {
    serde_json::from_str(raw)
        .map_err(|error| Status::invalid_argument(format!("invalid json: {error}")))
}

pub(crate) fn k_or_default(k: u64) -> Result<usize, Status> {
    if k == 0 {
        Ok(10)
    } else {
        usize_from_u64(k, "k")
    }
}

pub(crate) fn fusion_from_proto(raw: &str) -> Result<HybridFusion, Status> {
    match raw {
        "" | "rrf" => Ok(HybridFusion::Rrf),
        "weighted" => Ok(HybridFusion::Weighted),
        value => Err(Status::invalid_argument(format!(
            "unknown hybrid fusion: {value}"
        ))),
    }
}

pub(crate) fn optional_fusion_from_proto(raw: &str) -> Result<Option<HybridFusion>, Status> {
    if raw.trim().is_empty() {
        Ok(None)
    } else {
        fusion_from_proto(raw).map(Some)
    }
}

pub(crate) fn optional_string(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

pub(crate) fn weight_or_default(weight: f32) -> f32 {
    if weight == 0.0 { 1.0 } else { weight }
}

pub(crate) fn scroll_limit_or_default(limit: u64) -> Result<usize, Status> {
    if limit == 0 {
        Ok(100)
    } else {
        usize_from_u64(limit, "limit")
    }
}

pub(crate) fn usize_from_u64(value: u64, name: &str) -> Result<usize, Status> {
    usize::try_from(value)
        .map_err(|_| Status::invalid_argument(format!("{name} is too large for this platform")))
}

pub(crate) fn optional_usize_from_u64(value: u64, name: &str) -> Result<Option<usize>, Status> {
    if value == 0 {
        Ok(None)
    } else {
        usize_from_u64(value, name).map(Some)
    }
}

pub(crate) fn status_from_error(error: GaussError) -> Status {
    match error {
        GaussError::Graph(error) => graph_status(error),
        GaussError::CollectionNotFound(_) | GaussError::PointNotFound(_) => {
            Status::not_found(error.to_string())
        }
        GaussError::CollectionExists(_)
        | GaussError::DimensionMismatch { .. }
        | GaussError::InvalidCollectionName(_)
        | GaussError::InvalidRequest(_) => Status::invalid_argument(error.to_string()),
        GaussError::ResourceExhausted(_) => Status::resource_exhausted(error.to_string()),
        GaussError::WalUnavailable(_)
        | GaussError::AuditUnavailable(_)
        | GaussError::DataDirLocked { .. } => Status::unavailable(error.to_string()),
        GaussError::WalCorruption { .. }
        | GaussError::SegmentCorruption { .. }
        | GaussError::Io(_)
        | GaussError::Json(_) => Status::internal(error.to_string()),
    }
}

fn graph_status(error: crate::graph::GraphError) -> Status {
    use crate::graph::GraphErrorCode;
    use tonic::Code;

    let code = match error.code {
        GraphErrorCode::EndpointNotFound
        | GraphErrorCode::EdgeNotFound
        | GraphErrorCode::TypeNotFound
        | GraphErrorCode::DeferredSessionNotFound => Code::NotFound,
        GraphErrorCode::Overloaded => Code::ResourceExhausted,
        GraphErrorCode::Cancelled => Code::Cancelled,
        GraphErrorCode::SloUnavailable => Code::Unavailable,
        GraphErrorCode::GraphDisabled
        | GraphErrorCode::EpochMismatch
        | GraphErrorCode::TooManyAnchors
        | GraphErrorCode::TooManyTypes
        | GraphErrorCode::BatchTooLarge
        | GraphErrorCode::DepthExceeded
        | GraphErrorCode::PropertyTooLarge
        | GraphErrorCode::BatchBytesExceeded
        | GraphErrorCode::InvalidBudget
        | GraphErrorCode::TenantMoveHasEdges
        | GraphErrorCode::EdgesExist
        | GraphErrorCode::DeferredEndpointsRemain
        | GraphErrorCode::AllocatorExhausted => Code::InvalidArgument,
    };
    let details = serde_json::to_vec(&error).unwrap_or_default();
    Status::with_details(code, error.message.clone(), details.into())
}

pub(crate) fn text_hybrid_from_proto(
    request: &pb::TextHybridSearchRequest,
) -> Result<crate::TextHybridSearchRequest, Status> {
    Ok(crate::TextHybridSearchRequest {
        vector: request.vector.clone(),
        query: request.query.clone(),
        text_field: request.text_field.clone(),
        k: usize::try_from(request.k)
            .map_err(|_| Status::invalid_argument("k exceeds platform range"))?,
        filter: filter_from_json(&request.filter_json)?,
        budget_ms: request.budget_ms,
    })
}

#[cfg(test)]
mod tests {
    use prost::Message;
    use serde_json::Value;
    use tonic::Code;

    use super::{grpc_web_cors, pb, search_request_from_proto, status_from_error};
    use crate::{GaussError, GraphError, GraphErrorCode};

    #[test]
    fn resource_exhaustion_maps_to_grpc_status() {
        let status = status_from_error(GaussError::ResourceExhausted("retry".into()));
        assert_eq!(status.code(), Code::ResourceExhausted);
    }

    #[test]
    fn data_directory_lock_maps_to_grpc_unavailable() {
        let status = status_from_error(GaussError::DataDirLocked {
            path: "/data/chirondb".into(),
            owner: None,
        });
        assert_eq!(status.code(), Code::Unavailable);
    }

    #[test]
    fn graph_errors_are_not_reported_as_internal_failures() {
        let status = status_from_error(
            GraphError::new(GraphErrorCode::GraphDisabled, "graph is disabled").into(),
        );
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[test]
    fn search_query_preserves_recall_target() {
        let request = search_request_from_proto(pb::SearchQuery {
            vector: vec![1.0, 0.0],
            k: 10,
            filter_json: String::new(),
            budget_ms: None,
            vector_name: String::new(),
            ef_search: Some(64),
            recall_target: Some(0.95),
            graph_json: None,
        })
        .unwrap();

        assert_eq!(request.ef_search, Some(64));
        assert_eq!(request.recall_target, Some(0.95));
    }

    #[test]
    fn graph_search_fields_keep_their_additive_wire_numbers() {
        let query = pb::SearchQuery {
            graph_json: Some("{}".to_string()),
            ..Default::default()
        };
        assert_eq!(query.encode_to_vec(), b"\x42\x02{}", "field 8 tag");

        let hybrid = pb::HybridSearchRequest {
            graph_json: Some("{}".to_string()),
            ..Default::default()
        };
        assert_eq!(hybrid.encode_to_vec(), b"\x62\x02{}", "field 12 tag");

        let response = pb::SearchResponse {
            graph_json: Some("{}".to_string()),
            ..Default::default()
        };
        assert_eq!(response.encode_to_vec(), b"\x2a\x02{}", "field 5 tag");
    }

    #[test]
    fn chironwire_chironql_fields_keep_their_additive_wire_numbers() {
        let request = pb::WireRequest {
            operation: Some(pb::wire_request::Operation::Chironql(
                pb::WireChironQlRequest {
                    query: "x".to_string(),
                    ..Default::default()
                },
            )),
            ..Default::default()
        };
        assert_eq!(
            request.encode_to_vec(),
            b"\xfa\x01\x03\x0a\x01x",
            "WireRequest field 31 tag"
        );

        let details = pb::WireResponse {
            error_details_json: Some("{}".to_string()),
            ..Default::default()
        };
        assert_eq!(details.encode_to_vec(), b"\x22\x02{}", "field 4 tag");

        let response = pb::WireResponse {
            payload: Some(pb::wire_response::Payload::Chironql(
                pb::WireChironQlResponse {
                    kind: "rows".to_string(),
                    ..Default::default()
                },
            )),
            ..Default::default()
        };
        assert_eq!(
            response.encode_to_vec(),
            b"\xd2\x01\x06\x0a\x04rows",
            "WireResponse field 26 tag"
        );
    }

    #[test]
    fn graph_status_carries_the_stable_code_and_retry_metadata() {
        let status = status_from_error(
            GraphError::new(GraphErrorCode::Overloaded, "busy")
                .with_item_index(3)
                .with_retry_after_ms(25)
                .into(),
        );
        assert_eq!(status.code(), Code::ResourceExhausted);
        let details: Value = serde_json::from_slice(status.details()).unwrap();
        assert_eq!(details["code"], "graph.overloaded");
        assert_eq!(details["item_index"], 3);
        assert_eq!(details["retry_after_ms"], 25);
    }

    #[test]
    fn grpc_web_requires_explicit_non_wildcard_origins() {
        assert!(grpc_web_cors(&[]).is_err());
        assert!(grpc_web_cors(&["*".to_string()]).is_err());
        assert!(grpc_web_cors(&["http://127.0.0.1:3000".to_string()]).is_ok());
    }
}
