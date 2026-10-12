//! Retain authorization through every poll of tonic's encoded response body.
use crate::chironql_protected::PublicationGuard;
use axum::{body::Bytes, http};
use http_body::{Body, Frame};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::OwnedSemaphorePermit;
use tonic::{Status, codegen::Service, server::NamedService};

#[derive(Clone)]
pub(crate) struct ProtectedQuery;

#[derive(Clone)]
pub(crate) struct Caller {
    pub token: Arc<str>,
    pub work: Arc<OwnedSemaphorePermit>,
}

#[derive(Clone)]
pub(crate) struct GuardedService<S> {
    inner: S,
    protected: bool,
}
impl<S> GuardedService<S> {
    pub(crate) fn new(inner: S, protected: bool) -> Self {
        Self { inner, protected }
    }
}
impl<S: NamedService> NamedService for GuardedService<S> {
    const NAME: &'static str = S::NAME;
}

impl<S, B, R> Service<http::Request<B>> for GuardedService<S>
where
    S: Service<http::Request<B>, Response = http::Response<R>> + Send,
    R: Body<Data = Bytes, Error = Status> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        let protected = self.protected;
        // Server-side marker derived from tonic's canonical route. GrpcMethod
        // is a client extension and is not transmitted over the network.
        if protected
            && matches!(
                request.uri().path(),
                "/chirondb.v1.ChironDb/ExecuteQuery"
                    | "/chirondb.v1.ChironDb/TextHybridSearch"
                    | "/chirondb.v1.ChironDb/GetPoints"
                    | "/chirondb.v1.ChironDb/Scroll"
                    | "/chirondb.v1.ChironDb/ExecuteSql"
                    | "/chirondb.v1.ChironDb/BeginSqlTransaction"
                    | "/chirondb.v1.ChironDb/ExecuteSqlTransaction"
                    | "/chirondb.v1.ChironDb/CommitSqlTransaction"
                    | "/chirondb.v1.ChironDb/RollbackSqlTransaction"
            )
        {
            request.extensions_mut().insert(ProtectedQuery);
        }
        let future = self.inner.call(request);
        Box::pin(async move {
            let mut response = future.await?.map(tonic::body::Body::new);
            let guard = if !protected {
                // Receiving owners also follow legacy native SQL frames.
                if response
                    .extensions()
                    .get::<crate::response_output::SharedAdmission>()
                    .is_none()
                {
                    return Ok(response);
                }
                PublicationGuard::Acknowledgement
            } else if let Some(guard) = response.extensions_mut().remove::<PublicationGuard>() {
                guard
            } else {
                // Interceptor/parser errors carry no sensitive body. An
                // unguarded successful RPC must never fall through.
                return Ok(
                    if response
                        .headers()
                        .get("grpc-status")
                        .is_some_and(|status| status != "0")
                    {
                        response
                    } else {
                        Status::unavailable("protected publication guard is missing").into_http()
                    },
                );
            };
            let work = response
                .extensions_mut()
                .remove::<Arc<OwnedSemaphorePermit>>();
            let admission = response
                .extensions_mut()
                .remove::<crate::response_output::SharedAdmission>();
            let (parts, body) = response.into_parts();
            Ok(http::Response::from_parts(
                parts,
                tonic::body::Body::new(GuardedBody {
                    body,
                    guard,
                    admission,
                    _work: work,
                    closed: false,
                }),
            ))
        })
    }
}

struct GuardedBody {
    body: tonic::body::Body,
    guard: PublicationGuard,
    admission: Option<crate::response_output::SharedAdmission>,
    _work: Option<Arc<OwnedSemaphorePermit>>,
    closed: bool,
}
impl Body for GuardedBody {
    type Data = Bytes;
    type Error = Status;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(None);
        }
        match this
            .guard
            .publish(|| Pin::new(&mut this.body).poll_frame(cx))
        {
            Ok(Poll::Ready(Some(Ok(frame)))) => {
                let frame = frame.map_data(|bytes| match &this.admission {
                    Some(admission) => {
                        crate::response_output::retain_frame(bytes, admission.clone())
                    }
                    None => bytes,
                });
                Poll::Ready(Some(Ok(frame)))
            }
            Ok(Poll::Ready(None)) => {
                this.closed = true;
                this.body = tonic::body::Body::empty();
                this.admission.take();
                this._work.take();
                Poll::Ready(None)
            }
            Ok(Poll::Ready(Some(Err(error)))) => {
                this.closed = true;
                this.body = tonic::body::Body::empty();
                this.admission.take();
                this._work.take();
                Poll::Ready(Some(Err(error)))
            }
            Ok(result) => result,
            Err(_) => {
                this.closed = true;
                this.body = tonic::body::Body::empty();
                this.admission.take();
                this._work.take();
                Poll::Ready(Some(Err(Status::permission_denied(
                    "authorization was revoked",
                ))))
            }
        }
    }
}

pub(crate) fn authentication_error(error: crate::security::SecurityError) -> Status {
    error_status(crate::chironql_protected::error("", error.code()))
}

/// Protected native operations expose the same sanitized failures as ChironQL.
pub(crate) fn engine_error(error: crate::GaussError) -> Status {
    error_status(crate::chironql_protected::map_error("", error))
}

pub(crate) fn error_status(error: chirondb_types::chironql::ChironQlError) -> Status {
    let code = match error.code.as_str() {
        "security.unauthenticated" => tonic::Code::Unauthenticated,
        "security.forbidden" | "chironql.protected_unsupported" => tonic::Code::PermissionDenied,
        "security.not_found" => tonic::Code::NotFound,
        "security.conflict" => tonic::Code::Aborted,
        "chironql.confirmation_required"
        | "chironql.revision_required"
        | "chironql.sql_row_precondition_failed" => tonic::Code::FailedPrecondition,
        "security.budget_exceeded" | "chironql.resource_exhausted" => {
            tonic::Code::ResourceExhausted
        }
        "security.unavailable" | "chironql.outcome_unknown" => tonic::Code::Unavailable,
        _ => tonic::Code::InvalidArgument,
    };
    let details = serde_json::to_vec(&error).unwrap_or_default();
    Status::with_details(code, error.error, Bytes::from(details))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admitted_grpc_frame_outlives_body_and_revoked_queue_releases_immediately() {
        let (_directory, authority, key) = crate::chironql_protected::tests::identity_fixture();
        let identity = authority.authenticate(&key.secret).unwrap();
        let make = || {
            let (message, admission) = crate::response_output::points(vec![crate::Point {
                id: "visible".into(),
                vector: vec![1.0, -0.0],
                vectors: Default::default(),
                sparse_vector: None,
                payload: serde_json::json!({"text":"visible"}),
            }])
            .unwrap();
            let weak = Arc::downgrade(&admission);
            let body = ReadyBody(Some(Bytes::from(prost::Message::encode_to_vec(&message))));
            (
                GuardedBody {
                    body: tonic::body::Body::new(body),
                    guard: PublicationGuard::Identity(identity.clone()),
                    admission: Some(admission),
                    _work: Some(Arc::new(authority.work_pool().try_acquire_owned().unwrap())),
                    closed: false,
                },
                weak,
            )
        };
        let (mut queued, weak) = make();
        let frame = std::future::poll_fn(|cx| Pin::new(&mut queued).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        let bytes = frame.into_data().unwrap();
        drop(queued);
        assert!(
            weak.upgrade().is_some(),
            "published bytes must own admission after body drop"
        );
        let clone = bytes.clone();
        drop(bytes);
        assert!(weak.upgrade().is_some());
        drop(clone);
        assert!(weak.upgrade().is_none());
        let (mut queued, weak) = make();
        drop(
            std::future::poll_fn(|cx| Pin::new(&mut queued).poll_frame(cx))
                .await
                .unwrap()
                .unwrap(),
        );
        assert!(
            std::future::poll_fn(|cx| Pin::new(&mut queued).poll_frame(cx))
                .await
                .is_none()
        );
        assert!(weak.upgrade().is_none());
        drop(queued);
        let (mut queued, weak) = make();
        queued.body = tonic::body::Body::new(ErrorBody);
        let error = std::future::poll_fn(|cx| Pin::new(&mut queued).poll_frame(cx))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Internal);
        assert!(weak.upgrade().is_none());
        assert!(
            std::future::poll_fn(|cx| Pin::new(&mut queued).poll_frame(cx))
                .await
                .is_none()
        );
        drop(queued);
        let (mut queued, weak) = make();
        authority
            .revoke_credential(&identity, identity.revision(), &key.id)
            .unwrap();
        let error = std::future::poll_fn(|cx| Pin::new(&mut queued).poll_frame(cx))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert!(
            weak.upgrade().is_none(),
            "revoked queue must free admission without waiting for caller drop"
        );
        assert_eq!(
            authority.work_pool().available_permits(),
            chirondb_core::resource_profile::current().query_workers
        );
    }

    #[tokio::test]
    async fn legacy_sql_service_retains_admission_through_body_eof_and_last_byte_slice() {
        struct Reply(Option<http::Response<ReadyBody>>);
        impl Service<http::Request<()>> for Reply {
            type Response = http::Response<ReadyBody>;
            type Error = std::convert::Infallible;
            type Future = std::future::Ready<Result<Self::Response, Self::Error>>;
            fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, _: http::Request<()>) -> Self::Future {
                std::future::ready(Ok(self.0.take().unwrap()))
            }
        }
        let (json, admission) =
            crate::response_output::wire_json(&serde_json::json!({"result":"日本語".repeat(4096)}))
                .unwrap();
        let weak = Arc::downgrade(&admission);
        let mut inner = http::Response::new(ReadyBody(Some(Bytes::from(json.into_bytes()))));
        inner.extensions_mut().insert(admission);
        let mut service = GuardedService::new(Reply(Some(inner)), false);
        let mut response = service.call(http::Request::new(())).await.unwrap();
        assert!(
            response
                .extensions()
                .get::<crate::response_output::SharedAdmission>()
                .is_none(),
            "owner moves into body"
        );
        let frame = std::future::poll_fn(|cx| Pin::new(response.body_mut()).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        let bytes = frame.into_data().unwrap();
        let slice = bytes.slice(1..);
        drop(bytes);
        assert!(
            std::future::poll_fn(|cx| Pin::new(response.body_mut()).poll_frame(cx))
                .await
                .is_none()
        );
        drop(response);
        assert!(
            weak.upgrade().is_some(),
            "encoded bytes outlive completed body"
        );
        drop(slice);
        assert!(weak.upgrade().is_none());
    }

    struct ReadyBody(Option<Bytes>);
    struct ErrorBody;
    impl Body for ErrorBody {
        type Data = Bytes;
        type Error = Status;
        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
            Poll::Ready(Some(Err(Status::internal("synthetic codec failure"))))
        }
    }
    impl Body for ReadyBody {
        type Data = Bytes;
        type Error = Status;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
            Poll::Ready(self.0.take().map(|bytes| Ok(Frame::data(bytes))))
        }
    }

    #[test]
    fn protected_engine_errors_hide_storage_paths_and_admission_details() {
        use crate::GaussError;
        let sensitive = "/private/install/tenant-physical-id/payload.gdx";
        for (error, expected) in [
            (
                GaussError::SegmentCorruption {
                    path: sensitive.into(),
                    message: "backend-private-record".into(),
                },
                tonic::Code::Unavailable,
            ),
            (
                GaussError::Io(std::io::Error::other(sensitive)),
                tonic::Code::Unavailable,
            ),
            (
                GaussError::ResourceExhausted(sensitive.into()),
                tonic::Code::ResourceExhausted,
            ),
            (
                GaussError::InvalidRequest(sensitive.into()),
                tonic::Code::InvalidArgument,
            ),
        ] {
            let status = engine_error(error);
            assert!(!status.message().contains(sensitive));
            assert!(!String::from_utf8_lossy(status.details()).contains(sensitive));
            assert!(!status.message().contains("backend-private-record"));
            assert!(!String::from_utf8_lossy(status.details()).contains("backend-private-record"));
            assert_eq!(status.code(), expected);
        }
    }

    #[test]
    fn authority_failure_is_unavailable_and_bad_credentials_are_unauthenticated() {
        assert_eq!(
            authentication_error(crate::security::SecurityError::Unavailable).code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            authentication_error(crate::security::SecurityError::Unauthenticated).code(),
            tonic::Code::Unauthenticated
        );
    }

    #[tokio::test]
    async fn encoded_grpc_queue_discards_data_and_releases_work_after_revoke() {
        let (_directory, authority, key) = crate::chironql_protected::tests::identity_fixture();
        let identity = authority.authenticate(&key.secret).unwrap();
        let work = authority.work_pool().try_acquire_owned().unwrap();
        let body = ReadyBody(Some(Bytes::from_static(b"queued-private-result")));
        let mut queued = GuardedBody {
            body: tonic::body::Body::new(body),
            guard: PublicationGuard::Identity(identity.clone()),
            admission: None,
            _work: Some(Arc::new(work)),
            closed: false,
        };
        authority
            .revoke_credential(&identity, identity.revision(), &key.id)
            .unwrap();
        let frame = std::future::poll_fn(|cx| Pin::new(&mut queued).poll_frame(cx))
            .await
            .unwrap();
        assert_eq!(frame.unwrap_err().code(), tonic::Code::PermissionDenied);
        assert!(
            std::future::poll_fn(|cx| Pin::new(&mut queued).poll_frame(cx))
                .await
                .is_none()
        );
        drop(queued);
        assert_eq!(
            authority.work_pool().available_permits(),
            chirondb_core::resource_profile::current().query_workers
        );
    }
}
