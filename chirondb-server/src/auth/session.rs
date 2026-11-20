//! A legacy connection retains only a credential digest, never the bearer key.
//! Key-file observation closes admission, drains existing output/commit leases,
//! then acknowledges retirement. Queued output rechecks on every poll. Bytes
//! already handed to the transport and committed work cannot be recalled.
use super::AuthConfig;
use crate::{Db, rbac::Permission};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use subtle::ConstantTimeEq;
use tokio::io::AsyncWrite;

/// A credential closes admission first, then drains already admitted output or
/// commits before an observer acknowledges the change. The gate is per key.
#[derive(Debug, Default)]
pub(super) struct CredentialEpoch {
    closed: AtomicBool,
    drained: AtomicBool,
    gate: parking_lot::RwLock<()>,
}
impl CredentialEpoch {
    pub(super) fn drain(&self) {
        if !self.drained.load(Ordering::Acquire) {
            let _exclusive = self.gate.write();
            self.drained.store(true, Ordering::Release);
        }
    }
    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

pub(crate) type CredentialLease<'a> = Option<parking_lot::RwLockReadGuard<'a, ()>>;

/// Current key digests plus pending retirement barriers. No credential history
/// is retained after its admitted operations drain. Every concurrent observer
/// sees the same pending barriers; none can acknowledge revocation prematurely.
#[derive(Debug, Default)]
pub(super) struct ObservedCredentials {
    current: HashMap<[u8; 32], Arc<CredentialEpoch>>,
    retiring: Vec<Arc<CredentialEpoch>>,
    pub(super) file_error: Option<io::ErrorKind>,
}
impl ObservedCredentials {
    pub(super) fn observe(&mut self, keys: &[Arc<str>]) -> Vec<Arc<CredentialEpoch>> {
        self.retiring
            .retain(|epoch| !epoch.drained.load(Ordering::Acquire));
        let digests: HashSet<[u8; 32]> = keys
            .iter()
            .map(|key| Sha256::digest(key.as_bytes()).into())
            .collect();
        let retiring = &mut self.retiring;
        self.current.retain(|digest, epoch| {
            let keep = digests.contains(digest);
            if !keep {
                epoch.closed.store(true, Ordering::Release);
                retiring.push(epoch.clone());
            }
            keep
        });
        for digest in digests {
            self.current
                .entry(digest)
                .or_insert_with(|| Arc::new(CredentialEpoch::default()));
        }
        self.retiring.clone()
    }
    pub(super) fn binding(&self, candidate: &str) -> Option<Arc<CredentialEpoch>> {
        let digest: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        self.current.get(&digest).cloned()
    }
}

pub(crate) struct LegacySession {
    auth: AuthConfig,
    digest: Option<[u8; 32]>,
    epoch: Arc<CredentialEpoch>,
    db: Db,
    denial_recorded: AtomicBool,
}

impl LegacySession {
    pub(crate) fn authenticate(
        db: &Db,
        auth: &AuthConfig,
        candidate: Option<&str>,
    ) -> Option<(Permission, Self)> {
        let principal = auth.permission_for(candidate)?;
        let (digest, epoch) = if let Some(keyring) = &auth.keyring {
            let candidate = candidate?;
            (
                Some(Sha256::digest(candidate.as_bytes()).into()),
                keyring.bind(candidate)?,
            )
        } else {
            (None, Arc::new(CredentialEpoch::default()))
        };
        Some((
            principal,
            Self {
                auth: auth.clone(),
                digest,
                epoch,
                db: db.clone(),
                denial_recorded: AtomicBool::new(false),
            },
        ))
    }

    pub(crate) fn authorize(&self) -> io::Result<CredentialLease<'_>> {
        if self.epoch.is_closed() {
            return Err(self.reject());
        }
        let Some(digest) = self.digest else {
            return Ok(None);
        };
        // Refresh before taking this key's lease: a refresh may need to drain
        // that same epoch and must never wait while holding its own read lease.
        let mut accepted = false;
        for key in self.auth.accepted_keys() {
            let current: [u8; 32] = Sha256::digest(key.as_bytes()).into();
            let permission_exists = self
                .auth
                .rbac
                .as_ref()
                .is_none_or(|rbac| rbac.find_key(&key).is_some());
            accepted |= bool::from(current.ct_eq(&digest)) && permission_exists;
        }
        if accepted {
            let lease = self.epoch.gate.read();
            // Close may race the first check or the read-lock acquisition.
            if !self.epoch.is_closed() {
                return Ok(Some(lease));
            }
        }
        self.epoch.closed.store(true, Ordering::Release);
        Err(self.reject())
    }

    fn reject(&self) -> io::Error {
        if !self.denial_recorded.swap(true, Ordering::AcqRel) {
            let _ = super::denial::record(&self.db, super::denial::Transport::Postgres);
        }
        revoked()
    }
}

fn revoked() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "session credential is no longer valid",
    )
}

/// Rechecks even after an inner writer returned Pending. A precomputed response,
/// portal or partially sent result cannot retain authority across revocation.
pub(crate) struct SessionWriter<'a, W> {
    inner: W,
    session: &'a LegacySession,
}
impl<'a, W> SessionWriter<'a, W> {
    pub(crate) fn new(inner: W, session: &'a LegacySession) -> Self {
        Self { inner, session }
    }
    pub(crate) fn authorize(&self) -> io::Result<()> {
        self.session.authorize().map(drop)
    }
    pub(crate) fn lease(&self) -> io::Result<CredentialLease<'_>> {
        self.session.authorize()
    }
}
impl<W: AsyncWrite + Unpin> AsyncWrite for SessionWriter<'_, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let _lease = match this.session.authorize() {
            Ok(lease) => lease,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let _lease = match this.session.authorize() {
            Ok(lease) => lease,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let _lease = match this.session.authorize() {
            Ok(lease) => lease,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, future::Future};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The inner transport/commit is stopped after admission but before its
    /// side effect. Two observers try to finish revocation in that exact gap.
    fn exercise_publication_revocation_race(commit: bool) {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        struct PausedWriter {
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
            observed: Arc<AtomicBool>,
            late: Arc<AtomicBool>,
        }
        impl AsyncWrite for PausedWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.entered.send(()).unwrap();
                self.release.recv_timeout(Duration::from_secs(5)).unwrap();
                self.late
                    .store(self.observed.load(Ordering::Acquire), Ordering::Release);
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let root = tempfile::tempdir().unwrap();
        let key = format!("synthetic-{}", uuid::Uuid::new_v4());
        let retained = format!("synthetic-{}", uuid::Uuid::new_v4());
        let file = root.path().join("keys");
        fs::write(&file, format!("{key}\n{retained}")).unwrap();
        let db = Db::open(root.path()).unwrap();
        let auth = AuthConfig::from_key_sources(None, Some(file.clone()));
        let (_, session) = LegacySession::authenticate(&db, &auth, Some(&key)).unwrap();
        let observed = Arc::new(AtomicBool::new(false));
        let late = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let operation_observed = observed.clone();
            let operation_late = late.clone();
            let session_ref = &session;
            let operation = scope.spawn(move || {
                if commit {
                    // A synchronous commit owns this admission until its effect
                    // completes, just like the production engine commit call.
                    let _lease = session_ref.authorize().unwrap();
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    operation_late.store(
                        operation_observed.load(Ordering::Acquire),
                        Ordering::Release,
                    );
                } else {
                    let inner = PausedWriter {
                        entered: entered_tx,
                        release: release_rx,
                        observed: operation_observed,
                        late: operation_late,
                    };
                    let mut writer = SessionWriter::new(inner, session_ref);
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    runtime
                        .block_on(writer.write_all(b"protected-result"))
                        .unwrap();
                }
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            fs::write(&file, &retained).unwrap();
            let observe = || {
                assert!(auth.permission_for(Some(&retained)).is_some());
                observed.store(true, Ordering::Release);
                done_tx.send(()).unwrap();
            };
            let first = scope.spawn(observe);
            let deadline = Instant::now() + Duration::from_secs(5);
            while !session.epoch.is_closed() {
                assert!(
                    Instant::now() < deadline,
                    "observer did not start revocation"
                );
                std::thread::yield_now();
            }
            let second = scope.spawn(observe);
            // Admission/transport are synchronized above; this bounded wait
            // gives an erroneously unblocked observer a chance to acknowledge.
            let acknowledged_early = done_rx.recv_timeout(Duration::from_millis(100)).is_ok();
            release_tx.send(()).unwrap();
            operation.join().unwrap();
            first.join().unwrap();
            second.join().unwrap();
            assert!(
                !acknowledged_early,
                "revocation returned before admitted publication/commit drained"
            );
            assert!(
                !late.load(Ordering::Acquire),
                "publication/commit occurred after an observer acknowledged revocation"
            );
            assert!(session.authorize().is_err());
        });
    }

    #[test]
    fn publication_poll_lease_drains_before_concurrent_observers_return() {
        exercise_publication_revocation_race(false);
    }

    #[test]
    fn synchronous_commit_lease_drains_before_concurrent_observers_return() {
        exercise_publication_revocation_race(true);
    }

    #[tokio::test]
    async fn pending_output_rechecks_revocation_and_cannot_reanimate() {
        let root = tempfile::tempdir().unwrap();
        let key = format!("synthetic-{}", uuid::Uuid::new_v4());
        let file = root.path().join("keys");
        fs::write(&file, &key).unwrap();
        let db = Db::open(root.path()).unwrap();
        let auth = AuthConfig::from_key_sources(None, Some(file.clone()));
        let (_, session) = LegacySession::authenticate(&db, &auth, Some(&key)).unwrap();
        let (mut inner, mut peer) = tokio::io::duplex(1);
        // Occupy the transport before any protected output is queued.
        inner.write_all(b"x").await.unwrap();
        let mut writer = SessionWriter::new(inner, &session);
        let mut write = std::pin::pin!(writer.write_all(b"private-row"));
        assert!(
            std::future::poll_fn(|cx| {
                assert!(write.as_mut().poll(cx).is_pending());
                Poll::Ready(true)
            })
            .await
        );
        fs::write(&file, "").unwrap();
        let mut first = [0; 1];
        peer.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"x");
        assert_eq!(
            write.await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::write(&file, &key).unwrap();
        assert!(
            session.authorize().is_err(),
            "an observed revocation permanently retires the session"
        );
        let (_, replacement) = LegacySession::authenticate(&db, &auth, Some(&key)).unwrap();
        assert!(
            replacement.authorize().is_ok(),
            "a new authorized connection still works"
        );
    }

    #[test]
    fn another_request_observes_revocation_of_an_idle_session_without_retaining_history() {
        let root = tempfile::tempdir().unwrap();
        let key = format!("synthetic-{}", uuid::Uuid::new_v4());
        let retained = format!("synthetic-{}", uuid::Uuid::new_v4());
        let file = root.path().join("keys");
        fs::write(&file, format!("{key}\n{retained}")).unwrap();
        let db = Db::open(root.path()).unwrap();
        let auth = AuthConfig::from_key_sources(None, Some(file.clone()));
        let (_, idle) = LegacySession::authenticate(&db, &auth, Some(&key)).unwrap();
        fs::write(&file, &retained).unwrap();
        assert!(auth.permission_for(Some(&retained)).is_some());
        fs::write(&file, format!("{key}\n{retained}")).unwrap();
        let (_, replacement) = LegacySession::authenticate(&db, &auth, Some(&key)).unwrap();
        assert!(replacement.authorize().is_ok());
        assert!(
            idle.authorize().is_err(),
            "another request observed revocation before this session was used"
        );
        let keyring = auth.keyring.as_ref().unwrap();
        assert_eq!(keyring.observed.lock().unwrap().current.len(), 2);
        for index in 0..100 {
            fs::write(&file, format!("synthetic-rotation-{index}")).unwrap();
            auth.accepted_keys();
        }
        assert_eq!(
            keyring.observed.lock().unwrap().current.len(),
            1,
            "retired credentials are not cached"
        );
        assert!(replacement.authorize().is_err());
    }

    #[test]
    fn missing_keyfile_warning_is_bounded_to_error_transitions() {
        #[derive(Clone)]
        struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("missing-keys");
        let capture = Capture(Arc::new(std::sync::Mutex::new(Vec::new())));
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let auth = AuthConfig::from_key_sources(None, Some(file.clone()));
            for _ in 0..64 {
                assert!(!auth.accepts(Some("synthetic")));
            }
            let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            assert_eq!(
                log.matches("failed to read api key file").count(),
                1,
                "repeated requests must not amplify one missing-file error"
            );
            fs::write(&file, "synthetic").unwrap();
            assert!(auth.accepts(Some("synthetic")));
            fs::remove_file(&file).unwrap();
            for _ in 0..64 {
                assert!(!auth.accepts(Some("synthetic")));
            }
            let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            assert_eq!(
                log.matches("failed to read api key file").count(),
                2,
                "a new failure after recovery must be observable once"
            );
        });
    }

    #[test]
    fn current_key_sources_and_missing_key_files_are_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let key = format!("synthetic-{}", uuid::Uuid::new_v4());
        let file = root.path().join("keys");
        fs::write(&file, &key).unwrap();
        let db = Db::open(root.path()).unwrap();
        let auth = AuthConfig::from_key_sources(None, Some(file.clone()));
        let (_, session) = LegacySession::authenticate(&db, &auth, Some(&key)).unwrap();
        assert!(session.authorize().is_ok());
        fs::remove_file(&file).unwrap();
        assert!(session.authorize().is_err());
        let static_auth = AuthConfig::from_key_sources(Some(key.clone()), Some(file));
        let (_, still_configured) =
            LegacySession::authenticate(&db, &static_auth, Some(&key)).unwrap();
        assert!(
            still_configured.authorize().is_ok(),
            "removing a file does not remove a separately configured static key"
        );
    }
}
