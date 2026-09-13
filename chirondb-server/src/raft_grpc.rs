use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{
    Db, GaussError,
    raft::{
        AppendEntriesReq, CatalogCommand, RaftHandle, RequestVoteReq,
        raft_proto::{
            AppendEntriesRequest, AppendEntriesResponse, ForwardProposalRequest,
            ForwardProposalResponse, InstallSnapshotRequest, InstallSnapshotResponse,
            RequestVoteRequest, RequestVoteResponse, WalSegment, WalStreamRequest,
            raft_service_server::RaftService,
        },
    },
    wal_replication::WalReplicationManager,
};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

// A WAL record may be as large as 128 MiB. Keep only one encoded record queued
// so channel backpressure also provides a meaningful byte-memory bound.
const WAL_STREAM_CHANNEL_CAPACITY: usize = 1;

fn wal_stream_status(error: GaussError) -> Status {
    match error {
        GaussError::WalCorruption { .. } => Status::data_loss(error.to_string()),
        GaussError::InvalidRequest(message) if message.contains("precedes retained base") => {
            Status::failed_precondition(message)
        }
        GaussError::InvalidRequest(_) => Status::invalid_argument(error.to_string()),
        GaussError::WalUnavailable(_) | GaussError::Io(_) => Status::unavailable(error.to_string()),
        GaussError::CollectionNotFound(_) | GaussError::PointNotFound(_) => {
            Status::not_found(error.to_string())
        }
        other => Status::internal(other.to_string()),
    }
}

fn spawn_wal_stream(
    wal_dir: PathBuf,
    collection: String,
    from_lsn: u64,
) -> ReceiverStream<Result<crate::raft::raft_proto::WalSegment, Status>> {
    let (tx, rx) = tokio::sync::mpsc::channel(WAL_STREAM_CHANNEL_CAPACITY);
    tokio::task::spawn_blocking(move || {
        let result = WalReplicationManager::scan_wal_entries(&wal_dir, from_lsn, |record| {
            let lsn = record.lsn;
            let entry_json = serde_json::to_vec(&record.entry)?;
            drop(record);
            tx.blocking_send(Ok(crate::raft::raft_proto::WalSegment {
                collection: collection.clone(),
                lsn,
                entry_json,
            }))
            .map_err(|_| GaussError::WalUnavailable("WAL stream receiver closed".to_string()))?;
            Ok(())
        });
        if let Err(error) = result {
            // If the client cancelled, this final send simply fails. Real WAL
            // scan/serialization errors become a terminal gRPC stream item.
            let _ = tx.blocking_send(Err(wal_stream_status(error)));
        }
    });
    ReceiverStream::new(rx)
}

pub struct RaftGrpcService {
    pub raft_handle: RaftHandle,
    pub db: Db,
    pub replication: Arc<RwLock<WalReplicationManager>>,
}

#[tonic::async_trait]
impl RaftService for RaftGrpcService {
    async fn append_entries(
        &self,
        request: Request<AppendEntriesRequest>,
    ) -> Result<Response<AppendEntriesResponse>, Status> {
        let req = request.into_inner();
        let entries = req
            .entries
            .iter()
            .map(|e| {
                let command: crate::raft::CatalogCommand =
                    serde_json::from_slice(&e.data).unwrap_or(CatalogCommand::Noop);
                crate::raft::RaftLogEntry {
                    term: e.term,
                    index: e.index,
                    command,
                }
            })
            .collect();

        let internal_req = AppendEntriesReq {
            term: req.term,
            leader_id: req.leader_id,
            prev_log_index: req.prev_log_index,
            prev_log_term: req.prev_log_term,
            entries,
            leader_commit: req.leader_commit,
        };

        let resp = self.raft_handle.append_entries(internal_req).await;
        Ok(Response::new(AppendEntriesResponse {
            term: resp.term,
            success: resp.success,
            conflict_index: resp.conflict_index,
            conflict_term: resp.conflict_term,
        }))
    }

    async fn request_vote(
        &self,
        request: Request<RequestVoteRequest>,
    ) -> Result<Response<RequestVoteResponse>, Status> {
        let req = request.into_inner();
        let internal_req = RequestVoteReq {
            term: req.term,
            candidate_id: req.candidate_id,
            last_log_index: req.last_log_index,
            last_log_term: req.last_log_term,
        };
        let resp = self.raft_handle.request_vote(internal_req).await;
        Ok(Response::new(RequestVoteResponse {
            term: resp.term,
            vote_granted: resp.vote_granted,
        }))
    }

    async fn install_snapshot(
        &self,
        request: Request<InstallSnapshotRequest>,
    ) -> Result<Response<InstallSnapshotResponse>, Status> {
        let req = request.into_inner();
        // Restore the state machine from snapshot
        let sm = crate::raft::CatalogStateMachine::restore(&req.data);
        {
            let arc = self.raft_handle.state_machine();
            let mut guard = arc.write().await;
            *guard = sm;
        }
        Ok(Response::new(InstallSnapshotResponse { term: req.term }))
    }

    async fn forward_proposal(
        &self,
        request: Request<ForwardProposalRequest>,
    ) -> Result<Response<ForwardProposalResponse>, Status> {
        let req = request.into_inner();
        let cmd: CatalogCommand = serde_json::from_slice(&req.command)
            .map_err(|e| Status::invalid_argument(format!("bad command: {e}")))?;
        match self.raft_handle.propose(cmd).await {
            Ok(()) => Ok(Response::new(ForwardProposalResponse {
                success: true,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(ForwardProposalResponse {
                success: false,
                error: e,
            })),
        }
    }

    type StreamWalStream = ReceiverStream<Result<WalSegment, Status>>;

    async fn stream_wal(
        &self,
        request: Request<WalStreamRequest>,
    ) -> Result<Response<Self::StreamWalStream>, Status> {
        let req = request.into_inner();
        let collection = req.collection.clone();
        let from_lsn = req.from_lsn;

        // Resolve WAL directory for this collection from Db
        let wal_dir = self
            .db
            .collection_wal_dir(&collection)
            .ok_or_else(|| Status::not_found(format!("collection '{collection}' not found")))?;

        Ok(Response::new(spawn_wal_stream(
            wal_dir, collection, from_lsn,
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, io::Write};

    use chirondb_core::wal::{Wal, WalEntry};
    use tempfile::TempDir;
    use tokio_stream::StreamExt;
    use tonic::Code;

    use super::spawn_wal_stream;

    #[tokio::test]
    async fn bounded_stream_propagates_wal_corruption() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open(temp.path()).unwrap();
        wal.append(&WalEntry::Delete {
            id: "durable".to_string(),
        })
        .unwrap();
        let active = wal.path().to_path_buf();
        drop(wal);
        OpenOptions::new()
            .append(true)
            .open(active)
            .unwrap()
            .write_all(&[1, 2, 3])
            .unwrap();

        let mut stream = spawn_wal_stream(temp.path().to_path_buf(), "docs".to_string(), 0);
        assert!(stream.next().await.unwrap().is_ok());
        let status = stream.next().await.unwrap().unwrap_err();
        assert_eq!(status.code(), Code::DataLoss);
    }

    #[tokio::test]
    async fn retained_prefix_miss_requires_snapshot() {
        let temp = TempDir::new().unwrap();
        let mut wal = Wal::open(temp.path()).unwrap();
        let end = wal
            .append(&WalEntry::Delete {
                id: "archived".to_string(),
            })
            .unwrap();
        wal.drop_prefix(end).unwrap();
        drop(wal);

        let mut stream = spawn_wal_stream(temp.path().to_path_buf(), "docs".to_string(), 0);
        let status = stream.next().await.unwrap().unwrap_err();
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert!(status.message().contains("snapshot required"));
    }
}
