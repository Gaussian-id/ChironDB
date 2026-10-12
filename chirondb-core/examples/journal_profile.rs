//! Diagnostic for transaction-journal growth and cold reopen. Run each mode
//! in a separate process so the reopen RSS excludes the writer's allocator.

use std::{env, fs, path::PathBuf, time::Instant};

use chirondb_core::{
    audit::AuditContext,
    resource_profile,
    transaction_journal::{
        IdempotencyAdmission, ProjectionKind, TransactionAudit, TransactionJournal,
        TransactionTarget,
    },
    wal::WalEntry,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mode = args
        .next()
        .ok_or("usage: journal_profile write|reopen DIR [COUNT]")?;
    let directory = PathBuf::from(args.next().ok_or("missing directory")?);
    let count = match mode.as_str() {
        "write" => {
            let count = args.next().ok_or("missing write count")?.parse::<u64>()?;
            if count == 0 || count > 1_000_000 {
                return Err("write count must be between 1 and 1,000,000".into());
            }
            fs::create_dir(&directory)?;
            count
        }
        "reopen" => 0,
        _ => return Err("mode must be write or reopen".into()),
    };
    if args.next().is_some() {
        return Err("unexpected trailing argument".into());
    }

    let baseline_rss = resource_profile::process_usage().rss_bytes;
    let started = Instant::now();
    let journal = TransactionJournal::open(&directory)?;
    let open_seconds = started.elapsed().as_secs_f64();
    let open_rss = resource_profile::process_usage().rss_bytes;
    let context = AuditContext::embedded();
    let write_started = Instant::now();
    for index in 0..count {
        let key = format!("resource-probe-{index}");
        let transaction =
            match journal.begin_idempotent(&key, &context, "delete", &index, || Ok(()))? {
                IdempotencyAdmission::Execute(guard) => guard.commit(
                    TransactionTarget::Collection {
                        name: "probe".into(),
                    },
                    WalEntry::DeleteBatch {
                        ids: vec![format!("point-{index}")],
                    },
                    TransactionAudit::mutation("delete", Some("probe"), &context, json!({})),
                    json!({"deleted": 1}),
                )?,
                IdempotencyAdmission::Replay(_) => {
                    return Err("fresh key was already consumed".into());
                }
            };
        journal.mark_projected(transaction.prepare.transaction_id, ProjectionKind::Storage)?;
        journal.mark_projected(transaction.prepare.transaction_id, ProjectionKind::Audit)?;
    }
    let write_seconds = write_started.elapsed().as_secs_f64();
    let final_rss = resource_profile::process_usage().rss_bytes;
    let frontier = journal.completed_commit_frontier()?;
    println!(
        "{}",
        json!({
            "mode": mode,
            "count_written": count,
            "baseline_rss_bytes": baseline_rss,
            "after_open_rss_bytes": open_rss,
            "final_rss_bytes": final_rss,
            "open_seconds": open_seconds,
            "write_seconds": write_seconds,
            "completed_commit_frontier": frontier,
        })
    );
    Ok(())
}
