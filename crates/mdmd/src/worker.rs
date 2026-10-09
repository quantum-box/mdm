use crate::{
    apns::{ApnsClient, PushOutcome},
    storage::{self, Store},
};
use std::sync::Arc;

pub async fn run(
    store: Store,
    apns: Option<Arc<ApnsClient>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=shutdown.changed()=>break,
            _=interval.tick()=>{},
        }
        if store.recover_timeouts(storage::now()).is_err() {
            tracing::error!(category = "timeout_recovery_failed");
        }
        let Some(client) = &apns else { continue };
        // One leased notification at a time bounds concurrency and supports durable restart.
        let job = match store.claim_notification(storage::now()) {
            Ok(Some(job)) => job,
            Ok(None) => continue,
            Err(_) => {
                tracing::error!(category = "outbox_claim_failed");
                continue;
            }
        };
        let result = match client.send(&job.token, &job.push_magic).await {
            Ok(PushOutcome::Accepted { apns_id }) => store.finish_notification(
                &job,
                "accepted",
                None,
                apns_id.as_deref(),
                storage::now(),
            ),
            Ok(PushOutcome::Retry { reason }) => {
                store.finish_notification(&job, "retry", Some(&reason), None, storage::now())
            }
            Ok(PushOutcome::Rejected { reason }) => {
                store.finish_notification(&job, "rejected", Some(&reason), None, storage::now())
            }
            Err(_) => store.finish_notification(
                &job,
                "retry",
                Some("transport_error"),
                None,
                storage::now(),
            ),
        };
        if result.is_err() {
            tracing::error!(category = "outbox_result_failed");
        }
    }
}
