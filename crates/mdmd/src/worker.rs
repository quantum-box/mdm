//! Provider-independent outbox processing and the standalone interval scheduler.
//!
//! A host can invoke `tick` from a timer, queue delivery or scheduled invocation.
//! Leases and results always belong to the durable repository, not the scheduler.

use crate::{
    apns::{ApnsClient, PushOutcome},
    storage::{self, Notification, Store},
};
use anyhow::Result;
use std::{future::Future, pin::Pin, sync::Arc};

/// Time is supplied by the host so queue and recovery behavior can be tested.
pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> i64 {
        storage::now()
    }
}

/// Atomic lease and result operations a durable backend must provide.
pub trait NotificationStore: Send + Sync {
    fn recover_timeouts(&self, time: i64) -> StoreFuture<'_, usize>;
    fn claim_notification(&self, time: i64) -> StoreFuture<'_, Option<Notification>>;
    fn finish_notification<'a>(
        &'a self,
        job: &'a Notification,
        state: &'a str,
        reason: Option<&'a str>,
        apns_id: Option<&'a str>,
        time: i64,
    ) -> StoreFuture<'a, ()>;
}

pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

impl NotificationStore for Store {
    fn recover_timeouts(&self, time: i64) -> StoreFuture<'_, usize> {
        Box::pin(std::future::ready(Store::recover_timeouts(self, time)))
    }
    fn claim_notification(&self, time: i64) -> StoreFuture<'_, Option<Notification>> {
        Box::pin(std::future::ready(Store::claim_notification(self, time)))
    }
    fn finish_notification<'a>(
        &'a self,
        job: &'a Notification,
        state: &'a str,
        reason: Option<&'a str>,
        apns_id: Option<&'a str>,
        time: i64,
    ) -> StoreFuture<'a, ()> {
        Box::pin(std::future::ready(Store::finish_notification(
            self, job, state, reason, apns_id, time,
        )))
    }
}

pub type PushFuture<'a> = Pin<Box<dyn Future<Output = Result<PushOutcome>> + Send + 'a>>;

/// Sending a push is independent of the runtime or queue product.
pub trait PushProvider: Send + Sync {
    fn send<'a>(&'a self, token: &'a [u8], push_magic: &'a str) -> PushFuture<'a>;
}

impl PushProvider for ApnsClient {
    fn send<'a>(&'a self, token: &'a [u8], push_magic: &'a str) -> PushFuture<'a> {
        Box::pin(ApnsClient::send(self, token, push_magic))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TickResult {
    pub recovered_commands: usize,
    pub notification_attempted: bool,
}

/// Recovers expired commands and processes at most one leased notification.
///
/// Calling this more than once, or from multiple schedulers, is safe only when
/// the repository provides the atomic lease contract above. Transport failures
/// become a persisted retry; no scheduler should replay the original command.
pub async fn tick(
    store: &dyn NotificationStore,
    push: Option<&dyn PushProvider>,
    clock: &dyn Clock,
) -> Result<TickResult> {
    let recovered_commands = store.recover_timeouts(clock.now()).await?;
    let mut result = TickResult {
        recovered_commands,
        notification_attempted: false,
    };
    let Some(push) = push else { return Ok(result) };
    let Some(job) = store.claim_notification(clock.now()).await? else {
        return Ok(result);
    };
    result.notification_attempted = true;
    match push.send(&job.token, &job.push_magic).await {
        Ok(PushOutcome::Accepted { apns_id }) => {
            store
                .finish_notification(&job, "accepted", None, apns_id.as_deref(), clock.now())
                .await?;
        }
        Ok(PushOutcome::Retry { reason }) => {
            store
                .finish_notification(&job, "retry", Some(&reason), None, clock.now())
                .await?;
        }
        Ok(PushOutcome::Rejected { reason }) => {
            store
                .finish_notification(&job, "rejected", Some(&reason), None, clock.now())
                .await?;
        }
        Err(_) => {
            store
                .finish_notification(&job, "retry", Some("transport_error"), None, clock.now())
                .await?;
        }
    }
    Ok(result)
}

/// Standalone host adapter; cloud schedulers can invoke `tick` directly instead.
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
        let push = apns.as_deref().map(|client| client as &dyn PushProvider);
        if tick(&store, push, &SystemClock).await.is_err() {
            tracing::error!(category = "worker_tick_failed");
        }
    }
}
