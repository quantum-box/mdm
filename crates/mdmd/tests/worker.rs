use anyhow::{Result, anyhow};
use mdmd::{
    apns::PushOutcome,
    storage::Notification,
    worker::{Clock, NotificationStore, PushFuture, PushProvider, StoreFuture, tick},
};
use std::{collections::VecDeque, sync::Mutex};

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> i64 {
        1234
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Completion {
    id: i64,
    state: String,
    reason: Option<String>,
    apns_id: Option<String>,
    time: i64,
}

#[derive(Default)]
struct FakeStore {
    jobs: Mutex<VecDeque<Notification>>,
    completed: Mutex<Vec<Completion>>,
    recovered: Mutex<Vec<i64>>,
    claims: Mutex<Vec<i64>>,
    fail_recovery: bool,
}
impl NotificationStore for FakeStore {
    fn recover_timeouts(&self, time: i64) -> StoreFuture<'_, usize> {
        let result = {
            self.recovered.lock().unwrap().push(time);
            if self.fail_recovery {
                Err(anyhow!("database unavailable"))
            } else {
                Ok(2)
            }
        };
        Box::pin(std::future::ready(result))
    }
    fn claim_notification(&self, time: i64) -> StoreFuture<'_, Option<Notification>> {
        self.claims.lock().unwrap().push(time);
        let result = Ok(self.jobs.lock().unwrap().pop_front());
        Box::pin(std::future::ready(result))
    }
    fn finish_notification<'a>(
        &'a self,
        job: &'a Notification,
        state: &'a str,
        reason: Option<&'a str>,
        apns_id: Option<&'a str>,
        time: i64,
    ) -> StoreFuture<'a, ()> {
        let result = {
            self.completed.lock().unwrap().push(Completion {
                id: job.id,
                state: state.into(),
                reason: reason.map(str::to_owned),
                apns_id: apns_id.map(str::to_owned),
                time,
            });
            Ok(())
        };
        Box::pin(std::future::ready(result))
    }
}

struct FakePush {
    outcomes: Mutex<VecDeque<Result<PushOutcome>>>,
    sends: Mutex<Vec<(Vec<u8>, String)>>,
}
impl PushProvider for FakePush {
    fn send<'a>(&'a self, token: &'a [u8], magic: &'a str) -> PushFuture<'a> {
        Box::pin(async move {
            self.sends
                .lock()
                .unwrap()
                .push((token.to_vec(), magic.into()));
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected send")
        })
    }
}
fn notification(id: i64) -> Notification {
    Notification {
        id,
        enrollment_id: "enrollment".into(),
        token: vec![1, 2, 3],
        push_magic: "test-magic".into(),
        attempt: 1,
    }
}

#[tokio::test]
async fn scheduled_invocations_are_bounded_and_preserve_provider_results() {
    let store = FakeStore::default();
    store.jobs.lock().unwrap().extend((1..=4).map(notification));
    let push = FakePush {
        outcomes: Mutex::new(VecDeque::from([
            Ok(PushOutcome::Accepted {
                apns_id: Some("apple-request".into()),
            }),
            Ok(PushOutcome::Retry {
                reason: "ServiceUnavailable".into(),
            }),
            Ok(PushOutcome::Rejected {
                reason: "BadDeviceToken".into(),
            }),
            Err(anyhow!("transport contained confidential-token")),
        ])),
        sends: Mutex::new(Vec::new()),
    };
    for remaining in (0..=3).rev() {
        let result = tick(&store, Some(&push), &FixedClock).await.unwrap();
        assert_eq!(result.recovered_commands, 2);
        assert!(result.notification_attempted);
        assert_eq!(store.jobs.lock().unwrap().len(), remaining);
    }
    let results = store.completed.lock().unwrap();
    assert_eq!(
        results.iter().map(|r| r.state.as_str()).collect::<Vec<_>>(),
        ["accepted", "retry", "rejected", "retry"]
    );
    assert_eq!(results[0].apns_id.as_deref(), Some("apple-request"));
    assert_eq!(results[1].reason.as_deref(), Some("ServiceUnavailable"));
    assert_eq!(results[2].reason.as_deref(), Some("BadDeviceToken"));
    assert_eq!(results[3].reason.as_deref(), Some("transport_error"));
    assert!(results.iter().all(|r| r.time == 1234));
    assert_eq!(push.sends.lock().unwrap().len(), 4);
    assert_eq!(*store.claims.lock().unwrap(), vec![1234; 4]);
    drop(results);
    assert!(
        !tick(&store, Some(&push), &FixedClock)
            .await
            .unwrap()
            .notification_attempted
    );
    assert_eq!(push.sends.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn unconfigured_push_runs_recovery_without_leasing_notifications() {
    let store = FakeStore::default();
    store.jobs.lock().unwrap().push_back(notification(1));
    let result = tick(&store, None, &FixedClock).await.unwrap();
    assert_eq!(result.recovered_commands, 2);
    assert!(!result.notification_attempted);
    assert_eq!(store.jobs.lock().unwrap().len(), 1);
    assert!(store.claims.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unavailable_storage_prevents_external_push_side_effects() {
    let store = FakeStore {
        fail_recovery: true,
        ..FakeStore::default()
    };
    store.jobs.lock().unwrap().push_back(notification(1));
    let push = FakePush {
        outcomes: Mutex::new(VecDeque::new()),
        sends: Mutex::new(Vec::new()),
    };
    assert!(tick(&store, Some(&push), &FixedClock).await.is_err());
    assert!(push.sends.lock().unwrap().is_empty());
    assert!(store.claims.lock().unwrap().is_empty());
    assert_eq!(store.jobs.lock().unwrap().len(), 1);
}
