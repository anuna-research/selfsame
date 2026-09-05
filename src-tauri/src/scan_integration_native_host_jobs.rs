//! Test-only ownership for one background native continuation.
//!
//! The host process keeps the result until the exact attempt and job tags poll
//! it. Dropping the async wrapper is not treated as stopping the blocking
//! native command: teardown separately observes the actual session worker
//! lease before allowing process-local custody to be cleared.

use super::*;
use std::{
    future::Future,
    sync::mpsc::{self, Receiver, TryRecvError},
    time::{Duration, Instant},
};

const DRAIN_BOUND: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StartContinueLink {
    #[serde(deserialize_with = "opaque_tag")]
    pub(super) attempt_tag: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PollContinueLink {
    #[serde(deserialize_with = "opaque_tag")]
    pub(super) attempt_tag: String,
    #[serde(deserialize_with = "opaque_tag")]
    pub(super) job_id: String,
}

fn opaque_tag<'de, D: serde::Deserializer<'de>>(input: D) -> std::result::Result<String, D::Error> {
    let value = String::deserialize(input)?;
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(serde::de::Error::custom("HostJobRefused"));
    }
    Ok(value)
}

type JobResult = std::result::Result<Value, &'static str>;

struct ContinueLinkJob {
    attempt_tag: String,
    job_id: String,
    receiver: Receiver<JobResult>,
    task: tauri::async_runtime::JoinHandle<()>,
    cancelled: bool,
}

#[derive(Default)]
pub(super) struct NativeHostJobs {
    continuation: Option<ContinueLinkJob>,
}

impl NativeHostJobs {
    pub(super) fn occupied(&self) -> bool {
        self.continuation.is_some()
    }

    pub(super) fn matches_attempt(&self, attempt_tag: &str) -> bool {
        self.continuation
            .as_ref()
            .is_some_and(|job| job.attempt_tag == attempt_tag)
    }

    pub(super) fn require_poll(&self, request: &PollContinueLink) -> Result<()> {
        let job = self
            .continuation
            .as_ref()
            .ok_or_else(|| UiError::from("HostJobMissing"))?;
        if job.attempt_tag != request.attempt_tag || job.job_id != request.job_id {
            return Err(UiError::from("HostJobRefused"));
        }
        Ok(())
    }

    pub(super) fn start<F>(&mut self, attempt_tag: String, future: F) -> Result<Value>
    where
        F: Future<Output = Result<Value>> + Send + 'static,
    {
        if self.continuation.is_some() {
            return Err(UiError::from("HostJobOccupied"));
        }
        let mut random = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let job_id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let (sender, receiver) = mpsc::sync_channel(1);
        let task = tauri::async_runtime::spawn(async move {
            let result = future.await.map_err(|error| error_category(&error));
            let _ = sender.send(result);
        });
        self.continuation = Some(ContinueLinkJob {
            attempt_tag,
            job_id: job_id.clone(),
            receiver,
            task,
            cancelled: false,
        });
        Ok(json!({"state":"started", "jobId":job_id}))
    }

    pub(super) fn mark_cancelled(&mut self, attempt_tag: &str) -> Result<()> {
        let job = self
            .continuation
            .as_mut()
            .ok_or_else(|| UiError::from("HostJobMissing"))?;
        if job.attempt_tag != attempt_tag {
            return Err(UiError::from("HostJobRefused"));
        }
        job.cancelled = true;
        Ok(())
    }

    pub(super) fn poll(&mut self, request: PollContinueLink, work_active: bool) -> Result<Value> {
        self.require_poll(&request)?;
        let job = self.continuation.as_ref().expect("poll binding checked");
        match job.receiver.try_recv() {
            Err(TryRecvError::Empty) => Ok(json!({"state":"pending", "workActive":work_active})),
            result => {
                let command = match result {
                    Ok(Ok(result)) => json!({"ok":true, "result":result}),
                    Ok(Err(error)) => json!({"ok":false, "error":error}),
                    Err(TryRecvError::Disconnected) => {
                        json!({"ok":false, "error":"HostCommandRefused"})
                    }
                    Err(TryRecvError::Empty) => unreachable!("handled above"),
                };
                let finished = if job.cancelled {
                    json!({
                        "state":"finished", "ok":false, "error":"PairingCancelled",
                        "cancellation":"confirmed", "command":command
                    })
                } else {
                    if command["ok"] == true {
                        json!({
                            "state":"finished", "ok":true,
                            "result":command.get("result").cloned().expect("successful command")
                        })
                    } else {
                        json!({
                            "state":"finished", "ok":false,
                            "error":command.get("error").cloned().expect("failed command")
                        })
                    }
                };
                self.continuation = None;
                Ok(finished)
            }
        }
    }

    pub(super) async fn teardown(&mut self, app: &tauri::AppHandle<MockRuntime>) -> Result<()> {
        app.state::<AppSession>()
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .revoke_cbcl_v2();
        let Some(job) = self.continuation.as_mut() else {
            return Ok(());
        };

        if tokio::time::timeout(DRAIN_BOUND, &mut job.task)
            .await
            .is_err()
        {
            job.task.abort();
            if tokio::time::timeout(DRAIN_BOUND, &mut job.task)
                .await
                .is_err()
            {
                return Err(UiError::from("HostJobDrainFailed"));
            }
        }

        let deadline = Instant::now() + DRAIN_BOUND;
        loop {
            let active = app
                .state::<AppSession>()
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .cbcl_v2_attempts
                .tagged_worker_active(&job.attempt_tag)?;
            if !active {
                self.continuation = None;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(UiError::from("HostJobDrainFailed"));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_id_grammar_is_closed() {
        for value in [
            "0000000000000000000000000000000",
            "000000000000000000000000000000000",
            "0000000000000000000000000000000g",
            "0000000000000000000000000000000A",
        ] {
            let raw = format!(r#"{{"attemptTag":"a","jobId":"{value}"}}"#);
            assert!(serde_json::from_str::<PollContinueLink>(&raw).is_err());
        }
        assert!(serde_json::from_str::<PollContinueLink>(
            r#"{"attemptTag":"a","jobId":"00000000000000000000000000000000","extra":1}"#
        )
        .is_err());
    }

    #[tokio::test]
    async fn retained_job_requires_both_tags_and_drains_once() {
        let mut jobs = NativeHostJobs::default();
        let started = jobs
            .start("attempt-a".into(), async {
                Ok(json!({"phase":"await-receipt"}))
            })
            .unwrap();
        let job_id = started["jobId"].as_str().unwrap().to_owned();
        assert!(jobs
            .start("attempt-a".into(), async { Ok(Value::Null) })
            .is_err());
        assert!(jobs
            .poll(
                PollContinueLink {
                    attempt_tag: "attempt-b".into(),
                    job_id: job_id.clone(),
                },
                false,
            )
            .is_err());
        assert!(jobs.occupied());
        assert!(jobs
            .poll(
                PollContinueLink {
                    attempt_tag: "attempt-a".into(),
                    job_id: "11111111111111111111111111111111".into(),
                },
                false,
            )
            .is_err());
        assert!(jobs.occupied());

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let result = jobs
                .poll(
                    PollContinueLink {
                        attempt_tag: "attempt-a".into(),
                        job_id: job_id.clone(),
                    },
                    false,
                )
                .unwrap();
            if result["state"] == "finished" {
                assert_eq!(result["ok"], true);
                assert_eq!(result["result"]["phase"], "await-receipt");
                break;
            }
            assert!(Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        assert!(!jobs.occupied());
        assert!(jobs
            .poll(
                PollContinueLink {
                    attempt_tag: "attempt-a".into(),
                    job_id,
                },
                false,
            )
            .is_err());
    }

    #[tokio::test]
    async fn cancellation_overrides_a_retained_success_result() {
        let mut jobs = NativeHostJobs::default();
        let attempt_tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let started = jobs
            .start(attempt_tag.into(), async {
                Ok(json!({"phase":"await-receipt"}))
            })
            .unwrap();
        let job_id = started["jobId"].as_str().unwrap().to_owned();
        jobs.mark_cancelled(attempt_tag).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let result = jobs
                .poll(
                    PollContinueLink {
                        attempt_tag: attempt_tag.into(),
                        job_id: job_id.clone(),
                    },
                    false,
                )
                .unwrap();
            if result["state"] == "finished" {
                assert_eq!(result["ok"], false);
                assert_eq!(result["error"], "PairingCancelled");
                assert!(result.get("result").is_none());
                assert_eq!(result["cancellation"], "confirmed");
                assert_eq!(result["command"]["ok"], true);
                assert_eq!(result["command"]["result"]["phase"], "await-receipt");
                break;
            }
            assert!(Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        assert!(!jobs.occupied());
    }
}
