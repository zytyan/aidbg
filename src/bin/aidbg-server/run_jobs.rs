use aidbg::{
    breakpoint::Control,
    run::{RunControl, RunObservation, RunResult},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use tonic::Status;

const RETENTION: Duration = Duration::from_secs(600);
const MAX_JOBS: usize = 64;

#[derive(Default)]
pub(super) struct RunJobs(Mutex<BTreeMap<String, Arc<Job>>>);

#[derive(Default)]
struct State {
    pid: Option<i32>,
    outcome: Option<(Instant, std::result::Result<RunResult, Status>)>,
}

pub(super) struct Job {
    pub cancelled: Arc<AtomicBool>,
    observations: mpsc::SyncSender<RunObservation>,
    breakpoints: Control,
    paused: Arc<AtomicBool>,
    ready: tokio::sync::Notify,
    state: Mutex<State>,
}

impl RunJobs {
    pub fn list(&self) -> Result<Value, Status> {
        let jobs = self.0.lock().map_err(super::internal)?;
        let mut rows = Vec::new();
        for (id, job) in jobs.iter() {
            let state = job.state.lock().map_err(super::internal)?;
            if state
                .outcome
                .as_ref()
                .is_some_and(|(end, _)| end.elapsed() >= RETENTION)
            {
                continue;
            }
            drop(state);
            let mut row = job.document(id, false)?;
            row.as_object_mut().unwrap().remove("result");
            rows.push(row);
        }
        Ok(json!({"runs": rows}))
    }

    pub fn live_controls(&self) -> Result<Vec<(i32, Control)>, Status> {
        let jobs = self.0.lock().map_err(super::internal)?;
        Ok(jobs.values().filter_map(|job| job.target().ok()).collect())
    }

    pub fn reserve(&self) -> Result<(String, Arc<Job>, RunControl), Status> {
        let mut jobs = self.0.lock().map_err(super::internal)?;
        jobs.retain(|_, job| {
            job.state.lock().is_ok_and(|state| {
                state
                    .outcome
                    .as_ref()
                    .is_none_or(|(finished, _)| finished.elapsed() < RETENTION)
            })
        });
        if jobs.len() == MAX_JOBS {
            return Err(Status::resource_exhausted(
                "detached run retention limit reached",
            ));
        }
        let path = tempfile::Builder::new()
            .prefix("run-")
            .rand_bytes(24)
            .tempfile()
            .map_err(super::internal)?;
        let id = path
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let (observations, receiver) = mpsc::sync_channel(1);
        let (breakpoints, commands) = Control::channel();
        let paused = Arc::new(AtomicBool::new(false));
        let job = Arc::new(Job {
            cancelled: Arc::new(AtomicBool::new(false)),
            observations,
            breakpoints,
            paused: paused.clone(),
            ready: tokio::sync::Notify::new(),
            state: Mutex::default(),
        });
        jobs.insert(id.clone(), Arc::clone(&job));
        Ok((
            id,
            job,
            RunControl {
                observations: receiver,
                breakpoints: commands,
                paused,
            },
        ))
    }

    pub fn get(&self, id: &str) -> Result<Arc<Job>, Status> {
        let jobs = self.0.lock().map_err(super::internal)?;
        let job = jobs.get(id).ok_or_else(unknown_run)?;
        if job
            .state
            .lock()
            .map_err(super::internal)?
            .outcome
            .as_ref()
            .is_some_and(|(finished, _)| finished.elapsed() >= RETENTION)
        {
            return Err(unknown_run());
        }
        Ok(Arc::clone(job))
    }

    pub fn control_for_pid(&self, pid: i32) -> Result<Option<Control>, Status> {
        let jobs = self.0.lock().map_err(super::internal)?;
        for job in jobs.values() {
            let state = job.state.lock().map_err(super::internal)?;
            if state.pid == Some(pid) && state.outcome.is_none() {
                return Ok(Some(job.breakpoints.clone()));
            }
        }
        Ok(None)
    }
}

impl Drop for RunJobs {
    fn drop(&mut self) {
        let jobs = self
            .0
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for job in jobs.values() {
            job.cancelled.store(true, Ordering::Relaxed);
        }
    }
}

fn unknown_run() -> Status {
    super::script_error(
        aidbg::Diagnostic::new("RUN_GONE", "Run ID is unknown or expired", None).into(),
    )
}

impl Job {
    pub fn launched(&self, pid: i32, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
        if let Ok(mut state) = self.state.lock() {
            state.pid = Some(pid);
        }
        self.ready.notify_one();
    }

    pub fn finish(&self, result: Result<RunResult, Status>) {
        if let Ok(mut state) = self.state.lock() {
            state.outcome = Some((Instant::now(), result));
        }
        self.ready.notify_one();
    }

    pub async fn wait_ready(&self) {
        self.ready.notified().await;
    }

    pub fn target(&self) -> Result<(i32, Control), Status> {
        let state = self.state.lock().map_err(super::internal)?;
        match state.pid {
            Some(pid) if state.outcome.is_none() => Ok((pid, self.breakpoints.clone())),
            _ => Err(Status::failed_precondition("run has no live target")),
        }
    }

    pub fn document(&self, id: &str, cancel: bool) -> Result<Value, Status> {
        let state = self.state.lock().map_err(super::internal)?;
        if cancel && state.outcome.is_none() {
            self.cancelled.store(true, Ordering::Relaxed);
        }
        let (status, result, issue) = match &state.outcome {
            Some((_, Ok(result))) => ("finished", Some(result), None),
            Some((_, Err(error))) if error.code() == tonic::Code::Cancelled => {
                ("cancelled", None, Some(error.message()))
            }
            Some((_, Err(error))) => ("failed", None, Some(error.message())),
            None if self.paused.load(Ordering::Relaxed) => ("paused", None, None),
            None if state.pid.is_some() => ("running", None, None),
            None => ("starting", None, None),
        };
        Ok(json!({
            "run_id": id, "pid": state.pid, "status": status, "result": result, "issue": issue,
            "cancel_requested": self.cancelled.load(Ordering::Relaxed),
        }))
    }

    fn observe(&self, observation: RunObservation) -> Result<(), Status> {
        self.observations
            .try_send(observation)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    Status::resource_exhausted("a run command is already pending")
                }
                mpsc::TrySendError::Disconnected(_) => unknown_run(),
            })
    }

    pub async fn snapshot(&self, mode: aidbg::rpc::FreezeMode) -> Result<aidbg::Snapshot, Status> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.observe(RunObservation::Snapshot { mode, reply })?;
        wait_response(response).await
    }

    pub async fn set_paused(&self, paused: bool) -> Result<(), Status> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.observe(RunObservation::SetPaused { paused, reply })?;
        wait_response(response)
            .await?
            .map_err(|e| Status::failed_precondition(e.to_string()))
    }
}

async fn wait_response<T>(response: tokio::sync::oneshot::Receiver<T>) -> Result<T, Status> {
    tokio::time::timeout(Duration::from_secs(2), response)
        .await
        .map_err(|_| Status::deadline_exceeded("run command timed out"))?
        .map_err(|_| unknown_run())
}
