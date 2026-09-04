//! Limits on the external scanners the handlers start.
//!
//! Both scan endpoints are reachable without authentication and every request
//! that the cache cannot answer starts a child process, so without a ceiling a
//! handful of callers can keep the host running trivy for as long as they
//! like. Every child therefore goes through [`Limits::run`], which admits only
//! a fixed number of them at a time, turns a caller away rather than queueing
//! forever, kills a run that overruns its deadline and refuses to buffer more
//! output than [`MAX_OUTPUT_BYTES`].

use std::{
    num::NonZeroUsize,
    process::{
        ExitStatus,
        Output,
        Stdio,
    },
    sync::Arc,
    time::Duration,
};

use eyre::{
    Context,
    Result,
};
use tokio::{
    io::{
        AsyncRead,
        AsyncReadExt,
    },
    process::{
        Child,
        Command,
    },
    runtime::Handle,
    sync::{
        OwnedSemaphorePermit,
        Semaphore,
    },
    time::timeout,
};
use tracing::{
    Instrument,
    error,
    info_span,
};

/// How much a single run may write to each of stdout and stderr before it is
/// killed.
///
/// A trivy report for a large image is a few megabytes of json, so this is far
/// above anything a scan produces in practice: it is here to keep a runaway
/// process from being buffered into memory, not to bound reports.
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// The ceiling the scan handlers run their child processes under.
///
/// One instance is shared by every handler, so the bound is on the processes
/// this server has running in total rather than per endpoint.
#[derive(Clone, Debug)]
pub(crate) struct Limits {
    /// One permit per running child process.
    permits: Arc<Semaphore>,

    /// How long a caller waits for a permit before it is turned away.
    queue_timeout: Duration,

    /// How long a single child may run before it is killed.
    run_timeout: Duration,
}

impl Limits {
    pub(crate) fn new(
        max_concurrent: NonZeroUsize,
        queue_timeout: Duration,
        run_timeout: Duration,
    ) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent.get())),
            queue_timeout,
            run_timeout,
        }
    }

    /// The longest one [`Limits::run`] can take: the wait for a free slot plus
    /// the deadline of the run itself.
    ///
    /// What anything waiting on a run has to bound its own waiting by.
    pub(crate) fn max_duration(&self) -> Duration {
        self.queue_timeout.saturating_add(self.run_timeout)
    }

    /// Runs `command` to completion under the limits and collects its output.
    ///
    /// Fails without starting anything when no slot frees up in time, and
    /// fails with the child killed when it outruns the deadline or writes more
    /// than [`MAX_OUTPUT_BYTES`].
    pub(crate) async fn run(&self, command: &mut Command) -> Result<Output> {
        let permit = timeout(self.queue_timeout, self.permits.clone().acquire_owned())
            .instrument(info_span!("wait for a scan slot"))
            .await
            .map_err(|_elapsed| {
                eyre::eyre!(
                    "too many scans are already running, no slot became free within {seconds} \
                     seconds, please try again in a moment",
                    seconds = self.queue_timeout.as_secs()
                )
            })?
            .context("the scan slots are gone, the server is shutting down")?;

        let child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The backstop for a drop that has no runtime left to reap on, see
            // the Drop of Running below.
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn the process")?;

        // The slot travels with the child from here on, and comes back only
        // once the child is gone.
        let mut running = Running::new(child, permit);

        let stdout = running
            .child()
            .stdout
            .take()
            .expect("stdout was piped above");
        let stderr = running
            .child()
            .stderr
            .take()
            .expect("stderr was piped above");

        timeout(self.run_timeout, async {
            // Both pipes are drained while the child is waited on, not after
            // it exits: a child that fills a pipe buffer blocks until someone
            // reads it, and waiting first would hang for the whole deadline on
            // every report bigger than that buffer.
            let (stdout, stderr, status) = tokio::try_join!(
                read_limited(stdout, MAX_OUTPUT_BYTES, "stdout"),
                read_limited(stderr, MAX_OUTPUT_BYTES, "stderr"),
                running.wait(),
            )?;

            Ok::<_, eyre::Error>(Output {
                status,
                stdout,
                stderr,
            })
        })
        .await
        .map_err(|_elapsed| {
            eyre::eyre!(
                "the scan was killed after running for more than {seconds} seconds",
                seconds = self.run_timeout.as_secs()
            )
        })?
    }
}

/// A running child and the scan slot it occupies.
///
/// The slot comes back when this is dropped, and not before the child is gone:
/// `kill_on_drop` only signals a process, and one that has been signalled but
/// not yet reaped is still a process on the host, so handing its slot to the
/// next scan would put one more of them on the machine than the limit says.
/// Reaping has to be waited for and a [`Drop`] cannot wait, so a dropped one
/// hands the child to a task that holds the slot until it has.
struct Running {
    /// Taken once the child has been reaped, which is what tells the [`Drop`]
    /// there is nothing left to do.
    child: Option<Child>,

    permit: Option<OwnedSemaphorePermit>,
}

impl Running {
    fn new(child: Child, permit: OwnedSemaphorePermit) -> Self {
        Self {
            child: Some(child),
            permit: Some(permit),
        }
    }

    fn child(&mut self) -> &mut Child {
        self.child
            .as_mut()
            .expect("the child is only taken once it has been waited for")
    }

    /// Waits for the child to exit, which reaps it.
    async fn wait(&mut self) -> Result<ExitStatus> {
        let status = self
            .child()
            .wait()
            .await
            .context("failed to wait for the process to exit")?;

        self.child = None;

        Ok(status)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let (Some(mut child), Some(permit)) = (self.child.take(), self.permit.take()) else {
            // Waited for already: nothing to kill, and the slot goes back with
            // the permit dropped here.
            return;
        };

        let Ok(handle) = Handle::try_current() else {
            // Nothing left to spawn on, which is the runtime shutting down and
            // taking the process with it. `kill_on_drop` still signals the
            // child on the way out.
            return;
        };

        // Holds the slot for as long as the killing takes, so that the scan
        // this one is making room for cannot start while it is still there.
        handle.spawn(async move {
            let _permit = permit;

            if let Err(err) = child.kill().await {
                error!("failed to kill the scan that was given up on: {err}");
            }
        });
    }
}

/// Reads `reader` to its end, giving up instead of buffering more than `limit`
/// bytes.
async fn read_limited<R>(reader: R, limit: usize, name: &'static str) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    // One byte past the limit is read so output that exactly fits can be told
    // apart from output that was cut short.
    let read_at_most = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);

    let mut buffer = Vec::new();

    reader
        .take(read_at_most)
        .read_to_end(&mut buffer)
        .await
        .with_context(|| format!("failed to read the process {name}"))?;

    if buffer.len() > limit {
        return Err(eyre::eyre!(
            "the process wrote more than {limit} bytes to {name}"
        ));
    }

    Ok(buffer)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
mod tests {
    use std::{
        num::NonZeroUsize,
        time::Duration,
    };

    use tokio::{
        process::Command,
        time::Instant,
    };

    use super::{
        Limits,
        read_limited,
    };

    fn limits(max_concurrent: usize, queue_timeout_ms: u64, run_timeout_ms: u64) -> Limits {
        Limits::new(
            NonZeroUsize::new(max_concurrent).unwrap(),
            Duration::from_millis(queue_timeout_ms),
            Duration::from_millis(run_timeout_ms),
        )
    }

    #[tokio::test]
    async fn output_is_collected() {
        let got = limits(1, 1_000, 10_000)
            .run(Command::new("echo").arg("hello"))
            .await
            .unwrap();

        assert!(got.status.success());
        assert_eq!(b"hello\n".as_slice(), got.stdout.as_slice());
    }

    /// A scan that never finishes has to be killed rather than held onto for
    /// as long as the caller is willing to wait.
    #[tokio::test]
    async fn a_run_past_the_deadline_is_killed() {
        let started = Instant::now();

        let err = limits(1, 1_000, 200)
            .run(Command::new("sleep").arg("60"))
            .await
            .unwrap_err();

        assert!(
            format!("{err}").contains("killed after running for more than"),
            "{err}"
        );

        assert!(started.elapsed() < Duration::from_secs(30), "{started:?}");
    }

    /// The point of the whole module: the number of scans running at once is
    /// bounded, and a caller that finds no free slot is turned away instead of
    /// piling up behind the ones already running.
    #[tokio::test]
    async fn a_caller_without_a_free_slot_is_turned_away() {
        let limits = limits(1, 0, 10_000);

        let running = {
            let limits = limits.clone();

            tokio::spawn(async move { limits.run(Command::new("sleep").arg("60")).await })
        };

        // Long enough for the spawned scan to have taken the only permit.
        while limits.permits.available_permits() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let err = limits
            .run(Command::new("echo").arg("hello"))
            .await
            .unwrap_err();

        assert!(
            format!("{err}").contains("too many scans are already running"),
            "{err}"
        );

        running.abort();
    }

    /// A caller that goes away mid-scan has to take the scan with it: the
    /// child is killed and, what the next caller needs, the slot it held comes
    /// back.
    #[tokio::test]
    async fn a_dropped_run_frees_its_slot() {
        let limits = limits(1, 1_000, 10_000);

        // Runs long enough to still hold the slot when the timeout drops the
        // whole run, which is what a caller hanging up looks like from here.
        let gone_away = tokio::time::timeout(
            Duration::from_millis(200),
            limits.run(Command::new("sleep").arg("60")),
        )
        .await;

        assert!(gone_away.is_err(), "the run was supposed to be dropped");

        limits
            .run(Command::new("echo").arg("hello"))
            .await
            .expect("the slot should come back");
    }

    /// The slot is not free the moment the killing starts, it is free once the
    /// killing is done: a child that has been signalled but not yet reaped is
    /// still a process, and letting the next scan start next to it would put
    /// one more on the machine than the limit allows.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_slot_comes_back_only_once_the_child_is_reaped() {
        use std::{
            path::Path,
            sync::Arc,
        };

        use tokio::sync::Semaphore;

        use super::Running;

        let permits = Arc::new(Semaphore::new(1));
        let permit = permits.clone().acquire_owned().await.unwrap();

        let child = Command::new("sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let pid = child.id().expect("the child was just spawned");

        // What a caller hanging up leaves behind.
        drop(Running::new(child, permit));

        let waited = tokio::time::timeout(Duration::from_secs(5), permits.acquire()).await;
        assert!(waited.is_ok(), "the slot never came back");

        // /proc keeps an entry for a process that has exited until it is
        // reaped, so this is gone only if the killing was seen through.
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "the child was still there when its slot was handed on"
        );
    }

    #[tokio::test]
    async fn output_past_the_limit_is_refused() {
        let err = read_limited(b"0123456789".as_slice(), 4, "stdout")
            .await
            .unwrap_err();

        assert!(
            format!("{err}").contains("wrote more than 4 bytes to stdout"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn output_up_to_the_limit_is_kept() {
        let got = read_limited(b"0123".as_slice(), 4, "stdout").await.unwrap();

        assert_eq!(b"0123".as_slice(), got.as_slice());
    }
}
