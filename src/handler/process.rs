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
    process::Command,
    sync::Semaphore,
    time::timeout,
};
use tracing::{
    Instrument,
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

    /// Runs `command` to completion under the limits and collects its output.
    ///
    /// Fails without starting anything when no slot frees up in time, and
    /// fails with the child killed when it outruns the deadline or writes more
    /// than [`MAX_OUTPUT_BYTES`].
    pub(crate) async fn run(&self, command: &mut Command) -> Result<Output> {
        let _permit = timeout(self.queue_timeout, self.permits.acquire())
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

        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // What actually enforces the deadline below: the child is killed
            // when the future holding it is dropped. Nothing else would stop a
            // scan whose caller has long since gone away.
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn the process")?;

        let stdout = child.stdout.take().expect("stdout was piped above");
        let stderr = child.stderr.take().expect("stderr was piped above");

        timeout(self.run_timeout, async move {
            // Both pipes are drained while the child is waited on, not after
            // it exits: a child that fills a pipe buffer blocks until someone
            // reads it, and waiting first would hang for the whole deadline on
            // every report bigger than that buffer.
            let (stdout, stderr, status) = tokio::try_join!(
                read_limited(stdout, MAX_OUTPUT_BYTES, "stdout"),
                read_limited(stderr, MAX_OUTPUT_BYTES, "stderr"),
                async {
                    child
                        .wait()
                        .await
                        .context("failed to wait for the process to exit")
                },
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
