//! Where a running scan has got to, for the page that is waiting on it.
//!
//! A scan can spend most of its time waiting rather than scanning: behind
//! another request's scan of the same image, or for one of the few scan slots
//! [`Limits`](super::Limits) hands out. From the outside all of that looks
//! like the same spinner. The scan reports each wait here as it enters it, and
//! the Vulnerabilities card reads it back to say which one it is.

use tokio::sync::watch;

/// One step of a scan, in the order a scan goes through them. Any of the
/// waits can be skipped: a cached result goes straight from [`Stage::Starting`]
/// to [`Stage::Finished`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Asked for, and looking for an earlier result in the cache.
    Starting,

    /// Another request is already scanning the same image. This one waits for
    /// that scan and reads what it caches instead of running a second one.
    WaitingForSameImage,

    /// Waiting for one of the scan slots, all of which are taken.
    WaitingForSlot,

    /// The scanner is running.
    Scanning,

    Finished,

    Failed,
}

impl Stage {
    /// Whether the scan is over, one way or the other.
    pub(crate) fn has_ended(self) -> bool {
        matches!(self, Self::Finished | Self::Failed)
    }
}

/// The sending side of one scan's [`Stage`].
///
/// Reporting never fails and never waits: a stage nobody is watching is
/// simply dropped, which is what every caller that does not render progress
/// -- a test, say -- relies on.
#[derive(Debug)]
pub(crate) struct Progress(watch::Sender<Stage>);

impl Progress {
    pub(crate) fn set(&self, stage: Stage) {
        self.0.send_replace(stage);
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Stage> {
        self.0.subscribe()
    }
}

impl Default for Progress {
    fn default() -> Self {
        Self(watch::Sender::new(Stage::Starting))
    }
}
