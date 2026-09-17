//! Where the scanners keep what they download between scans.
//!
//! All three of them cache under `$HOME` by default -- `~/.cache/trivy`,
//! `~/.cache/syft`, `~/.cache/grype/db` -- and the biggest of those is grype's
//! vulnerability database, a few hundred megabytes fetched over the network.
//! A service account has no home to speak of (FreeBSD gives `www`
//! `/nonexistent`, and a container image has no `$HOME` set at all), so with
//! nothing said about it grype either fails outright or refetches the whole
//! database on every scan, which is the one thing a scan cannot afford to
//! wait for.
//!
//! So the cache directory is the deployment's to name and this process'
//! to prepare: one root, created and proven writable at startup rather than
//! discovered to be neither halfway through the first scan, with a
//! subdirectory per scanner because the three lay their caches out
//! differently and grype in particular wants to be pointed at the database
//! directory itself.

use std::{
    io::ErrorKind,
    path::{
        Path,
        PathBuf,
    },
};

use eyre::{
    Context,
    Result,
};

/// The directories the scanner child processes are pointed at.
#[derive(Clone, Debug)]
pub(crate) struct ScannerCache {
    root: PathBuf,
    trivy: PathBuf,
    syft: PathBuf,
    grype_db: PathBuf,
}

impl ScannerCache {
    /// Prepares the cache under `root`, or under the first of the defaults
    /// that can be prepared when there is no `root`.
    ///
    /// A `root` that was asked for and cannot be used is an error: a
    /// deployment that names a directory has said where the cache belongs, and
    /// quietly putting it somewhere else -- somewhere that may not survive a
    /// reboot -- would turn a typo into a database refetched on every scan,
    /// which is exactly what naming it was meant to prevent.
    pub(crate) fn new(root: Option<PathBuf>) -> Result<Self> {
        if let Some(root) = root {
            return Self::prepare(root.clone()).with_context(|| {
                format!(
                    "failed to use {root} as the scanner cache",
                    root = root.display()
                )
            });
        }

        let candidates = default_roots();

        let mut last_error = None;

        for candidate in &candidates {
            match Self::prepare(candidate.clone()) {
                Ok(cache) => return Ok(cache),
                Err(err) => last_error = Some(err),
            }
        }

        let tried = candidates
            .iter()
            .map(|candidate| candidate.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");

        Err(last_error.unwrap_or_else(|| eyre::eyre!("there was nowhere to put the scanner cache")))
            .with_context(|| {
                format!(
                    "none of the default scanner cache directories could be used ({tried}), name \
                     one with --cache-dir"
                )
            })
    }

    /// The root, for logging: what a deployment most wants to know at startup
    /// is which directory it actually ended up with.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// `TRIVY_CACHE_DIR`.
    pub(crate) fn trivy(&self) -> &Path {
        &self.trivy
    }

    /// `SYFT_CACHE_DIR`.
    pub(crate) fn syft(&self) -> &Path {
        &self.syft
    }

    /// `GRYPE_DB_CACHE_DIR`, which is the database directory rather than a
    /// grype-wide cache root: grype's own default for it is
    /// `~/.cache/grype/db`, not `~/.cache/grype`.
    pub(crate) fn grype_db(&self) -> &Path {
        &self.grype_db
    }

    /// Creates the whole layout and checks that it can be written to.
    ///
    /// Creating is not enough on its own: the interesting failure is a
    /// directory that already exists because root made it and the service runs
    /// as `www`, where every `create_dir_all` succeeds and every scan then
    /// fails. Better to find that out here, with the name of the directory
    /// still in hand, than in a scanner's stderr.
    fn prepare(root: PathBuf) -> Result<Self> {
        let cache = Self {
            trivy: root.join("trivy"),
            syft: root.join("syft"),
            grype_db: root.join("grype").join("db"),
            root,
        };

        for directory in [&cache.root, &cache.trivy, &cache.syft, &cache.grype_db] {
            std::fs::create_dir_all(directory).with_context(|| {
                format!(
                    "failed to create {directory}",
                    directory = directory.display()
                )
            })?;

            writable(directory)?;
        }

        Ok(cache)
    }
}

/// Fails unless a file can be made in `directory` and taken away again.
fn writable(directory: &Path) -> Result<()> {
    // The pid keeps two instances sharing one cache directory -- which is a
    // thing a deployment may well do -- from taking each other's probe away
    // mid-check.
    let probe = directory.join(format!(
        ".trivy-web-writable-{pid}",
        pid = std::process::id()
    ));

    std::fs::write(&probe, []).with_context(|| {
        format!(
            "{directory} is not writable",
            directory = directory.display()
        )
    })?;

    // Removing it is best effort: a probe that was written is what was being
    // asked, and a leftover empty dotfile is not worth failing a startup over.
    if let Err(err) = std::fs::remove_file(&probe)
        && err.kind() != ErrorKind::NotFound
    {
        tracing::warn!(
            probe = %probe.display(),
            "failed to remove the cache writability probe: {err}"
        );
    }

    Ok(())
}

/// Where the cache goes when the deployment did not say, best first.
///
/// `$XDG_CACHE_HOME` and `$HOME` are what a person running this from a shell
/// expects and what the scanners themselves would have used. The temporary
/// directory is last and is not really a cache -- it is what is left when the
/// process has no home it can write to, and it at least holds the database
/// for as long as the machine is up instead of refetching it per scan. A
/// service is meant to be given a real directory with `--cache-dir`.
fn default_roots() -> Vec<PathBuf> {
    let mut roots = Vec::with_capacity(3);

    if let Some(xdg) = absolute_from_env("XDG_CACHE_HOME") {
        roots.push(xdg.join("trivy-web"));
    }

    if let Some(home) = absolute_from_env("HOME") {
        roots.push(home.join(".cache").join("trivy-web"));
    }

    roots.push(std::env::temp_dir().join("trivy-web"));

    roots
}

/// The value of `name`, if it is set to an absolute path.
///
/// Relative is thrown out rather than resolved: the working directory of a
/// service is not something to hang a cache off.
fn absolute_from_env(name: &str) -> Option<PathBuf> {
    let value = PathBuf::from(std::env::var_os(name)?);

    value.is_absolute().then_some(value)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "using unwrap in tests is fine")]
mod tests {
    use std::path::PathBuf;

    use super::ScannerCache;

    /// A unique directory under the temporary directory, without pulling in a
    /// crate for it.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "trivy-web-scanner-cache-{name}-{pid}",
            pid = std::process::id()
        ));

        let _ = std::fs::remove_dir_all(&path);

        path
    }

    #[test]
    fn the_layout_is_created_under_the_named_root() {
        let root = scratch("layout");

        let cache = ScannerCache::new(Some(root.clone())).unwrap();

        assert_eq!(cache.root(), root);
        assert_eq!(cache.trivy(), root.join("trivy"));
        assert_eq!(cache.syft(), root.join("syft"));

        // The database directory itself, the way grype's own default names it.
        assert_eq!(cache.grype_db(), root.join("grype").join("db"));

        for directory in [cache.trivy(), cache.syft(), cache.grype_db()] {
            assert!(directory.is_dir(), "{directory:?} was not created");
        }

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Being asked for a directory twice is the normal case: a restart finds
    /// the cache the last run left behind, which is the entire point.
    #[test]
    fn an_existing_cache_is_reused() {
        let root = scratch("existing");

        let first = ScannerCache::new(Some(root.clone())).unwrap();
        std::fs::write(first.grype_db().join("db.tar"), b"pretend database").unwrap();

        let second = ScannerCache::new(Some(root.clone())).unwrap();

        assert!(second.grype_db().join("db.tar").exists());

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A named directory that cannot be used fails startup instead of being
    /// swapped for somewhere the cache would not survive.
    #[test]
    fn a_named_root_that_cannot_be_used_is_an_error() {
        let root = scratch("unusable");

        // A file where the root should be: nothing can be created under it.
        std::fs::write(&root, b"not a directory").unwrap();

        let err = ScannerCache::new(Some(root.clone())).unwrap_err();

        assert!(
            format!("{err:#}").contains("as the scanner cache"),
            "{err:#}"
        );

        std::fs::remove_file(&root).unwrap();
    }

    /// With nothing named there is always somewhere to fall back to, so that
    /// a process with no usable home still caches for as long as it runs.
    #[test]
    fn without_a_named_root_there_is_still_a_cache() {
        let cache = ScannerCache::new(None).unwrap();

        assert!(cache.grype_db().is_dir(), "{cache:?}");
    }
}
