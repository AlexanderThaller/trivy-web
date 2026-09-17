//! The views the pages render.
//!
//! These replace the askama templates in `templates/`. Where a template used
//! `{% include %}` to paste a fragment into its caller's scope, a `view!` here
//! calls a component with named arguments, so each piece of markup says what
//! it needs.

pub(crate) mod format;
pub(crate) mod grype;
pub(crate) mod image;
pub(crate) mod layout;
pub(crate) mod scan;
pub(crate) mod shared;
pub(crate) mod syft;
pub(crate) mod trivy;
