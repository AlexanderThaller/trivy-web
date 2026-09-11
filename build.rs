fn main() {
    // Get the current Git commit hash.
    //
    // Both failure modes are tolerated rather than fatal, because the Nix
    // build hits them: flake.nix's source filtering excludes .git (and Nix's
    // sandbox has no guarantee of a git binary either), so `git` either fails
    // to spawn or exits non-zero with empty stdout. Panicking there would
    // make `nix build` unbuildable for a string that only decorates the
    // /info page. Cargo builds still see a real hash.
    let git_commit = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or_else(|| "unknown".to_owned(), |hash| hash.trim().to_owned());

    // Get the current build time
    let build_time = chrono::Utc::now().to_rfc3339();

    // Pass environment variables to the build
    println!("cargo:rustc-env=GIT_COMMIT={git_commit}");
    println!("cargo:rustc-env=BUILD_TIME={build_time}");

    // Pass crate version
    let crate_version = std::env::var("CARGO_PKG_VERSION").expect("Failed to get crate version");
    println!("cargo:rustc-env=CRATE_VERSION={crate_version}");
}
