fn main() {
    // Get the current Git commit hash
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("Failed to execute Git command");

    let git_commit = String::from_utf8(output.stdout).expect("Invalid UTF-8 in Git output");

    // Get the current build time
    let build_time = chrono::Utc::now().to_rfc3339();

    // Pass environment variables to the build
    println!("cargo:rustc-env=GIT_COMMIT={git_commit}");
    println!("cargo:rustc-env=BUILD_TIME={build_time}");

    // Pass crate version
    let crate_version = std::env::var("CARGO_PKG_VERSION").expect("Failed to get crate version");
    println!("cargo:rustc-env=CRATE_VERSION={crate_version}");
}
