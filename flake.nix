{
  description = "trivy-web -- built binary and the container image it ships in";

  inputs = {
    # unstable, not a stable release channel: trivy and cosign are security
    # tools, and this flake exists specifically so the image can track
    # current releases of both without hand-fetching and checksumming a
    # binary for every bump (see publish-image.yml history for what that
    # looked like before).
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    # The pinned Rust toolchain this repo already commits to in
    # rust-toolchain.toml (1.98.1) -- nixpkgs' own rustc lags behind
    # (1.97.1 even on this unstable channel; edition 2024 needs 1.98+ --
    # this project's own MSRV). `fenix.packages.${system}.fromToolchainFile`
    # reads that same file, so the version lives in exactly one place.
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      fenix,
    }:
    let
      # x86_64-linux only, matching crate.from_cargo's platform_triples in
      # MODULE.bazel: a second architecture needs cross-compiling the Rust
      # binary too, not just a second nixpkgs platform.
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      toolchain = fenix.packages.${system}.fromToolchainFile {
        file = ./rust-toolchain.toml;
        sha256 = "sha256-p8h3Sl/YRByZfZTAKXdsvF6xEenXKrXSVvpphmZENH4=";
      };

      rustPlatform = pkgs.makeRustPlatform {
        cargo = toolchain;
        rustc = toolchain;
      };

      trivy-web = rustPlatform.buildRustPackage {
        pname = "trivy-web";
        version = "0.1.0";

        # Nix copies `src` into the build sandbox as-is; without filtering,
        # that includes target/ (a symlink into a local build-cache
        # directory that does not exist inside the sandbox -- cargo fails
        # trying to create a directory through it) and the various
        # bazel-* convenience symlinks, none of which are inputs.
        src = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.difference ./. (
            pkgs.lib.fileset.unions (
              map pkgs.lib.fileset.maybeMissing [
                ./target
                ./bazel-bin
                ./bazel-out
                ./bazel-testlogs
                ./bazel-trivy-web
                ./.git
              ]
            )
          );
        };

        # docker-registry-client (and every other non-crates.io dependency
        # here) is published to a private registry, not crates.io or git --
        # cargoLock.lockFile vendors it correctly anyway, reading the same
        # .cargo/config.toml registry replacement Cargo itself does.
        cargoLock.lockFile = ./Cargo.lock;

        # [profile.deploy] in Cargo.toml: LTO, one codegen unit,
        # panic=abort -- the same profile the Dockerfile builds with.
        buildType = "deploy";

        # Covered by `bazel test //...` already; the tests needing a
        # reachable registry or a local redis have no route to either
        # inside Nix's sandboxed build (no network access outside of
        # fixed-output derivations), so they are not run a third way here.
        doCheck = false;

        meta.mainProgram = "trivy-web";
      };

      # cosign_verify's `cosign verify --key` subprocess and trivy image
      # scanning both need their own binary on PATH; nixpkgs already
      # packages both, so there is nothing to fetch or checksum by hand
      # here the way MODULE.bazel used to.
      image = pkgs.dockerTools.buildLayeredImage {
        name = "trivy-web";
        tag = "latest";
        contents = [
          trivy-web
          pkgs.trivy
          pkgs.cosign
          pkgs.cacert
        ];

        # sigstore's trust-root fetch (see SigstoreTrustRoot in
        # src/handler/cosign.rs) needs somewhere to stage a temp directory;
        # buildLayeredImage does not create /tmp on its own.
        extraCommands = ''
          mkdir -m 1777 -p tmp
        '';

        config = {
          Entrypoint = [ "${trivy-web}/bin/trivy-web" ];
          ExposedPorts = {
            "16223/tcp" = { };
          };
          Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
        };
      };
    in
    {
      packages.${system} = {
        inherit trivy-web image;
        default = trivy-web;
      };
    };
}
