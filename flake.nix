{
  description = "trivy-web -- built binary and the container image it ships in";

  inputs = {
    # unstable, not a stable release channel: trivy is a security tool, and
    # this flake exists specifically so the image can track its current
    # releases without hand-fetching and checksumming a binary for every
    # bump (see publish-image.yml history for what that looked like
    # before).
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

      # fenix's fixed-output hash of the release channel's manifest; the same
      # manifest lists the musl standard library below, so one hash covers
      # both.
      channelSha256 = "sha256-p8h3Sl/YRByZfZTAKXdsvF6xEenXKrXSVvpphmZENH4=";

      # The channel from rust-toolchain.toml, read rather than repeated, so
      # a version bump there is the whole bump: fromToolchainFile reads the
      # same file for the host toolchain.
      channel = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain.channel;

      # The pinned toolchain, plus that same version's standard library for
      # x86_64-unknown-linux-musl. Only rust-std, not a second rustc: the
      # host compiler emits musl code fine once it has a std to link.
      toolchain = fenix.packages.${system}.combine [
        (fenix.packages.${system}.fromToolchainFile {
          file = ./rust-toolchain.toml;
          sha256 = channelSha256;
        })
        (fenix.packages.${system}.targets.x86_64-unknown-linux-musl.toolchainOf {
          inherit channel;
          sha256 = channelSha256;
        }).rust-std
      ];

      # pkgsStatic: builds for x86_64-unknown-linux-musl with static linking,
      # so the shipped trivy-web is one self-contained ELF with no libc in
      # its closure -- what let glibc (35 MB unpacked, mostly locale data
      # nothing here reads) drop out of the image. The C in the dependency
      # tree (aws-lc, ring, mimalloc) all builds against musl without
      # patching; mimalloc's `override` feature (see Cargo.toml) keeps
      # musl's own allocator out of the binary too.
      rustPlatform = pkgs.pkgsStatic.makeRustPlatform {
        cargo = toolchain;
        rustc = toolchain;
      };

      # rustfmt pinned to a nightly separately from rustc, the same split
      # the old Bazel toolchain kept. Every option in .rustfmt.toml --
      # imports_granularity, imports_layout, format_strings and the rest --
      # is unstable, so stable rustfmt prints "can't set X, unstable
      # features are only available in nightly channel" for each and then
      # formats with the defaults, which is not what's actually committed.
      # This nightly is only ever used for its rustfmt; devShell still
      # builds, tests and lints with the pinned stable toolchain above.
      nightlyRustfmt =
        (fenix.packages.${system}.toolchainOf {
          channel = "nightly";
          date = "2026-07-14";
          sha256 = "sha256-Vo4TslYYA7ldRP9vocgb0Y3c8PvcRcHipKArlRXq9xY=";
        }).rustfmt;

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

        # `strip -s` on the binary rather than the default `strip -S`, which
        # only takes the debug sections and left .symtab/.strtab -- about 2 MB
        # nothing reads, since panic=abort never prints a backtrace -- in the
        # shipped binary. The Cargo profile's own `strip` setting cannot do
        # this: nixpkgs' cargo build hook overrides it with
        # CARGO_PROFILE_<type>_STRIP=false to leave stripping to this phase.
        stripAllList = [ "bin" ];

        # Covered by CI's own `cargo test` step (see nix.yml) instead: the
        # tests needing a reachable registry or a local redis have no route
        # to either inside Nix's sandboxed build (no network access outside
        # of fixed-output derivations), so running them here would just be
        # the same failure this session already hit once, packaged instead
        # of fixed.
        doCheck = false;

        meta.mainProgram = "trivy-web";
      };

      # trivy image scanning needs the trivy binary on PATH; nixpkgs already
      # packages it, so there is nothing to fetch or checksum by hand here
      # the way MODULE.bazel used to. Built with cgo off: nixpkgs' default
      # build links it against glibc through cgo, and that build also
      # carries 85 MB more code than the pure-Go one (253 MB vs 168 MB on
      # disk, 79 MB vs 50 MB compressed). With cgo off it is a static binary
      # that uses Go's own resolver and TLS, which is how trivy's official
      # image ships it. `old.env //` rather than a fresh set: the package
      # keeps its GOEXPERIMENT there, and dropping it breaks the build.
      #
      # Not in the public binary cache, so CI compiles it -- about a minute
      # here, and only again when nixpkgs bumps trivy.
      trivy = pkgs.trivy.overrideAttrs (old: {
        env = old.env // {
          CGO_ENABLED = 0;
        };
      });

      # syft and grype, the other two scanners a scan runs (see --scanners in
      # src/args.rs). Not in the devShell, the same as trivy: `nix develop` is
      # what CI runs cargo test, clippy and fmt under, and three Go builds
      # that are not in any binary cache have no business standing between a
      # push and `cargo fmt --check`. A local `just dev` finds whatever is on
      # PATH, which is how trivy has always been found.
      #
      # Same treatment as trivy above and for the same reasons:
      # nixpkgs packages both, and cgo off makes each a static binary using
      # Go's own resolver and TLS rather than one linked against glibc, which
      # is what keeps libc out of the image entirely.
      #
      # They are the two largest things in the image by some way. A deployment
      # that only wants trivy can say `--scanners trivy` and leave them
      # unused, but they are in the image either way: an image whose contents
      # depend on a runtime flag is not one that can be published once.
      syft = pkgs.syft.overrideAttrs (old: {
        env = (old.env or { }) // {
          CGO_ENABLED = 0;
        };
      });

      grype = pkgs.grype.overrideAttrs (old: {
        env = (old.env or { }) // {
          CGO_ENABLED = 0;
        };
      });

      # No cosign: both kinds of signature verification (keyless and against
      # a supplied key) run in-process through the sigstore crate (see
      # src/handler/cosign.rs), and the binary was a third of the compressed
      # image.
      image = pkgs.dockerTools.buildLayeredImage {
        name = "trivy-web";
        tag = "latest";
        contents = [
          trivy-web
          trivy
          syft
          grype
          pkgs.cacert
        ];

        # sigstore's trust-root fetch (see SigstoreTrustRoot in
        # src/handler/cosign.rs) needs somewhere to stage a temp directory;
        # buildLayeredImage does not create /tmp on its own. syft and grype
        # want one too -- both stage the image layers they pull through it,
        # and grype unpacks its vulnerability database there.
        #
        # /var/cache/trivy-web is where the three scanners keep what they
        # download (TRIVY_WEB_CACHE_DIR below). Worth a volume: grype's
        # vulnerability database is a few hundred megabytes, and without one it
        # is refetched every time the container is replaced.
        extraCommands = ''
          mkdir -m 1777 -p tmp
          mkdir -m 0777 -p var/cache/trivy-web
        '';

        config = {
          Entrypoint = [ "${trivy-web}/bin/trivy-web" ];
          ExposedPorts = {
            "16223/tcp" = { };
          };
          Env = [
            "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"

            # Named rather than left to the defaults: there is no $HOME in
            # this image, so without it the scanners would fall back to a
            # directory under /tmp and there would be nothing for a volume to
            # be mounted at.
            "TRIVY_WEB_CACHE_DIR=/var/cache/trivy-web"
          ];
        };
      };
    in
    {
      packages.${system} = {
        inherit trivy-web image;
        default = trivy-web;
      };


      # `nix develop` for local work, and what CI (see nix.yml) runs `cargo
      # test`/`clippy`/`fmt` under -- the same pinned versions either way,
      # rather than whatever `cargo` happens to resolve to on a given
      # machine. rustfmt first in the combine so it wins the conflict with
      # the stable toolchain's own bundled rustfmt (fenix.combine keeps the
      # earliest entry on a path collision; verified by checking
      # `rustfmt --version` both ways round rather than assuming).
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          (fenix.packages.${system}.combine [
            nightlyRustfmt
            toolchain
          ])
        ];
      };
    };
}
