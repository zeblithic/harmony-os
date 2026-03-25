{
  description = "Harmony OS — mesh-native operating system dev environment";

  nixConfig = {
    extra-substituters = [ "https://zeblithic.cachix.org" ];
    extra-trusted-public-keys = [ "zeblithic.cachix.org-1:aS8HanVPr6MQxxqDq3UbgVhI8WxXzYHyYeb6xjE+UQk=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, fenix, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-darwin" "aarch64-darwin" "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # aarch64-unknown-linux-musl C cross-compiler — needed to build
        # dynamically-linked musl test fixtures (hello world + ld-musl).
        muslCross = pkgs.pkgsCross.aarch64-multiplatform-musl.stdenv.cc;

        # Nightly Rust toolchain with cross-compilation targets.
        # Nightly is required because the `bootloader` crate (used by xtask for
        # x86_64 disk image creation) invokes `cargo -Z build-std` internally.
        # Uses fenix.combine to merge the host toolchain with target rust-std libs.
        rustToolchain = fenix.packages.${system}.combine [
          (fenix.packages.${system}.latest.withComponents [
            "cargo"
            "clippy"
            "rustc"
            "rustfmt"
            "llvm-tools-preview"  # needed by bootloader crate for llvm-objcopy
            "rust-src"  # needed for -Z build-std on no_std/bare-metal targets
          ])
          fenix.packages.${system}.targets.aarch64-unknown-uefi.latest.rust-std
          fenix.packages.${system}.targets.x86_64-unknown-none.latest.rust-std
          fenix.packages.${system}.targets.aarch64-unknown-linux-musl.latest.rust-std
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            rustToolchain
            # rust-analyzer as a standalone fenix derivation — more reliable
            # than including it in withComponents where it may be silently
            # dropped if the stable manifest omits it for this platform.
            fenix.packages.${system}.rust-analyzer
            pkgs.pkg-config
            pkgs.cargo-deny
            # Host tools (executables that run on the build machine)
            pkgs.qemu
            pkgs.mtools
            pkgs.curl
            pkgs.unzip
            pkgs.git
            # aarch64 musl C cross-compiler for test fixtures
            muslCross
          ];

          buildInputs = [
            # Libraries linked against by Rust crates
            pkgs.openssl.dev
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
            # On nixpkgs 26.05+, darwin.apple_sdk.frameworks is removed.
            # Frameworks (Security, SystemConfiguration) are pulled transitively
            # by openssl and other deps — no explicit listing needed.
          ];
        };
      }
    );
}
