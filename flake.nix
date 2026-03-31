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
    nixos-hardware.url = "github:NixOS/nixos-hardware";
  };

  outputs = { self, nixpkgs, fenix, flake-utils, nixos-hardware }:
    let
      # Per-system dev shell outputs (Rust cross-compilation environment)
      perSystem = flake-utils.lib.eachSystem [ "x86_64-darwin" "aarch64-darwin" "x86_64-linux" "aarch64-linux" ] (system:
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

      # Wrap the pre-built harmony-node static binary as a Nix package.
      # The binary is cross-compiled outside Nix via:
      #   cargo build -p harmony-node --features no-neon \
      #     --target aarch64-unknown-linux-musl --profile release-cross
      # and placed at deploy/harmony-node-aarch64 in this repo.
      harmonyNodePkg = let
        pkgsArm = nixpkgs.legacyPackages.aarch64-linux;
      in pkgsArm.runCommand "harmony-node" {} ''
        mkdir -p $out/bin
        cp ${./deploy/harmony-node-aarch64} $out/bin/harmony
        chmod +x $out/bin/harmony
      '';

      # NixOS configurations for Raspberry Pi 5 SD card images.
      # Three hosts sharing a common base, each with a unique hostname.
      # Build from any x86_64 or aarch64 host:
      #   nix build .#sdImage-luna  --system aarch64-linux
      #   nix build .#sdImage-terra --system aarch64-linux
      #   nix build .#sdImage-sol   --system aarch64-linux
      # On x86_64 hosts, this uses QEMU binfmt emulation (qemu-user-static).
      mkRpi5 = hostConfig: nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        specialArgs = { inherit harmonyNodePkg; };
        modules = [
          "${nixpkgs}/nixos/modules/installer/sd-card/sd-image-aarch64.nix"
          nixos-hardware.nixosModules.raspberry-pi-5
          hostConfig
        ];
      };

      nixosOutputs = {
        nixosConfigurations.rpi5-luna     = mkRpi5 ./nixos/luna.nix;
        nixosConfigurations.rpi5-terra    = mkRpi5 ./nixos/terra.nix;
        nixosConfigurations.rpi5-sol      = mkRpi5 ./nixos/sol.nix;
        nixosConfigurations.rpi5-archive  = mkRpi5 ./nixos/archivist.nix;

        packages.aarch64-linux = {
          sdImage-luna    = self.nixosConfigurations.rpi5-luna.config.system.build.sdImage;
          sdImage-terra   = self.nixosConfigurations.rpi5-terra.config.system.build.sdImage;
          sdImage-sol     = self.nixosConfigurations.rpi5-sol.config.system.build.sdImage;
          sdImage-archive = self.nixosConfigurations.rpi5-archive.config.system.build.sdImage;
        };
      };
    in
    # Merge per-system dev shells with NixOS outputs
    nixpkgs.lib.recursiveUpdate perSystem nixosOutputs;
}
