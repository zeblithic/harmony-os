# NixOS module that runs harmony-node as a systemd service.
#
# Starts a Harmony mesh node on boot with mDNS peer discovery.
# Nodes on the same LAN automatically discover each other and
# begin exchanging Reticulum packets over UDP port 4242.
#
# Identity is persisted in /var/lib/harmony/ so it survives reboots.
#
# Usage in flake.nix:
#   imports = [ ./nixos/harmony-node-service.nix ];
#   services.harmony-node.package = harmonyNodePkg;

{ config, pkgs, lib, ... }:

{
  options.services.harmony-node = {
    enable = lib.mkEnableOption "Harmony mesh node";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The harmony-node package (pre-built static binary)";
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0";
      description = "UDP bind address for Reticulum packets";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 4242;
      description = "UDP port for Reticulum packets (used by both the service and the firewall)";
    };

    cacheCapacity = lib.mkOption {
      type = lib.types.int;
      default = 1024;
      description = "W-TinyLFU cache item capacity";
    };
  };

  config = lib.mkIf config.services.harmony-node.enable {
    systemd.services.harmony-node = {
      description = "Harmony mesh node — Reticulum/Zenoh P2P network";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = let
        cfg = config.services.harmony-node;
      in {
        Type = "simple";
        DynamicUser = true;
        StateDirectory = "harmony";
        ExecStart = "${cfg.package}/bin/harmony run --identity-file /var/lib/harmony/id.key --listen-address ${cfg.listenAddress}:${toString cfg.port} --cache-capacity ${toString cfg.cacheCapacity}";
        Restart = "on-failure";
        RestartSec = "5s";

        # Hardening (ReadWritePaths not needed — DynamicUser + StateDirectory
        # already grants write access to /var/lib/harmony)
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
      };
    };

    # Open UDP port for Harmony Reticulum (derived from the same port option)
    networking.firewall.allowedUDPPorts = [ config.services.harmony-node.port ];
  };
}
