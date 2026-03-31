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

    dataDir = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Runtime path for persistent CAS book and memo storage. When null, uses in-memory cache only.";
    };

    diskQuota = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "3.5 TiB";
      description = "Maximum disk usage for persistent storage (e.g. '3.5 TiB', '500 GiB'). Requires dataDir.";
    };
  };

  config = lib.mkIf config.services.harmony-node.enable (let
    cfg = config.services.harmony-node;
  in {
    assertions = [
      {
        assertion = cfg.diskQuota == null || cfg.dataDir != null;
        message = "services.harmony-node.diskQuota requires services.harmony-node.dataDir to be set.";
      }
    ];

    # Static service user — DynamicUser doesn't work with external mount points
    # (the transient UID can't own files on a real ext4 filesystem).
    users.users.harmony-node = {
      isSystemUser = true;
      group = "harmony-node";
      home = "/var/lib/harmony";
    };
    users.groups.harmony-node = {};

    systemd.services.harmony-node = {
      description = "Harmony mesh node — Reticulum/Zenoh P2P network";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = let
        dataDirArgs = lib.optionalString (cfg.dataDir != null)
          " --data-dir ${cfg.dataDir}";
        diskQuotaArgs = lib.optionalString (cfg.diskQuota != null)
          " --disk-quota '${cfg.diskQuota}'";
      in {
        Type = "simple";
        User = "harmony-node";
        Group = "harmony-node";
        StateDirectory = "harmony";
        ExecStart = "${cfg.package}/bin/harmony run --identity-file /var/lib/harmony/id.key --listen-address ${cfg.listenAddress}:${toString cfg.port} --cache-capacity ${toString cfg.cacheCapacity}${dataDirArgs}${diskQuotaArgs}";
        Restart = "on-failure";
        RestartSec = "5s";

        # Hardening
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
      } // lib.optionalAttrs (cfg.dataDir != null) {
        ReadWritePaths = [ cfg.dataDir ];
      };
    };

    # Open UDP port for Harmony Reticulum (derived from the same port option)
    networking.firewall.allowedUDPPorts = [ cfg.port ];
  });
}
