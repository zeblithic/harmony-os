# Archivist node — RPi5 with large USB HDD for cold storage.
#
# This node serves as the long-term archive for the Harmony mesh.
# When hot-cache RPi5 nodes (luna, terra, sol) evict LFU content,
# the archivist ingests and persists it on a high-capacity HDD.
#
# Differences from standard nodes:
#   - XFS filesystem on USB HDD (labeled HARMONY-ARCHIVE)
#   - Large cache capacity (8192 vs default 1024)
#   - sysctl tuning for large-volume I/O on 8GB RAM
#   - Higher disk quota (20 TiB to leave headroom on 22TB drive)
#
# To prepare the HDD:
#   sudo parted /dev/sdX mklabel gpt
#   sudo parted /dev/sdX mkpart primary 0% 100%
#   sudo mkfs.xfs -L HARMONY-ARCHIVE /dev/sdX1
#   sudo mount /dev/sdX1 /mnt && sudo chown harmony-node:harmony-node /mnt && sudo umount /mnt

{ lib, ... }:
{
  imports = [ ./rpi5-base.nix ];
  networking.hostName = "harmony-archive";

  # Load the XFS kernel module after boot so it is available when the
  # automount first triggers. Not needed in initrd (the HDD is not
  # mounted there); boot.kernelModules and boot.initrd.availableKernelModules
  # are independent NixOS options with separate merge semantics.
  boot.kernelModules = [ "xfs" ];

  # --- Archivist overrides ---
  # mkForce required because rpi5-base.nix sets these to different values
  # and NixOS's nullOr str type cannot merge two non-null strings.

  services.harmony-node.cacheCapacity = 8192;
  services.harmony-node.dataDir = lib.mkForce "/mnt/harmony-archive";
  services.harmony-node.diskQuota = lib.mkForce "20 TiB";

  # --- XFS HDD auto-mount ---
  # The archivist's primary storage — USB HDD labeled HARMONY-ARCHIVE.
  # XFS chosen over ext4 for large volumes: dynamic inode allocation,
  # delayed allocation for sequential writes, and fast journal recovery
  # (seconds, not hours) after unclean shutdown.
  #
  # This is separate from the HARMONY-DATA SSD mount in rpi5-base.nix.
  # The archivist can have both: SSD for hot cache, HDD for cold archive.
  fileSystems."/mnt/harmony-archive" = {
    device = "/dev/disk/by-label/HARMONY-ARCHIVE";
    fsType = "xfs";
    options = [
      "nofail"                       # Don't block boot if HDD is absent
      "noatime"                      # Skip access-time writes
      "x-systemd.automount"          # Mount on first access
      "x-systemd.idle-timeout=0"     # Never unmount once mounted
      "x-systemd.device-timeout=10s" # HDD spin-up can take longer than SSD
    ];
  };

  # --- sysctl tuning for large-volume XFS on 8GB RAM ---
  # Based on Gemini research (2026-03-30): XFS metadata caching can
  # consume all available RAM on a 22TB volume. These settings constrain
  # dirty pages and VFS cache to prevent OOM under sustained write load.
  #
  # NOTE: These are system-wide knobs — they affect all mounted filesystems
  # (SD card root, SSD, HDD). The values are tuned for the archivist's
  # primary workload (sustained sequential writes to a large XFS volume).
  # If SD card I/O latency is noticeable, consider reducing
  # vfs_cache_pressure to 150-200.
  boot.kernel.sysctl = {
    # Dirty page limits — prevent massive I/O stalls from accumulated writes.
    # 2% of 8GB = ~160MB background flush threshold.
    # 5% of 8GB = ~400MB hard limit before blocking writes.
    "vm.dirty_background_ratio" = 2;
    "vm.dirty_ratio" = 5;

    # Reclaim inode/dentry caches more aggressively than default (100).
    # Frees RAM for the harmony-node process. System-wide — affects all
    # filesystems including the SD card root. 200 is a moderate value;
    # increase to 300 if XFS metadata pressure causes OOM under load.
    "vm.vfs_cache_pressure" = 200;

    # Reserve 32MB for atomic kernel operations (network interrupt handling).
    # Prevents UDP ingest bursts from exhausting memory during XFS flushes.
    "vm.min_free_kbytes" = 32768;

    # Prefer keeping application pages in RAM over swapping to disk.
    # The HDD is the primary I/O target — don't add swap I/O on top.
    "vm.swappiness" = 10;
  };
}
