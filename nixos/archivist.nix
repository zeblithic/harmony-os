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

{ ... }:
{
  imports = [ ./rpi5-base.nix ];
  networking.hostName = "harmony-archive";

  # Ensure XFS kernel module is available (appended to base's mkForce list)
  boot.kernelModules = [ "xfs" ];

  # --- Archivist overrides ---

  # Larger cache for archival workload
  services.harmony-node.cacheCapacity = 8192;

  # Point to the XFS HDD mount, not the SSD mount
  services.harmony-node.dataDir = "/mnt/harmony-archive";
  services.harmony-node.diskQuota = "20 TiB";

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
  boot.kernel.sysctl = {
    # Dirty page limits — prevent massive I/O stalls from accumulated writes.
    # 2% of 8GB = ~160MB background flush threshold.
    # 5% of 8GB = ~400MB hard limit before blocking writes.
    "vm.dirty_background_ratio" = 2;
    "vm.dirty_ratio" = 5;

    # Aggressively reclaim XFS inode/dentry caches.
    # Default is 100 (balanced). 300 penalizes metadata caching heavily,
    # freeing RAM for the harmony-node process and page cache.
    "vm.vfs_cache_pressure" = 300;

    # Reserve 32MB for atomic kernel operations (network interrupt handling).
    # Prevents UDP ingest bursts from exhausting memory during XFS flushes.
    "vm.min_free_kbytes" = 32768;

    # Prefer keeping application pages in RAM over swapping to disk.
    # The HDD is the primary I/O target — don't add swap I/O on top.
    "vm.swappiness" = 10;
  };
}
