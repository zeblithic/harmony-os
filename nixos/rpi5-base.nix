# Shared NixOS configuration for all Raspberry Pi 5 dev workstations.
#
# Each host imports this base and sets its own networking.hostName.
# Uses direct kernel loading via the RPi5 SPI bootloader — no U-Boot.
#
# Build:  nix build .#sdImage-luna --system aarch64-linux
# Flash:  Use Raspberry Pi Imager → "Use custom" → select .img

{ config, pkgs, lib, harmonyNodePkg, ... }:

{
  imports = [ ./harmony-node-service.nix ];

  # --- Harmony mesh node ---

  services.harmony-node = {
    enable = true;
    package = harmonyNodePkg;
    dataDir = "/mnt/harmony-data";
    diskQuota = "3.5 TiB";
    nixCachePort = 5000;
  };

  # --- USB SSD auto-mount ---
  # Auto-mount any USB drive labeled HARMONY-DATA at /mnt/harmony-data.
  # If no SSD is attached, the automount fails in 5s and the path stays
  # absent — harmony-node sees a nonexistent data-dir and falls back to
  # in-memory cache only.
  #
  # To prepare a drive:
  #   sudo mkfs.ext4 -L HARMONY-DATA /dev/sdX1
  #   sudo mount /dev/sdX1 /mnt && sudo chown harmony-node:harmony-node /mnt && sudo umount /mnt
  #
  # No tmpfiles stub — systemd automount creates the mount point itself.
  # If we pre-created it, harmony-node would find the empty directory and
  # try to use it, triggering the automount and a 5s hang on every boot
  # without an SSD.
  fileSystems."/mnt/harmony-data" = {
    device = "/dev/disk/by-label/HARMONY-DATA";
    fsType = "ext4";
    options = [
      "nofail"                       # Don't block boot if SSD is absent
      "noatime"                      # Skip access-time writes (reduces SSD wear)
      "x-systemd.automount"          # Mount on first access, not at boot
      "x-systemd.idle-timeout=0"     # Never unmount once mounted
      "x-systemd.device-timeout=5s"  # Fail fast if SSD isn't plugged in
    ];
  };

  # --- Boot ---

  # Keep extlinux enabled (sd-image-aarch64 module requires populateCmd to exist)
  # but we override populateFirmwareCommands to use RPi5 direct kernel loading.
  boot.loader.grub.enable = false;
  boot.loader.generic-extlinux-compatible.enable = true;

  boot.kernelParams = [
    "console=ttyAMA10,115200"  # RPi5 debug UART (BCM2712 PL011)
    "console=tty1"
    "root=LABEL=NIXOS_SD"
    "rootfstype=ext4"
    "ro"
  ];

  # mkForce is required here because the NixOS defaults include dw-hdmi in
  # availableKernelModules, but the RPi Foundation kernel (6.12+) doesn't
  # ship this module — the initrd module-shrunk build fails if it's present.
  # NixOS has no list-filtering mechanism, so we must replace the entire list.
  #
  # This consolidates modules from three sources:
  #   - nixos-hardware RPi5: nvme, usbhid, usb-storage
  #   - NixOS defaults (minus dw-hdmi): vc4, xhci_pci
  #   - RPi5-specific: pcie_brcmstb, reset-raspberrypi, bcm2835_dma,
  #     i2c_bcm2835, dwc2, mmc_block, sdhci_iproc
  #
  # If nixos-hardware adds new modules for RPi5, they must be added here too.
  boot.initrd.availableKernelModules = lib.mkForce [
    # From nixos-hardware raspberry-pi-5
    "nvme"
    "usbhid"
    "usb-storage"
    # From NixOS defaults (dw-hdmi excluded — absent in RPi kernel 6.12+)
    "vc4"
    "xhci_pci"
    # RPi5-specific
    "pcie_brcmstb"
    "reset-raspberrypi"
    "bcm2835_dma"
    "i2c_bcm2835"
    "dwc2"
    "mmc_block"
    "sdhci_iproc"
  ];

  # --- SD image settings ---

  sdImage = {
    compressImage = false;
    firmwareSize = 256;

    # RPi5 direct kernel loading (replaces U-Boot RPi3/4 setup)
    populateFirmwareCommands = lib.mkForce ''
      # RPi5 device trees and overlays
      cp ${pkgs.raspberrypifw}/share/raspberrypi/boot/bcm2712*.dtb firmware/
      mkdir -p firmware/overlays
      cp ${pkgs.raspberrypifw}/share/raspberrypi/boot/overlays/* firmware/overlays/ 2>/dev/null || true

      # NixOS kernel and initrd
      cp ${config.boot.kernelPackages.kernel}/${config.system.boot.loader.kernelFile} firmware/Image
      cp ${config.system.build.initialRamdisk}/${config.system.boot.loader.initrdFile} firmware/initrd

      # config.txt — RPi5 SPI bootloader configuration
      cat > firmware/config.txt <<'CONFIGTXT'
[all]
arm_64bit=1
enable_uart=1
uart_2ndstage=1
disable_overscan=1
os_check=0

[pi5]
kernel=Image
initramfs initrd followkernel
device_tree=bcm2712-rpi-5-b.dtb
CONFIGTXT

      # cmdline.txt — kernel command line
      echo "init=${config.system.build.toplevel}/init ${lib.concatStringsSep " " config.boot.kernelParams}" > firmware/cmdline.txt
    '';
  };

  # --- Networking ---

  networking.networkmanager.enable = true;

  # Pre-configured WiFi networks (RPi5 has built-in Broadcom WiFi).
  # Prioritized: MLO (WiFi 7) > 5GHz > 2.4GHz. Ethernet always preferred if available.
  #
  # The PSK is the org name (ZEBLITHIC), not a real secret. Kept in plaintext
  # because NetworkManager ensureProfiles has no native secret-file support —
  # injecting from agenix would require a custom systemd oneshot to template
  # NM profiles, adding meaningful complexity for zero security gain.
  networking.networkmanager.ensureProfiles.profiles = {
    "zHARMONY-MLO" = {
      connection = {
        id = "zHARMONY-MLO";
        type = "wifi";
        autoconnect = "true";
        autoconnect-priority = "30";
      };
      wifi = {
        ssid = "zHARMONY-MLO";
        mode = "infrastructure";
      };
      wifi-security = {
        key-mgmt = "wpa-psk";
        psk = "ZEBLITHIC";
      };
      ipv4.method = "auto";
      ipv6.method = "auto";
    };

    "zHARMONY-5" = {
      connection = {
        id = "zHARMONY-5";
        type = "wifi";
        autoconnect = "true";
        autoconnect-priority = "20";
      };
      wifi = {
        ssid = "zHARMONY-5";
        mode = "infrastructure";
      };
      wifi-security = {
        key-mgmt = "wpa-psk";
        psk = "ZEBLITHIC";
      };
      ipv4.method = "auto";
      ipv6.method = "auto";
    };

    "zHARMONY-2" = {
      connection = {
        id = "zHARMONY-2";
        type = "wifi";
        autoconnect = "true";
        autoconnect-priority = "10";
      };
      wifi = {
        ssid = "zHARMONY-2";
        mode = "infrastructure";
      };
      wifi-security = {
        key-mgmt = "wpa-psk";
        psk = "ZEBLITHIC";
      };
      ipv4.method = "auto";
      ipv6.method = "auto";
    };
  };

  # mDNS — makes hosts discoverable as <hostname>.local on the LAN
  services.avahi = {
    enable = true;
    nssmdns4 = true;   # resolve .local via mDNS for IPv4
    publish = {
      enable = true;
      addresses = true;  # announce our IP
      workstation = true;
    };
  };

  # --- SSH ---

  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "prohibit-password";
      PasswordAuthentication = false;  # Key-only auth; no password login over SSH
    };
  };

  # --- Users ---

  # agenix-managed hashed password for console login.
  # Decrypted at NixOS activation time to /run/agenix/user-password.
  # Source: secrets/user-password.age (age-encrypted mkpasswd -m sha-512 output).
  age.secrets.user-password.file = ../secrets/user-password.age;

  users.users.zeblith = {
    isNormalUser = true;
    extraGroups = [ "wheel" "networkmanager" "dialout" ];
    # hashedPasswordFile takes precedence when the agenix secret is available.
    # initialPassword is the HDMI-console emergency fallback: it activates only
    # if the agenix secret file is missing (first flash, decryption failure).
    # SSH remains key-only (PasswordAuthentication = false above).
    hashedPasswordFile = config.age.secrets.user-password.path;
    initialPassword = "harmony";
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM+Y/OkDTbAa/T0TXHESg7ZRkXOj0rJQ3qUlCR9STo7t zeblith@gmail.com"  # AVALON
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC9fSUat8x5KnIbuqbThWn7fqm3ork11fsvaqxAY/b5F zeblith@gmail.com"  # MacBook Pro
    ];
  };

  # Sudo requires password now that hashedPasswordFile is in place.
  security.sudo.wheelNeedsPassword = true;

  # --- Packages ---

  environment.systemPackages = with pkgs; [
    vim
    git
    htop
    tmux
    curl
    wget
    usbutils
    pciutils
  ];

  # --- Nix ---

  nix.settings.experimental-features = [ "nix-command" "flakes" ];
  nix.settings = {
    substituters = [ "https://zeblithic.cachix.org" ];
    trusted-public-keys = [ "zeblithic.cachix.org-1:aS8HanVPr6MQxxqDq3UbgVhI8WxXzYHyYeb6xjE+UQk=" ];
  };

  # --- System ---

  system.stateVersion = "25.05";
}
