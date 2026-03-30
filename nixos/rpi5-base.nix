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

  # The sd-image-aarch64 module includes dw-hdmi in availableKernelModules,
  # but the RPi Foundation kernel (6.12+) doesn't ship this module.
  boot.initrd.availableKernelModules = lib.mkForce [
    "usbhid"
    "usb_storage"
    "vc4"
    "pcie_brcmstb"
    "reset-raspberrypi"
    "bcm2835_dma"
    "i2c_bcm2835"
    "dwc2"
    "xhci_pci"
    "nvme"
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
  # TODO(harmony-os-wifi-secrets): The PSK is committed in plaintext. This is
  # intentionally accepted for now (it's the org name, not a secret), but should
  # be migrated to agenix or sops-nix for proper secrets management.
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

  users.users.zeblith = {
    isNormalUser = true;
    extraGroups = [ "wheel" "networkmanager" "dialout" ];
    # initialPassword kept for local console access (HDMI + keyboard) only.
    # SSH requires key auth (PasswordAuthentication = false above).
    # TODO(harmony-os-user-secrets): Migrate to hashedPasswordFile via agenix/sops-nix.
    initialPassword = "harmony";
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM+Y/OkDTbAa/T0TXHESg7ZRkXOj0rJQ3qUlCR9STo7t zeblith@gmail.com"
    ];
  };

  # TODO(harmony-os-sudo-hardening): Re-enable wheelNeedsPassword once
  # hashedPasswordFile is in place via agenix/sops-nix.
  security.sudo.wheelNeedsPassword = false;

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
