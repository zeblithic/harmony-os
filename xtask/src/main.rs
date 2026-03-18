mod qemu_runner;
mod qemu_test;

use std::path::PathBuf;
use std::process::Command;

const TARGET: &str = "x86_64-unknown-none";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("build-kernel") => build_kernel(),
        Some("build-image") => {
            build_kernel();
            build_image();
        }
        Some("build-image-test") => {
            build_kernel_with_features(&["qemu-test"]);
            build_image();
        }
        Some("run") => {
            build_kernel();
            build_image();
            run_qemu();
        }
        Some("qemu-test") => {
            qemu_test::run(&args[2..]);
        }
        _ => {
            eprintln!("Usage: cargo xtask <command>");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  build-kernel      Build the kernel ELF");
            eprintln!("  build-image       Build kernel + bootable BIOS disk image");
            eprintln!("  build-image-test  Build kernel with qemu-test feature + disk image");
            eprintln!("  run               Build image + launch QEMU");
            eprintln!("  qemu-test         Build + boot both architectures, verify serial milestones");
            std::process::exit(1);
        }
    }
}

pub(crate) fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn kernel_binary() -> PathBuf {
    // harmony-boot is excluded from the workspace, so its target dir is local
    project_root().join(format!("crates/harmony-boot/target/{TARGET}/release/harmony-boot"))
}

pub(crate) fn image_path() -> PathBuf {
    project_root().join("target/harmony-boot-bios.img")
}

fn build_kernel() {
    build_kernel_with_features(&[]);
}

fn build_kernel_with_features(features: &[&str]) {
    let boot_dir = project_root().join("crates/harmony-boot");
    println!("Building kernel ELF...");
    let mut args = vec!["build", "--target", TARGET, "--release"];
    let features_str = features.join(",");
    if !features.is_empty() {
        args.push("--features");
        args.push(&features_str);
    }
    let status = Command::new("cargo")
        .args(&args)
        .current_dir(&boot_dir)
        .status()
        .expect("failed to invoke cargo");
    assert!(status.success(), "kernel build failed");
    println!("Kernel ELF: {}", kernel_binary().display());
}

fn build_image() {
    println!("Creating BIOS disk image...");
    bootloader::BiosBoot::new(&kernel_binary())
        .create_disk_image(&image_path())
        .expect("failed to create BIOS disk image");
    println!("Created: {}", image_path().display());
}

fn run_qemu() {
    let img = image_path();
    if !img.exists() {
        eprintln!("Disk image not found: {}", img.display());
        eprintln!("Run `cargo xtask build-image` first.");
        std::process::exit(1);
    }

    println!("Launching QEMU...");
    let status = Command::new("qemu-system-x86_64")
        .args([
            "-drive",
            &format!("format=raw,file={}", img.display()),
            "-serial",
            "stdio",
            "-display",
            "none",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-cpu",
            "qemu64,+rdrand",
        ])
        .status()
        .expect("failed to launch QEMU — is qemu-system-x86_64 installed?");

    // The isa-debug-exit device maps exit code: (value << 1) | 1
    // Guest calls exit(0x10) -> host sees (0x10 << 1) | 1 = 33
    let code = status.code().unwrap_or(1);
    if code == 33 {
        println!("QEMU exited with success (guest exit code 0x10)");
        std::process::exit(0);
    }
    std::process::exit(code);
}
