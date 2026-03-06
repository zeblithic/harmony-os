use std::path::PathBuf;
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("build-image") => build_image(),
        Some("run") => {
            build_image();
            run_qemu();
        }
        _ => eprintln!("Usage: cargo xtask [build-image|run]"),
    }
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn kernel_binary() -> PathBuf {
    project_root().join("target/x86_64-unknown-none/release/harmony-boot")
}

fn image_path() -> PathBuf {
    project_root().join("target/harmony-boot-bios.img")
}

fn build_image() {
    // Build kernel ELF
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "harmony-boot",
            "--target",
            "x86_64-unknown-none",
            "--release",
        ])
        .current_dir(project_root())
        .status()
        .expect("failed to build kernel");
    assert!(status.success(), "kernel build failed");

    // Create BIOS disk image
    bootloader::BiosBoot::new(&kernel_binary())
        .create_disk_image(&image_path())
        .expect("failed to create BIOS disk image");
    println!("Created: {}", image_path().display());
}

fn run_qemu() {
    let status = Command::new("qemu-system-x86_64")
        .args([
            "-drive",
            &format!("format=raw,file={}", image_path().display()),
            "-serial",
            "stdio",
            "-display",
            "none",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ])
        .status()
        .expect("failed to launch QEMU");
    std::process::exit(status.code().unwrap_or(1));
}
