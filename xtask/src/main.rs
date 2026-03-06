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
        Some("run") => {
            build_kernel();
            build_image();
            run_qemu();
        }
        _ => {
            eprintln!("Usage: cargo xtask [build-kernel|build-image|run]");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  build-kernel  Build the kernel ELF (stable Rust)");
            eprintln!("  build-image   Build kernel + bootable BIOS disk image (needs nightly)");
            eprintln!("  run           Build image + launch QEMU");
            std::process::exit(1);
        }
    }
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn kernel_binary() -> PathBuf {
    project_root().join(format!("target/{TARGET}/release/harmony-boot"))
}

fn image_path() -> PathBuf {
    project_root().join("target/harmony-boot-bios.img")
}

fn build_kernel() {
    let boot_dir = project_root().join("crates/harmony-boot");
    println!("Building kernel ELF...");
    let status = Command::new("cargo")
        .args(["build", "--target", TARGET, "--release"])
        .current_dir(&boot_dir)
        .status()
        .expect("failed to invoke cargo");
    assert!(status.success(), "kernel build failed");
    println!("Kernel ELF: {}", kernel_binary().display());
}

fn build_image() {
    // The bootloader crate v0.11 build.rs uses -Z build-std which requires nightly.
    // We shell out to `cargo +nightly run` on a small helper, or use bootimage.
    // For now, we create a raw disk image by invoking the bootloader's disk image tool
    // via cargo +nightly. If nightly isn't available, we give a clear error.
    // Try using bootimage tool first (cargo install bootimage)
    println!("Creating BIOS disk image...");

    // Approach: use the bootloader crate's runner via cargo +nightly bootimage
    let status = Command::new("cargo")
        .args([
            "+nightly",
            "run",
            "--manifest-path",
            "xtask/Cargo.toml.nightly",
            "--",
            "create-image",
        ])
        .current_dir(project_root())
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("Created: {}", image_path().display());
        }
        _ => {
            // Fallback: create a minimal flat binary for QEMU -kernel flag (no BIOS boot)
            eprintln!();
            eprintln!("WARNING: Could not create BIOS disk image.");
            eprintln!("The bootloader crate requires nightly Rust for disk image creation.");
            eprintln!("Install nightly: rustup toolchain install nightly");
            eprintln!();
            eprintln!("Alternative: use QEMU with -kernel flag directly on the ELF:");
            eprintln!(
                "  qemu-system-x86_64 -kernel {} -serial stdio -display none",
                kernel_binary().display()
            );
            std::process::exit(1);
        }
    }
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
    // So exit(0) from guest -> host exit code 1, exit(1) -> 3
    let code = status.code().unwrap_or(1);
    if code == 33 {
        // Guest called exit(0x10) which is our success convention: (0x10 << 1) | 1 = 33
        std::process::exit(0);
    }
    std::process::exit(code);
}
