use crate::project_root;
use crate::qemu_runner::{run_qemu_test, Milestone, QemuConfig, QemuResult};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ── Milestone definitions ────────────────────────────────────────────

fn x86_64_milestones() -> Vec<Milestone> {
    vec![
        Milestone {
            pattern: "[BOOT] Harmony unikernel",
            description: "kernel entry",
        },
        Milestone {
            pattern: "[ENTROPY] RDRAND",
            description: "RNG available",
        },
        Milestone {
            pattern: "[IDENTITY]",
            description: "identity generated",
        },
        Milestone {
            pattern: "[READY] entering event loop",
            description: "boot complete",
        },
    ]
}

fn aarch64_milestones() -> Vec<Milestone> {
    vec![
        Milestone {
            pattern: "[PL011] Serial initialized",
            description: "serial up",
        },
        Milestone {
            pattern: "[RNDR]",
            description: "hardware RNG available",
        },
        Milestone {
            pattern: "[Identity]",
            description: "identity generated",
        },
        Milestone {
            pattern: "[Runtime] Entering idle loop",
            description: "runtime idle loop",
        },
    ]
}

// ── Paths ────────────────────────────────────────────────────────────

fn aarch64_efi_path() -> PathBuf {
    project_root().join(
        "crates/harmony-boot-aarch64/target/aarch64-unknown-uefi/release/harmony-boot-aarch64.efi",
    )
}

fn aarch64_esp_path() -> PathBuf {
    project_root().join("target/harmony-aarch64-esp.img")
}

/// Find the EDK2 aarch64 UEFI firmware shipped with QEMU.
/// Resolves relative to the qemu-system-aarch64 binary location.
fn find_aarch64_firmware() -> Result<PathBuf, String> {
    // Check OVMF_FD env var first (allows override).
    if let Ok(path) = std::env::var("OVMF_FD") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("OVMF_FD={path} does not exist"));
    }

    // Find QEMU binary and resolve symlinks (Nix wraps binaries in /nix/store
    // wrapper dirs whose parent is NOT where share/qemu/ lives).
    let qemu_path = which("qemu-system-aarch64")
        .map_err(|_| "qemu-system-aarch64 not found on PATH".to_string())?;
    let qemu_path = qemu_path.canonicalize().unwrap_or(qemu_path);
    let qemu_dir = qemu_path.parent().unwrap();
    let firmware = qemu_dir.join("../share/qemu/edk2-aarch64-code.fd");
    let firmware = firmware
        .canonicalize()
        .map_err(|e| format!("EDK2 firmware not found at {}: {e}", firmware.display()))?;
    Ok(firmware)
}

/// Simple `which` implementation — find an executable on PATH.
fn which(name: &str) -> Result<PathBuf, ()> {
    let path_var = std::env::var("PATH").map_err(|_| ())?;
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            if let Ok(meta) = candidate.metadata() {
                if meta.permissions().mode() & 0o111 != 0 {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(())
}

// ── Build functions ──────────────────────────────────────────────────

fn build_x86_64() -> Result<(), String> {
    let boot_dir = project_root().join("crates/harmony-boot");

    // Build kernel with qemu-test feature.
    let status = Command::new("cargo")
        .args([
            "build",
            "--target",
            "x86_64-unknown-none",
            "--release",
            "--features",
            "qemu-test",
        ])
        .current_dir(&boot_dir)
        .status()
        .map_err(|e| format!("cargo build: {e}"))?;
    if !status.success() {
        return Err("x86_64 kernel build failed".into());
    }

    // Create BIOS disk image.
    let kernel = boot_dir.join("target/x86_64-unknown-none/release/harmony-boot");
    let image = crate::image_path();
    bootloader::BiosBoot::new(&kernel)
        .create_disk_image(&image)
        .map_err(|e| format!("disk image creation: {e}"))?;

    Ok(())
}

fn build_aarch64() -> Result<(), String> {
    let boot_dir = project_root().join("crates/harmony-boot-aarch64");

    // Build kernel (default features include qemu-virt).
    let status = Command::new("cargo")
        .args(["build", "--target", "aarch64-unknown-uefi", "--release"])
        .current_dir(&boot_dir)
        .status()
        .map_err(|e| format!("cargo build: {e}"))?;
    if !status.success() {
        return Err("aarch64 kernel build failed".into());
    }

    // Create FAT32 ESP image using mtools.
    let efi = aarch64_efi_path();
    let esp = aarch64_esp_path();

    // Create 4MB FAT image.
    let _ = std::fs::remove_file(&esp);
    let status = Command::new("dd")
        .args([
            "if=/dev/zero",
            &format!("of={}", esp.display()),
            "bs=1M",
            "count=4",
        ])
        .stderr(Stdio::null()) // dd always prints transfer stats to stderr
        .status()
        .map_err(|e| format!("dd: {e}"))?;
    if !status.success() {
        return Err("dd failed creating ESP image".into());
    }

    // Format as FAT.
    run_cmd("mformat", &["-i", &esp.display().to_string(), "::"])?;
    // Create EFI/BOOT directory.
    run_cmd("mmd", &["-i", &esp.display().to_string(), "::/EFI"])?;
    run_cmd("mmd", &["-i", &esp.display().to_string(), "::/EFI/BOOT"])?;
    // Copy kernel.
    run_cmd(
        "mcopy",
        &[
            "-i",
            &esp.display().to_string(),
            &efi.display().to_string(),
            "::/EFI/BOOT/BOOTAA64.EFI",
        ],
    )?;

    Ok(())
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .status()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if !status.success() {
        return Err(format!("{cmd} failed"));
    }
    Ok(())
}

// ── QEMU configs ─────────────────────────────────────────────────────

fn x86_64_qemu_config(timeout: Duration) -> QemuConfig {
    let image = crate::image_path();
    QemuConfig {
        qemu_binary: "qemu-system-x86_64".into(),
        qemu_args: vec![
            "-drive".into(),
            format!("format=raw,file={}", image.display()),
            "-serial".into(),
            "stdio".into(),
            "-display".into(),
            "none".into(),
            "-device".into(),
            "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
            "-cpu".into(),
            "qemu64,+rdrand".into(),
            "-no-reboot".into(),
        ],
        milestones: x86_64_milestones(),
        timeout,
        on_milestone: Some(Box::new(|_, m| {
            println!("[x86_64]  ✓ {} ...", m.pattern);
        })),
    }
}

fn aarch64_qemu_config(timeout: Duration, firmware: &PathBuf) -> QemuConfig {
    let esp = aarch64_esp_path();
    QemuConfig {
        qemu_binary: "qemu-system-aarch64".into(),
        qemu_args: vec![
            "-machine".into(),
            "virt".into(),
            "-cpu".into(),
            "max".into(),
            "-m".into(),
            "256M".into(),
            "-bios".into(),
            firmware.display().to_string(),
            "-drive".into(),
            format!("format=raw,file={}", esp.display()),
            "-serial".into(),
            "stdio".into(),
            "-display".into(),
            "none".into(),
            "-no-reboot".into(),
        ],
        milestones: aarch64_milestones(),
        timeout,
        on_milestone: Some(Box::new(|_, m| {
            println!("[aarch64] ✓ {} ...", m.pattern);
        })),
    }
}

// ── Display ──────────────────────────────────────────────────────────

fn print_result(target: &str, result: &QemuResult, config: &QemuConfig) {
    match result {
        QemuResult::Pass { duration } => {
            println!("[{target}]  PASS ({:.1}s)", duration.as_secs_f64());
        }
        QemuResult::Panic { line, output_tail } => {
            println!("[{target}]  FAIL — panic detected:");
            println!("[{target}]    {line}");
            println!("[{target}]  Last serial output:");
            for l in output_tail {
                println!("[{target}]    {l}");
            }
        }
        QemuResult::Timeout {
            reached,
            total,
            output_tail,
        } => {
            println!("[{target}]  FAIL — timeout ({reached}/{total} milestones)");
            if *reached < config.milestones.len() {
                println!("[{target}]  Stuck at: {}", config.milestones[*reached].description);
            }
            println!("[{target}]  Last serial output:");
            for l in output_tail {
                println!("[{target}]    {l}");
            }
        }
        QemuResult::ExitedEarly {
            reached,
            total,
            output_tail,
        } => {
            println!("[{target}]  FAIL — QEMU exited early ({reached}/{total} milestones)");
            if *reached < config.milestones.len() {
                println!("[{target}]  Stuck at: {}", config.milestones[*reached].description);
            }
            println!("[{target}]  Last serial output:");
            for l in output_tail {
                println!("[{target}]    {l}");
            }
        }
        QemuResult::LaunchFailed { error } => {
            println!("[{target}]  FAIL — could not launch QEMU: {error}");
        }
    }
}

// ── Public entry point ───────────────────────────────────────────────

pub fn run(args: &[String]) {
    let mut targets: Vec<&str> = Vec::new();
    let mut timeout_secs: u64 = 30;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--target requires a value (x86_64 or aarch64)");
                    std::process::exit(1);
                }
                let t = match args[i].as_str() {
                    "x86_64" | "x86" => "x86_64",
                    "aarch64" | "arm64" => "aarch64",
                    other => {
                        eprintln!("Unknown target: {other} (expected x86_64 or aarch64)");
                        std::process::exit(1);
                    }
                };
                if !targets.contains(&t) {
                    targets.push(t);
                }
            }
            "--timeout" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--timeout requires a value (seconds)");
                    std::process::exit(1);
                }
                timeout_secs = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("Invalid timeout: {}", args[i]);
                    std::process::exit(1);
                });
            }
            other => {
                eprintln!("Unknown argument: {other}");
                eprintln!(
                    "Usage: cargo xtask qemu-test [--target x86_64|aarch64] [--timeout SECS]"
                );
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Default: test both.
    if targets.is_empty() {
        targets = vec!["x86_64", "aarch64"];
    }

    let timeout = Duration::from_secs(timeout_secs);
    let mut all_pass = true;

    for &target in &targets {
        match target {
            "x86_64" => {
                print!("[x86_64]  BUILDING... ");
                let _ = std::io::stdout().flush();
                let build_start = Instant::now();
                match build_x86_64() {
                    Ok(()) => {
                        println!("ok ({:.1}s)", build_start.elapsed().as_secs_f64());
                    }
                    Err(e) => {
                        println!("FAILED: {e}");
                        all_pass = false;
                        continue;
                    }
                }

                println!("[x86_64]  BOOTING...");
                let config = x86_64_qemu_config(timeout);
                let result = run_qemu_test(&config);

                // Milestones print in real-time via on_milestone callback.
                print_result("x86_64", &result, &config);
                if !matches!(result, QemuResult::Pass { .. }) {
                    all_pass = false;
                }
            }
            "aarch64" => {
                // Find firmware first.
                let firmware = match find_aarch64_firmware() {
                    Ok(f) => f,
                    Err(e) => {
                        println!("[aarch64] FAIL — {e}");
                        all_pass = false;
                        continue;
                    }
                };

                print!("[aarch64] BUILDING... ");
                let _ = std::io::stdout().flush();
                let build_start = Instant::now();
                match build_aarch64() {
                    Ok(()) => {
                        println!("ok ({:.1}s)", build_start.elapsed().as_secs_f64());
                    }
                    Err(e) => {
                        println!("FAILED: {e}");
                        all_pass = false;
                        continue;
                    }
                }

                println!("[aarch64] BOOTING...");
                let config = aarch64_qemu_config(timeout, &firmware);
                let result = run_qemu_test(&config);

                print_result("aarch64", &result, &config);
                if !matches!(result, QemuResult::Pass { .. }) {
                    all_pass = false;
                }
            }
            _ => unreachable!(),
        }

        println!();
    }

    std::process::exit(if all_pass { 0 } else { 1 });
}
