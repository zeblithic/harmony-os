# QEMU Test Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `cargo xtask qemu-test` that builds and boots harmony-os kernels in QEMU, verifying serial output milestones for both x86_64 and aarch64.

**Architecture:** Extend existing xtask binary with a `qemu-test` subcommand. A generic `QemuRunner` spawns QEMU, reads serial output via a background reader thread + mpsc channel, matches milestones with timeout. Per-target modules define build commands, QEMU args, and milestone lists.

**Tech Stack:** Rust (xtask binary), std::process, std::sync::mpsc, mtools (ESP image creation for aarch64)

**Spec:** `docs/plans/2026-03-18-qemu-test-harness-design.md`

---

### Task 1: Create the QEMU runner module

**Files:**
- Create: `xtask/src/qemu_runner.rs`

This is the core reusable component — spawns QEMU, captures serial output via a reader thread, matches milestones with timeout, detects panics.

- [ ] **Step 1: Create `xtask/src/qemu_runner.rs` with types and runner**

```rust
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A serial output milestone to match.
pub struct Milestone {
    /// Substring to search for in each serial line.
    pub pattern: &'static str,
    /// Human-readable description.
    pub description: &'static str,
}

/// Panic patterns — if any serial line contains one of these, fail immediately.
pub const PANIC_PATTERNS: &[&str] = &["[PANIC]", "!!! PANIC"];

/// Result of a QEMU test run.
pub enum QemuResult {
    Pass { duration: Duration },
    Panic { line: String, output_tail: Vec<String> },
    Timeout { reached: usize, total: usize, output_tail: Vec<String> },
    LaunchFailed { error: String },
}

/// Configuration for a QEMU test run.
pub struct QemuConfig {
    /// QEMU binary name (e.g. "qemu-system-x86_64").
    pub qemu_binary: String,
    /// Arguments to pass to QEMU.
    pub qemu_args: Vec<String>,
    /// Ordered milestones to match in serial output.
    pub milestones: Vec<Milestone>,
    /// Maximum time to wait for all milestones.
    pub timeout: Duration,
    /// Called when a milestone is matched (for real-time progress display).
    /// Arguments: milestone index, milestone reference.
    pub on_milestone: Option<Box<dyn Fn(usize, &Milestone)>>,
}

/// Run QEMU and match serial output against milestones.
///
/// Spawns QEMU with stdout piped, reads lines via a background thread,
/// and matches against milestones in order. Returns as soon as all
/// milestones pass, a panic is detected, or timeout is reached.
pub fn run_qemu_test(config: &QemuConfig) -> QemuResult {
    // Spawn QEMU with stdout piped for serial capture.
    let mut child = match Command::new(&config.qemu_binary)
        .args(&config.qemu_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return QemuResult::LaunchFailed {
                error: format!("{}: {e}", config.qemu_binary),
            }
        }
    };

    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<String>();

    // Reader thread: sends lines over the channel until pipe closes.
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break; // receiver dropped
                    }
                }
                Err(_) => break,
            }
        }
    });

    let start = Instant::now();
    let mut milestone_idx = 0;
    let mut tail: Vec<String> = Vec::new();
    let tail_max = 20;

    loop {
        let remaining = config
            .timeout
            .checked_sub(start.elapsed())
            .unwrap_or(Duration::ZERO);

        if remaining.is_zero() {
            kill_child(&mut child);
            return QemuResult::Timeout {
                reached: milestone_idx,
                total: config.milestones.len(),
                output_tail: tail,
            };
        }

        match rx.recv_timeout(remaining) {
            Ok(line) => {
                // Maintain tail buffer for diagnostics.
                tail.push(line.clone());
                if tail.len() > tail_max {
                    tail.remove(0);
                }

                // Check for panic.
                for pattern in PANIC_PATTERNS {
                    if line.contains(pattern) {
                        kill_child(&mut child);
                        return QemuResult::Panic {
                            line,
                            output_tail: tail,
                        };
                    }
                }

                // Check next milestone.
                if milestone_idx < config.milestones.len()
                    && line.contains(config.milestones[milestone_idx].pattern)
                {
                    if let Some(ref cb) = config.on_milestone {
                        cb(milestone_idx, &config.milestones[milestone_idx]);
                    }
                    milestone_idx += 1;
                    if milestone_idx == config.milestones.len() {
                        kill_child(&mut child);
                        return QemuResult::Pass {
                            duration: start.elapsed(),
                        };
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                kill_child(&mut child);
                return QemuResult::Timeout {
                    reached: milestone_idx,
                    total: config.milestones.len(),
                    output_tail: tail,
                };
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Pipe closed — QEMU exited. If all milestones matched
                // (race between last line and pipe close), that's a pass.
                kill_child(&mut child);
                if milestone_idx == config.milestones.len() {
                    return QemuResult::Pass {
                        duration: start.elapsed(),
                    };
                }
                return QemuResult::Timeout {
                    reached: milestone_idx,
                    total: config.milestones.len(),
                    output_tail: tail,
                };
            }
        }
    }
}

fn kill_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
```

- [ ] **Step 2: Verify xtask compiles with the new module**

Add `mod qemu_runner;` to `xtask/src/main.rs` (just the module declaration, no usage yet):

```rust
mod qemu_runner;
```

Run: `cd xtask && cargo check`
Expected: Compiles with no errors (may have unused warnings, that's fine).

- [ ] **Step 3: Commit**

```bash
git add xtask/src/qemu_runner.rs xtask/src/main.rs
git commit -m "feat(xtask): add QemuRunner — serial milestone matching with timeout"
```

---

### Task 2: Create per-target build and config modules

**Files:**
- Create: `xtask/src/qemu_test.rs`

This module defines the `qemu-test` subcommand: argument parsing, per-target build commands, QEMU arguments, milestone lists, and result display.

- [ ] **Step 1: Create `xtask/src/qemu_test.rs`**

```rust
use crate::qemu_runner::{Milestone, QemuConfig, QemuResult, run_qemu_test};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

// ── Milestone definitions ────────────────────────────────────────────

fn x86_64_milestones() -> Vec<Milestone> {
    vec![
        Milestone { pattern: "[BOOT] Harmony unikernel", description: "kernel entry" },
        Milestone { pattern: "[ENTROPY] RDRAND", description: "RNG available" },
        Milestone { pattern: "[IDENTITY]", description: "identity generated" },
        Milestone { pattern: "[READY] entering event loop", description: "boot complete" },
    ]
}

fn aarch64_milestones() -> Vec<Milestone> {
    vec![
        Milestone { pattern: "[PL011] Serial initialized", description: "serial up" },
        Milestone { pattern: "[RNDR]", description: "hardware RNG available" },
        Milestone { pattern: "[Identity]", description: "identity generated" },
        Milestone { pattern: "[Runtime]", description: "runtime idle loop" },
    ]
}

// ── Paths ────────────────────────────────────────────────────────────

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn x86_64_image_path() -> PathBuf {
    project_root().join("target/harmony-boot-bios.img")
}

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

    // Find QEMU binary and look for firmware relative to it.
    let qemu_path = which("qemu-system-aarch64")
        .map_err(|_| "qemu-system-aarch64 not found on PATH".to_string())?;
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
            return Ok(candidate);
        }
    }
    Err(())
}

// ── Build functions ──────────────────────────────────────────────────

fn build_x86_64() -> Result<(), String> {
    let boot_dir = project_root().join("crates/harmony-boot");

    // Build kernel with qemu-test feature.
    let status = Command::new("cargo")
        .args(["build", "--target", "x86_64-unknown-none", "--release", "--features", "qemu-test"])
        .current_dir(&boot_dir)
        .status()
        .map_err(|e| format!("cargo build: {e}"))?;
    if !status.success() {
        return Err("x86_64 kernel build failed".into());
    }

    // Create BIOS disk image.
    let kernel = boot_dir.join("target/x86_64-unknown-none/release/harmony-boot");
    let image = x86_64_image_path();
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
        .args(["if=/dev/zero", &format!("of={}", esp.display()), "bs=1M", "count=4"])
        .stderr(Stdio::null())
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
    run_cmd("mcopy", &[
        "-i",
        &esp.display().to_string(),
        &efi.display().to_string(),
        "::/EFI/BOOT/BOOTAA64.EFI",
    ])?;

    Ok(())
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if !status.success() {
        return Err(format!("{cmd} failed"));
    }
    Ok(())
}

// ── QEMU configs ─────────────────────────────────────────────────────

fn x86_64_qemu_config(timeout: Duration) -> QemuConfig {
    let image = x86_64_image_path();
    QemuConfig {
        qemu_binary: "qemu-system-x86_64".into(),
        qemu_args: vec![
            "-drive".into(), format!("format=raw,file={}", image.display()),
            "-serial".into(), "stdio".into(),
            "-display".into(), "none".into(),
            "-device".into(), "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
            "-cpu".into(), "qemu64,+rdrand".into(),
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
            "-machine".into(), "virt".into(),
            "-cpu".into(), "max".into(),
            "-m".into(), "256M".into(),
            "-bios".into(), firmware.display().to_string(),
            "-drive".into(), format!("format=raw,file={}", esp.display()),
            "-serial".into(), "stdio".into(),
            "-display".into(), "none".into(),
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

fn print_result(target: &str, result: &QemuResult, milestones: &[Milestone]) {
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
        QemuResult::Timeout { reached, total, output_tail } => {
            println!(
                "[{target}]  FAIL — timeout ({reached}/{total} milestones)"
            );
            if *reached < milestones.len() {
                println!(
                    "[{target}]  Stuck at: {}",
                    milestones[*reached].description
                );
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

use std::process::Stdio;

pub fn run(args: &[String]) {
    let mut targets: Vec<&str> = Vec::new();
    let mut timeout_secs: u64 = 30;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                i += 1;
                if i < args.len() {
                    targets.push(match args[i].as_str() {
                        "x86_64" | "x86" => "x86_64",
                        "aarch64" | "arm64" => "aarch64",
                        other => {
                            eprintln!("Unknown target: {other} (expected x86_64 or aarch64)");
                            std::process::exit(1);
                        }
                    });
                }
            }
            "--timeout" => {
                i += 1;
                if i < args.len() {
                    timeout_secs = args[i].parse().unwrap_or_else(|_| {
                        eprintln!("Invalid timeout: {}", args[i]);
                        std::process::exit(1);
                    });
                }
            }
            other => {
                eprintln!("Unknown argument: {other}");
                eprintln!("Usage: cargo xtask qemu-test [--target x86_64|aarch64] [--timeout SECS]");
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
                let milestones = x86_64_milestones();
                let result = run_qemu_test(&config);

                // Milestones print in real-time via on_milestone callback.
                print_result("x86_64", &result, &milestones);
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
                let milestones = aarch64_milestones();
                let result = run_qemu_test(&config);

                print_result("aarch64", &result, &milestones);
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
```

- [ ] **Step 2: Add `bootloader` dep check**

Verify `xtask/Cargo.toml` already has `bootloader = "0.11"` (it does — needed for `BiosBoot::new`).

- [ ] **Step 3: Verify xtask compiles**

Add `mod qemu_test;` to `xtask/src/main.rs`.

Run: `cd xtask && cargo check`
Expected: Compiles (unused warnings ok).

- [ ] **Step 4: Commit**

```bash
git add xtask/src/qemu_test.rs xtask/src/main.rs
git commit -m "feat(xtask): add qemu-test subcommand with x86_64 + aarch64 targets"
```

---

### Task 3: Wire up the subcommand in main.rs

**Files:**
- Modify: `xtask/src/main.rs`

- [ ] **Step 1: Add `qemu-test` to the match dispatch in `main()`**

Replace the existing `main()` match arms to include the new subcommand:

```rust
mod qemu_runner;
mod qemu_test;

// ... existing code ...

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
```

- [ ] **Step 2: Verify xtask builds**

Run: `cd xtask && cargo build`
Expected: Builds successfully.

- [ ] **Step 3: Verify help text**

Run: `cd xtask && cargo run`
Expected: Shows usage with `qemu-test` listed.

- [ ] **Step 4: Commit**

```bash
git add xtask/src/main.rs
git commit -m "feat(xtask): wire qemu-test subcommand into main dispatch"
```

---

### Task 4: End-to-end smoke test

No files to create — purely verification that the full pipeline works.

- [ ] **Step 1: Run x86_64 QEMU test**

Run (inside `nix develop`):
```bash
cd xtask && cargo run -- qemu-test --target x86_64
```

Expected: Builds kernel, creates disk image, boots QEMU, milestones pass, exits with code 0.

If it fails: check build output, check QEMU launch, check serial output. The `--timeout 60` flag can help if the build is slow.

- [ ] **Step 2: Run aarch64 QEMU test**

Run (inside `nix develop`):
```bash
cd xtask && cargo run -- qemu-test --target aarch64
```

Expected: Finds EDK2 firmware, builds kernel, creates ESP image, boots QEMU, milestones pass, exits with code 0.

- [ ] **Step 3: Run both targets**

Run (inside `nix develop`):
```bash
cd xtask && cargo run -- qemu-test
```

Expected: Both targets pass.

- [ ] **Step 4: Verify timeout handling**

Run:
```bash
cd xtask && cargo run -- qemu-test --timeout 1
```

Expected: Fails with timeout — 1 second is not enough for kernel boot.

- [ ] **Step 5: Commit (if any fixes were needed)**

```bash
git add -A xtask/
git commit -m "fix(xtask): adjustments from smoke testing qemu-test"
```

- [ ] **Step 6: Final commit from repo root**

```bash
git add xtask/
git commit -m "feat: cargo xtask qemu-test — automated boot verification for x86_64 + aarch64

Builds kernels, boots in QEMU, matches serial milestones (BOOT, ENTROPY,
IDENTITY, READY for x86_64; PL011, RNDR, Identity, Runtime for aarch64).
Pass/fail exit codes for CI. Configurable timeout (default 30s).

Closes: harmony-os-5yz"
```
