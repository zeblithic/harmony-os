use std::collections::VecDeque;
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
/// NOTE: panics before the serial UART is initialized produce no serial output
/// and will therefore appear as QemuResult::ExitedEarly, not QemuResult::Panic.
pub const PANIC_PATTERNS: &[&str] = &["[PANIC]", "!!! PANIC"];

/// Result of a QEMU test run.
pub enum QemuResult {
    Pass { duration: Duration },
    Panic { line: String, output_tail: VecDeque<String> },
    Timeout { reached: usize, total: usize, output_tail: VecDeque<String> },
    /// QEMU exited (pipe closed) before all milestones were reached.
    /// Distinct from Timeout: the guest crashed or exited, not slow.
    ExitedEarly { reached: usize, total: usize, output_tail: VecDeque<String> },
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
    #[allow(clippy::type_complexity)]
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
        .stderr(Stdio::inherit())
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
    let mut tail: VecDeque<String> = VecDeque::new();
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
                tail.push_back(line.clone());
                if tail.len() > tail_max {
                    tail.pop_front();
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
                // QEMU exited before all milestones — crash, not timeout.
                return QemuResult::ExitedEarly {
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
