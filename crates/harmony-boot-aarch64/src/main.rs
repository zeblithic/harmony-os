// SPDX-License-Identifier: GPL-2.0-or-later
//! aarch64 UEFI boot stub for Harmony unikernel.

#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod bump_alloc;
mod fdt_parse;
mod gic;
mod mmu;
mod pl011;
mod rndr;
mod sched;
mod timer;

mod platform;

mod cache;
mod mmio;
mod pe;
mod syscall;
mod vectors;

#[cfg(not(test))]
use linked_list_allocator::LockedHeap;

#[cfg(target_os = "uefi")]
use core::fmt::Write;
#[cfg(target_os = "uefi")]
use uefi::mem::memory_map::MemoryMap as _;
#[cfg(target_os = "uefi")]
use uefi::prelude::*;
#[cfg(target_os = "uefi")]
use uefi::proto::loaded_image::LoadedImage;

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Concrete runtime type — `KernelEntropy` parameterised with a function
/// pointer (the RNDR fill closure captures nothing, so it coerces to `fn`).
#[cfg(target_os = "uefi")]
type ConcreteRuntime = UnikernelRuntime<KernelEntropy<fn(&mut [u8])>, MemoryState>;

/// Global runtime — populated during boot, read by the system task.
/// Access is safe: boot init writes it once before spawning tasks;
/// the system task is the sole reader after that.
#[cfg(target_os = "uefi")]
static mut RUNTIME: Option<ConcreteRuntime> = None;

/// DirectBackend: wraps SerialServer directly for the Linuxulator.
/// Routes write(2) output through PL011 serial.
#[cfg(target_os = "uefi")]
struct DirectBackend {
    server: harmony_microkernel::serial_server::SerialServer,
}

#[cfg(target_os = "uefi")]
impl DirectBackend {
    fn new() -> Self {
        Self {
            server: harmony_microkernel::serial_server::SerialServer::new(),
        }
    }
}

#[cfg(target_os = "uefi")]
impl harmony_os::linuxulator::SyscallBackend for DirectBackend {
    fn walk(
        &mut self,
        _path: &str,
        new_fid: harmony_microkernel::Fid,
    ) -> Result<harmony_microkernel::QPath, harmony_microkernel::IpcError> {
        use harmony_microkernel::FileServer;
        self.server.walk(0, new_fid, "log")
    }
    fn open(
        &mut self,
        fid: harmony_microkernel::Fid,
        mode: harmony_microkernel::OpenMode,
    ) -> Result<(), harmony_microkernel::IpcError> {
        use harmony_microkernel::FileServer;
        self.server.open(fid, mode)
    }
    fn read(
        &mut self,
        fid: harmony_microkernel::Fid,
        offset: u64,
        count: u32,
    ) -> Result<alloc::vec::Vec<u8>, harmony_microkernel::IpcError> {
        use harmony_microkernel::FileServer;
        self.server.read(fid, offset, count)
    }
    fn write(
        &mut self,
        _fid: harmony_microkernel::Fid,
        _offset: u64,
        data: &[u8],
    ) -> Result<u32, harmony_microkernel::IpcError> {
        // Route stdout/stderr writes through PL011 serial
        for &byte in data {
            unsafe { pl011::write_byte(byte) };
        }
        Ok(data.len() as u32)
    }
    fn clunk(
        &mut self,
        fid: harmony_microkernel::Fid,
    ) -> Result<(), harmony_microkernel::IpcError> {
        use harmony_microkernel::FileServer;
        self.server.clunk(fid)
    }
    fn stat(
        &mut self,
        fid: harmony_microkernel::Fid,
    ) -> Result<harmony_microkernel::FileStat, harmony_microkernel::IpcError> {
        use harmony_microkernel::FileServer;
        self.server.stat(fid)
    }
}

/// Concrete Linuxulator type — `DirectBackend` with default `NoTcp`.
#[cfg(target_os = "uefi")]
type ConcreteLinuxulator = harmony_os::linuxulator::Linuxulator<DirectBackend>;

/// Global Linuxulator — populated during boot, used by the system task
/// (for poll_network/is_wait_ready) and by the SVC dispatch function.
/// Access is safe: boot init writes it once before spawning tasks;
/// only the system task and SVC handler access it after that.
#[cfg(target_os = "uefi")]
static mut LINUXULATOR: Option<ConcreteLinuxulator> = None;

/// Set by poll_network when smoltcp processes packets. Read and cleared
/// by check_and_wake_blocked_tasks to gate PollWait wakes — without this,
/// PollWait tasks would be woken on every system-task iteration (busy-poll).
#[cfg(all(feature = "qemu-virt", target_os = "uefi"))]
static mut NETWORK_CHANGED: bool = false;

#[cfg(target_os = "uefi")]
use mmu::MemoryRegion;

#[cfg(target_os = "uefi")]
use harmony_identity::PrivateIdentity;
#[cfg(target_os = "uefi")]
use harmony_microkernel::vm::PAGE_SIZE;
#[cfg(target_os = "uefi")]
use harmony_unikernel::{KernelEntropy, MemoryState, UnikernelRuntime};

/// Minimum physical address for the bump allocator region.
/// We skip the first 1 MiB to avoid legacy low-memory hazards.
#[cfg(target_os = "uefi")]
const BUMP_MIN_ADDR: u64 = 0x10_0000; // 1 MiB

/// Size of the bump allocator region in bytes.
/// QEMU: 2 MiB (~512 frames for page tables + stack).
/// RPi5: 4 MiB (~1024 frames for page tables + stack + 512 DMA buffers).
#[cfg(all(target_os = "uefi", feature = "qemu-virt"))]
const BUMP_REGION_SIZE: u64 = 2 * 1024 * 1024;

#[cfg(all(target_os = "uefi", feature = "rpi5"))]
const BUMP_REGION_SIZE: u64 = 4 * 1024 * 1024;

/// Returns `true` if a UEFI memory type represents usable RAM after
/// ExitBootServices.
///
/// After ExitBootServices, BOOT_SERVICES_CODE and BOOT_SERVICES_DATA become
/// free memory, so we include them along with CONVENTIONAL and LOADER_*.
#[cfg(target_os = "uefi")]
fn is_usable_memory(ty: uefi::mem::memory_map::MemoryType) -> bool {
    use uefi::mem::memory_map::MemoryType;
    matches!(
        ty,
        MemoryType::CONVENTIONAL
            | MemoryType::BOOT_SERVICES_CODE
            | MemoryType::BOOT_SERVICES_DATA
            | MemoryType::LOADER_CODE
            | MemoryType::LOADER_DATA
    )
}

#[cfg(all(target_os = "uefi", not(test)))]
#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    uefi::println!("[UEFI] Booting Harmony aarch64...");

    // ── Parse PE/COFF sections for W^X enforcement ──
    // Must be done BEFORE ExitBootServices while UEFI protocols are still available.
    let image_sections: Option<pe::ImageSections> = {
        let handle = uefi::boot::image_handle();
        // Use GetProtocol (non-exclusive) instead of Exclusive — OEM firmware
        // may already hold LoadedImage open, causing ACCESS_DENIED with exclusive.
        match unsafe {
            uefi::boot::open_protocol::<LoadedImage>(
                uefi::boot::OpenProtocolParams {
                    handle,
                    agent: handle,
                    controller: None,
                },
                uefi::boot::OpenProtocolAttributes::GetProtocol,
            )
        } {
            Ok(loaded_image) => {
                let (base_ptr, size) = loaded_image.info();
                let base = base_ptr as u64;
                uefi::println!("[BOOT] PE image: base={:#x} size={:#x}", base, size);
                match unsafe { pe::parse_sections(base, size) } {
                    Ok(sections) => {
                        uefi::println!("[BOOT] PE sections parsed: W^X will be enforced");
                        Some(sections)
                    }
                    Err(e) => {
                        uefi::println!(
                            "[BOOT] WARNING: PE section parse failed ({:?}), falling back to RWX",
                            e
                        );
                        None
                    }
                }
            }
            Err(e) => {
                uefi::println!(
                    "[BOOT] WARNING: LoadedImage protocol unavailable ({:?}), falling back to RWX",
                    e
                );
                None
            }
        }
    };

    // ── Exit boot services ── UEFI console is no longer available after this.
    // Capture the memory map -- we need it to build the identity page table.
    let memory_map = unsafe { uefi::boot::exit_boot_services(None) };

    // ── Enable FP/SIMD immediately after ExitBootServices ──
    // CPACR_EL1.FPEN [21:20] = 0b11 — full FP/SIMD access at EL1 and EL0.
    // Must be the FIRST thing after ExitBootServices: the reset value is
    // IMPLEMENTATION DEFINED, and any Rust code below could emit SIMD/VFP
    // instructions (memcpy, struct init, auto-vectorization).
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "mrs {tmp}, CPACR_EL1",
            "orr {tmp}, {tmp}, #(0x3 << 20)",
            "msr CPACR_EL1, {tmp}",
            "isb",
            tmp = out(reg) _,
        );
    }

    // ── Initialise PL011 UART (115200 8N1, FIFO enabled) ──
    unsafe { pl011::init() };

    let mut serial =
        harmony_unikernel::SerialWriter::new(|byte| unsafe { pl011::write_byte(byte) });
    let _ = writeln!(serial, "[PL011] Serial initialized: 115200 8N1");

    // ── Collect UEFI memory map into fixed-size array ──
    let mut regions = [MemoryRegion {
        base: 0,
        pages: 0,
        is_usable: false,
        is_conventional: false,
    }; 128];
    let mut region_count = 0;

    for desc in memory_map.entries() {
        let usable = is_usable_memory(desc.ty);
        if !usable {
            continue; // Only store usable regions to avoid truncating them
        }
        if region_count >= regions.len() {
            let _ = writeln!(
                serial,
                "[BOOT] WARNING: memory map truncated at {} entries",
                regions.len()
            );
            break;
        }
        regions[region_count] = MemoryRegion {
            base: desc.phys_start,
            pages: desc.page_count,
            is_usable: true,
            is_conventional: desc.ty == uefi::mem::memory_map::MemoryType::CONVENTIONAL,
        };
        region_count += 1;
    }

    let _ = writeln!(
        serial,
        "[BOOT] Memory map: {} usable regions ({} conventional)",
        region_count,
        regions[..region_count]
            .iter()
            .filter(|r| r.is_conventional)
            .count()
    );

    // ── Reserve bump allocator region from the first CONVENTIONAL region >= 1 MiB ──
    // Like heap, bump must come from CONVENTIONAL memory to avoid overwriting
    // our running binary (LOADER_CODE/DATA) or the UEFI stack (BOOT_SERVICES_DATA).
    let mut bump_base: Option<u64> = None;
    for region in &regions[..region_count] {
        if !region.is_conventional {
            continue;
        }
        let region_end = region.base + region.pages * PAGE_SIZE;
        // Find a region that starts at or above BUMP_MIN_ADDR with enough space.
        let start = if region.base >= BUMP_MIN_ADDR {
            region.base
        } else if region_end > BUMP_MIN_ADDR {
            BUMP_MIN_ADDR
        } else {
            continue;
        };
        let available = region_end.saturating_sub(start);
        if available >= BUMP_REGION_SIZE {
            bump_base = Some(start);
            break;
        }
    }

    let bump_base = bump_base.expect("no suitable region for bump allocator");

    let _ = writeln!(
        serial,
        "[BOOT] Bump allocator: base={:#x} size={:#x}",
        bump_base, BUMP_REGION_SIZE
    );
    let mut bump = bump_alloc::BumpAllocator::new(bump_base, BUMP_REGION_SIZE);

    let _ = writeln!(serial, "[FP] SIMD/FP access enabled (CPACR_EL1.FPEN)");

    // ── Build identity map and enable MMU ──
    unsafe {
        mmu::init_and_enable(
            &regions[..region_count],
            &mut bump,
            &mut serial,
            image_sections.as_ref(),
        )
    };

    // ── Initialise ARM Generic Timer ──
    unsafe { timer::init() };
    assert!(
        timer::freq() != 0,
        "CNTFRQ_EL0 is zero — timer not configured by firmware"
    );
    let _ = writeln!(
        serial,
        "[Timer] ARM generic timer: freq={} Hz",
        timer::freq()
    );

    // ── Verify RNDR hardware RNG is available ──
    assert!(
        unsafe { rndr::is_available() },
        "RNDR not available — use QEMU with -cpu max"
    );
    let _ = writeln!(serial, "[RNDR] Hardware RNG available");

    // ── Initialise heap allocator ──
    // Find the largest CONVENTIONAL sub-region after carving out the bump allocator.
    // Only CONVENTIONAL memory is safe for heap: LOADER_CODE/DATA contain our
    // running binary and BOOT_SERVICES_DATA may hold the active UEFI stack.
    // On QEMU virt, most RAM is one large CONVENTIONAL descriptor that contains
    // the bump allocator, so we must carve rather than exclude the whole region.
    // Cap at 4 MiB to avoid over-committing early in boot.
    let bump_end = bump_base + BUMP_REGION_SIZE;

    let mut best_heap: Option<(u64, u64)> = None; // (base, size)
    for r in regions[..region_count].iter().filter(|r| r.is_conventional) {
        let r_end = r.base + r.pages * PAGE_SIZE;

        // Consider up to two sub-regions: before and after the bump range.
        let candidates: [(u64, u64); 2] = [
            // Sub-region before bump allocator
            if r.base < bump_base {
                (r.base, core::cmp::min(r_end, bump_base) - r.base)
            } else {
                (0, 0)
            },
            // Sub-region after bump allocator
            if r_end > bump_end {
                let start = core::cmp::max(r.base, bump_end);
                (start, r_end - start)
            } else {
                (0, 0)
            },
        ];

        for (base, size) in candidates {
            if size > 0 {
                if best_heap.map_or(true, |(_, best_size)| size > best_size) {
                    best_heap = Some((base, size));
                }
            }
        }
    }

    let (heap_base, heap_size) = best_heap.expect("no usable memory region for heap");

    let heap_size = core::cmp::min(heap_size, 4 * 1024 * 1024);

    #[cfg(not(test))]
    unsafe {
        ALLOCATOR
            .lock()
            .init(heap_base as *mut u8, heap_size as usize);
    }
    let _ = writeln!(
        serial,
        "[Heap] Initialized: {} bytes at {:#x}",
        heap_size, heap_base
    );

    // ── Generate Ed25519 identity for Reticulum wire compat ──
    //    PQ identity is generated lazily by the runtime — PQ keygen's
    //    lattice operations overflow the UEFI-provided stack.
    // Coerce the non-capturing closure to a function pointer so the
    // concrete type is `KernelEntropy<fn(&mut [u8])>` — nameable for
    // the RUNTIME static.
    let rndr_fill: fn(&mut [u8]) = |buf: &mut [u8]| {
        unsafe { rndr::fill(buf) };
    };
    let mut entropy = KernelEntropy::new(rndr_fill);

    let identity = PrivateIdentity::generate(&mut entropy);
    let addr = identity.public_identity().address_hash;
    let _ = writeln!(
        serial,
        "[Identity] Ed25519 address: {:02x}{:02x}{:02x}{:02x}...",
        addr[0], addr[1], addr[2], addr[3],
    );

    // ── Create runtime and enter idle loop ──
    let persistence = MemoryState::new();
    let mut runtime = UnikernelRuntime::new(identity, entropy, persistence);

    // Generate PQ identity now that the heap is available.
    if let Some(pq_addr) = runtime.generate_pq_identity() {
        let _ = writeln!(
            serial,
            "[Identity] PQ address (ML-DSA-65/ML-KEM-768): {:02x}{:02x}{:02x}{:02x}...",
            pq_addr[0], pq_addr[1], pq_addr[2], pq_addr[3],
        );
    }

    // Register network interface and announcing destination.
    runtime.register_interface("eth0");
    let dest_hash = runtime.register_announcing_destination(
        "harmony",
        &["node"],
        300_000, // 5-minute announce interval
        timer::now_ms(),
    );
    let _ = writeln!(
        serial,
        "[Boot] Announcing destination: {:02x}{:02x}{:02x}{:02x}",
        dest_hash[0], dest_hash[1], dest_hash[2], dest_hash[3],
    );

    let _ = writeln!(serial, "[Runtime] UnikernelRuntime created");

    // Move runtime to static for access by the system scheduler task.
    unsafe { RUNTIME = Some(runtime) };

    // ── Initialise Linuxulator ──
    // Must happen BEFORE vectors::init() so the SVC dispatch function is
    // installed before any exception can fire.
    {
        use harmony_os::linuxulator::{LinuxSyscall, Linuxulator};

        let _ = writeln!(serial, "[Linux] Initializing Linuxulator");

        let mut linuxulator = Linuxulator::new(DirectBackend::new());
        linuxulator.init_stdio().expect("init_stdio failed");

        // Install scheduler callbacks so blocking syscalls yield the CPU
        // instead of spin-waiting.
        linuxulator.set_block_fn(|op, fd| {
            let reason = match op {
                0 => sched::WaitReason::FdReadable(fd),
                1 => sched::WaitReason::FdWritable(fd),
                2 => sched::WaitReason::FdConnectDone(fd),
                3 => sched::WaitReason::PollWait,
                _ => unreachable!(),
            };
            unsafe { sched::block_current(reason) };
        });

        linuxulator.set_wake_fn(|fd, op| {
            unsafe { sched::wake_by_fd(fd, op) };
        });

        // Thread spawning callback — creates a new scheduler task from clone().
        linuxulator.set_spawn_fn(|pid, tid, tls, clear_child_tid, child_stack| {
            let parent_tf = unsafe { syscall::current_trapframe() };
            if parent_tf.is_null() {
                return None;
            }
            unsafe {
                sched::spawn_task_runtime(
                    "thread",
                    pid,
                    tid,
                    tls,
                    clear_child_tid,
                    parent_tf,
                    child_stack,
                )
            }
            .map(|_idx| tid) // Return the TID on success, not the task index
        });

        // Futex blocking callback — blocks current task on a futex word.
        linuxulator.set_futex_block_fn(|uaddr| {
            unsafe { sched::block_current(sched::WaitReason::Futex(uaddr)) };
        });

        // Futex wake callback — wakes up to `max` tasks blocked on a futex.
        linuxulator.set_futex_wake_fn(|uaddr, max| unsafe { sched::futex_wake(uaddr, max) });

        // Get current thread's TID.
        linuxulator.set_get_current_tid_fn(|| unsafe { sched::current_task_tid() });

        // Set current thread's clear_child_tid address (CLONE_CHILD_CLEARTID).
        linuxulator.set_clear_child_tid_fn(|addr| {
            unsafe { sched::set_current_clear_child_tid(addr) };
        });

        // Move fully-configured Linuxulator to module-level static.
        unsafe { LINUXULATOR = Some(linuxulator) };

        // Install dispatch function for the SVC handler
        fn dispatch(syscall: LinuxSyscall) -> syscall::SyscallDispatchResult {
            let lx = unsafe { LINUXULATOR.as_mut().unwrap() };
            let retval = lx.dispatch_syscall(syscall);
            syscall::SyscallDispatchResult {
                retval,
                exited: lx.exited(),
                exit_code: lx.exit_code().unwrap_or(0),
            }
        }
        unsafe { syscall::set_dispatch_fn(dispatch) };

        let _ = writeln!(serial, "[Linux] Linuxulator ready, SVC dispatch installed");
    }

    // ── Install exception vector table ──
    // Placed AFTER set_dispatch_fn so the SVC handler has a valid
    // dispatch target from the moment exceptions are enabled.
    unsafe { vectors::init() };
    let _ = writeln!(serial, "[Vectors] Exception vector table installed");

    // ── Initialize GICv3 interrupt controller + timer interrupts ──
    // GIC and timer constants are only defined for qemu-virt. RPi5 uses
    // Apple AIC — interrupt support tracked by harmony-os-1hc.
    #[cfg(feature = "qemu-virt")]
    {
        unsafe {
            gic::init(
                platform::GICD_BASE as *mut u8,
                platform::GICR_BASE as *mut u8,
            )
        };
        let _ = writeln!(
            serial,
            "[GIC] GICv3 initialized: GICD={:#x} GICR={:#x}",
            platform::GICD_BASE,
            platform::GICR_BASE,
        );

        // Arm the physical timer at 100 Hz.
        timer::enable_tick(100);
        let _ = writeln!(
            serial,
            "[Timer] 100 Hz tick armed (reload={})",
            timer::freq() / 100,
        );

        // Spawn idle (PID 0), system (PID 1), and elf (PID 2) tasks.
        unsafe { sched::spawn_task("idle", 0, idle_task, &mut bump) };
        let _ = writeln!(serial, "[Sched] Spawned idle task (PID 0)");
        unsafe { sched::spawn_task("system", 1, system_task, &mut bump) };
        let _ = writeln!(serial, "[Sched] Spawned system task (PID 1)");
        unsafe { sched::spawn_task("elf", 2, elf_task, &mut bump) };
        let _ = writeln!(serial, "[Sched] Spawned elf task (PID 2)");

        // Move bump allocator to static for runtime task spawning (Phase 5 threads).
        unsafe { sched::set_bump_allocator(bump) };

        // Enter the scheduler — loads task 0's TrapFrame and erets into it.
        // The eret atomically unmasks IRQs via SPSR (I=0 in INITIAL_SPSR),
        // so we do NOT use `msr daifclr` here.
        let _ = writeln!(serial, "[Sched] Entering scheduler (eret unmasks IRQs)");
        unsafe { sched::enter_scheduler() };
    }

    // ── Phase 3: Load and run embedded test ELF ──
    let test_exit_code: i64;
    {
        use harmony_microkernel::vm::{FrameClassification, PageFlags, VmError};
        use harmony_os::elf_loader::{ElfLoader, InterpreterLoader};
        use harmony_os::linuxulator::SyscallBackend;

        // Embedded at compile time from the cross-compiled test binary.
        // Path: crates/harmony-test-elf/target/aarch64-unknown-linux-musl/release/
        static TEST_ELF: &[u8] = include_bytes!(
            "../../../crates/harmony-test-elf/target/aarch64-unknown-linux-musl/release/harmony-test-elf"
        );

        let _ = writeln!(
            serial,
            "[ELF] Loading test binary ({} bytes)",
            TEST_ELF.len()
        );

        // Bare-metal identity-map backend for the ELF loader.
        //
        // With the MMU identity map active, all RAM is directly
        // accessible at its physical address.  vm_mmap just returns the
        // requested address (no page table manipulation needed — the
        // identity map already covers it).  vm_write_bytes uses the
        // default unsafe ptr::copy implementation.
        struct IdentityMapBackend;

        impl SyscallBackend for IdentityMapBackend {
            fn walk(
                &mut self,
                _path: &str,
                _new_fid: harmony_microkernel::Fid,
            ) -> Result<harmony_microkernel::QPath, harmony_microkernel::IpcError> {
                Err(harmony_microkernel::IpcError::NotFound)
            }
            fn open(
                &mut self,
                _fid: harmony_microkernel::Fid,
                _mode: harmony_microkernel::OpenMode,
            ) -> Result<(), harmony_microkernel::IpcError> {
                Err(harmony_microkernel::IpcError::NotFound)
            }
            fn read(
                &mut self,
                _fid: harmony_microkernel::Fid,
                _offset: u64,
                _count: u32,
            ) -> Result<alloc::vec::Vec<u8>, harmony_microkernel::IpcError> {
                Err(harmony_microkernel::IpcError::NotFound)
            }
            fn write(
                &mut self,
                _fid: harmony_microkernel::Fid,
                _offset: u64,
                _data: &[u8],
            ) -> Result<u32, harmony_microkernel::IpcError> {
                Err(harmony_microkernel::IpcError::NotFound)
            }
            fn clunk(
                &mut self,
                _fid: harmony_microkernel::Fid,
            ) -> Result<(), harmony_microkernel::IpcError> {
                Ok(())
            }
            fn stat(
                &mut self,
                _fid: harmony_microkernel::Fid,
            ) -> Result<harmony_microkernel::FileStat, harmony_microkernel::IpcError> {
                Err(harmony_microkernel::IpcError::NotFound)
            }

            fn has_vm_support(&self) -> bool {
                true
            }

            fn vm_mmap(
                &mut self,
                vaddr: u64,
                _len: usize,
                _flags: PageFlags,
                _classification: FrameClassification,
            ) -> Result<u64, VmError> {
                // Identity-mapped: the address is already accessible.
                Ok(vaddr)
            }

            fn vm_munmap(&mut self, _vaddr: u64, _len: usize) -> Result<(), VmError> {
                Ok(())
            }

            fn vm_mprotect(
                &mut self,
                _vaddr: u64,
                _len: usize,
                _flags: PageFlags,
            ) -> Result<(), VmError> {
                // No-op: identity map has full RWX in EL1.
                Ok(())
            }

            fn vm_find_free_region(&self, _len: usize) -> Result<u64, VmError> {
                Err(VmError::PageTableError)
            }
        }

        let mut backend = IdentityMapBackend;
        let mut loader = InterpreterLoader::default();

        match loader.load(TEST_ELF, &mut backend) {
            Ok(load_result) => {
                let _ = writeln!(serial, "[ELF] Loaded: entry={:#x}", load_result.entry_point,);

                // Allocate an 8 KiB stack (2 pages) for the test binary.
                let stack_base = bump.alloc_frame().expect("stack page 1 alloc failed").0;
                let stack_page2 = bump.alloc_frame().expect("stack page 2 alloc failed").0;
                assert_eq!(
                    stack_page2,
                    stack_base + 4096,
                    "stack pages must be contiguous"
                );
                let stack_top = stack_base + 8192;

                let _ = writeln!(
                    serial,
                    "[ELF] Stack: base={:#x} top={:#x}",
                    stack_base, stack_top,
                );

                // Flush instruction cache for the loaded ELF text segment.
                // The ELF data was written via store instructions (D-cache) but
                // will be fetched via I-cache.  Without explicit cache maintenance,
                // the I-cache may hold stale (zero) data from before the write.
                unsafe {
                    // Use the ELF file size as the flush range — this is an upper
                    // bound on the loaded data, so it always covers all segments
                    // regardless of binary size or segment layout.
                    let start = load_result.entry_point & !0xFFFF; // page-align down
                    let end = start + (TEST_ELF.len() as u64);
                    let mut addr = start;
                    while addr < end {
                        core::arch::asm!("dc cvau, {}", in(reg) addr);
                        addr += 64;
                    }
                    core::arch::asm!("dsb ish");
                    addr = start;
                    while addr < end {
                        core::arch::asm!("ic ivau, {}", in(reg) addr);
                        addr += 64;
                    }
                    core::arch::asm!("dsb ish", "isb");
                }

                let _ = writeln!(serial, "[ELF] Jumping to entry point...");

                let code = unsafe { run_elf_binary(load_result.entry_point, stack_top) };
                // Clear stale return context so a future exit_group doesn't
                // redirect to an invalid stack frame.
                unsafe { syscall::reset_return_context() };
                test_exit_code = code;

                let _ = writeln!(serial, "[ELF] Test binary exited with code {}", code,);
            }
            Err(e) => {
                let _ = writeln!(serial, "[ELF] FATAL: Load failed: {:?}", e);
                test_exit_code = -1;
            }
        }
    }

    // ── GENET Ethernet initialization (RPi5 only) ──
    #[cfg(feature = "rpi5")]
    let (mut genet_driver, mut genet_bank, mut tx_pool, mut rx_pool) = {
        use harmony_unikernel::drivers::dma_pool::{DmaBuffer, DmaPool};
        use harmony_unikernel::drivers::genet::GenetDriver;

        let mut bank = unsafe { mmio::MmioRegisterBank::new(platform::GENET_BASE) };
        let mac = platform::NODE_MAC;
        let _ = writeln!(
            serial,
            "[GENET] Initializing at {:#x}, MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            platform::GENET_BASE,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
        );

        let driver = match GenetDriver::<256, 256>::init(&mut bank, mac, 1000) {
            Ok(d) => {
                let _ = writeln!(serial, "[GENET] Driver initialized");
                d
            }
            Err(e) => {
                let _ = writeln!(serial, "[GENET] FATAL: init failed: {:?}", e);
                panic!("GENET init failed");
            }
        };

        // Allocate DMA buffer pools from bump allocator.
        // Each page = 4 KiB, one 2048-byte DMA buffer per page.
        let mut tx_bufs = [DmaBuffer {
            virt: core::ptr::null_mut(),
            phys: 0,
        }; 256];
        for buf in tx_bufs.iter_mut() {
            let frame = bump.alloc_frame().expect("TX DMA buffer alloc failed");
            *buf = DmaBuffer {
                virt: frame.as_u64() as *mut u8,
                phys: frame.as_u64(),
            };
        }
        let tx_pool = DmaPool::new(tx_bufs, 2048);

        let mut rx_bufs = [DmaBuffer {
            virt: core::ptr::null_mut(),
            phys: 0,
        }; 256];
        for buf in rx_bufs.iter_mut() {
            let frame = bump.alloc_frame().expect("RX DMA buffer alloc failed");
            *buf = DmaBuffer {
                virt: frame.as_u64() as *mut u8,
                phys: frame.as_u64(),
            };
        }
        let mut rx_pool = DmaPool::new(rx_bufs, 2048);

        (driver, bank, tx_pool, rx_pool)
    };

    // Arm RX descriptors with DMA buffer addresses.
    #[cfg(feature = "rpi5")]
    {
        if let Err(e) = genet_driver.arm_rx_descriptors(&mut genet_bank, &mut rx_pool) {
            let _ = writeln!(serial, "[GENET] FATAL: arm RX failed: {:?}", e);
            panic!("GENET arm_rx_descriptors failed");
        }
        let _ = writeln!(serial, "[GENET] RX armed: 256 descriptors");
    }

    let _ = writeln!(
        serial,
        "[Boot] Entering event loop (test exit code: {})",
        test_exit_code,
    );

    let runtime = unsafe { RUNTIME.as_mut().unwrap() };

    loop {
        let now = timer::now_ms();

        // ── Network RX (RPi5 GENET) ──
        #[cfg(feature = "rpi5")]
        {
            // Invalidate all RX DMA buffers before polling — ensures CPU sees
            // data written by GENET's non-coherent PCIe DMA, not stale cache lines.
            for i in 0..256usize {
                let buf = rx_pool.get(i);
                unsafe { cache::invalidate_range(buf.virt, 2048) };
            }

            while let Some(frame) = genet_driver.poll_rx(&mut genet_bank, &mut rx_pool) {
                if frame.data.len() >= 14 {
                    let ethertype = u16::from_be_bytes([frame.data[12], frame.data[13]]);
                    if ethertype == 0x88B5 {
                        // Raw Harmony frame — strip Ethernet header
                        let payload = frame.data[14..].to_vec();
                        let rx_actions = runtime.handle_packet("eth0", payload, now);
                        for action in &rx_actions {
                            let mut handled = false;
                            // Dispatch TX actions from RX path (e.g., announce responses).
                            if let harmony_unikernel::RuntimeAction::SendOnInterface {
                                interface_name,
                                raw,
                            } = action
                            {
                                if interface_name.as_ref() != "eth0" {
                                    let _ = writeln!(
                                        serial,
                                        "[TX] WARN: unknown interface {:?}, skipping",
                                        interface_name
                                    );
                                } else {
                                    let mac = platform::NODE_MAC;
                                    let mut tx_frame =
                                        alloc::vec::Vec::with_capacity(14 + raw.len());
                                    tx_frame.extend_from_slice(&[0xFF; 6]);
                                    tx_frame.extend_from_slice(&mac);
                                    tx_frame.extend_from_slice(&0x88B5u16.to_be_bytes());
                                    tx_frame.extend_from_slice(raw);
                                    for j in 0..256usize {
                                        let buf = tx_pool.get(j);
                                        unsafe { cache::clean_range(buf.virt, 2048) };
                                    }
                                    genet_driver.reclaim_tx(&genet_bank, &mut tx_pool);
                                    match genet_driver.send(
                                        &mut genet_bank,
                                        &tx_frame,
                                        &mut tx_pool,
                                    ) {
                                        Ok(()) => {
                                            let _ = writeln!(
                                                serial,
                                                "[TX] {} bytes on eth0 (rx-resp)",
                                                tx_frame.len()
                                            );
                                        }
                                        Err(e) => {
                                            let _ = writeln!(
                                                serial,
                                                "[TX] rx-resp send error: {:?}",
                                                e
                                            );
                                        }
                                    }
                                }
                                handled = true;
                            }
                            if !handled {
                                dispatch_action(action, &mut serial);
                            }
                        }
                    }
                }
            }
        }

        // Reclaim completed TX buffers.
        #[cfg(feature = "rpi5")]
        genet_driver.reclaim_tx(&genet_bank, &mut tx_pool);

        // ── Timer tick ──
        let actions = runtime.tick(now);
        for action in &actions {
            // RPi5: handle SendOnInterface by building an Ethernet frame and
            // sending via GENET before falling through to dispatch_action for
            // the serial log.
            #[cfg(feature = "rpi5")]
            {
                let mut sent = false;
                if let harmony_unikernel::RuntimeAction::SendOnInterface {
                    interface_name,
                    raw,
                } = action
                {
                    sent = true;
                    if interface_name.as_ref() != "eth0" {
                        let _ = writeln!(
                            serial,
                            "[TX] WARN: unknown interface {:?}, skipping",
                            interface_name
                        );
                    } else {
                        let mac = platform::NODE_MAC;
                        let mut frame = alloc::vec::Vec::with_capacity(14 + raw.len());
                        // TODO: broadcast dst is correct for Reticulum announces
                        // but wrong for unicast responses. Needs neighbor table.
                        frame.extend_from_slice(&[0xFF; 6]);
                        frame.extend_from_slice(&mac);
                        frame.extend_from_slice(&0x88B5u16.to_be_bytes());
                        frame.extend_from_slice(raw);

                        for i in 0..256usize {
                            let buf = tx_pool.get(i);
                            unsafe { cache::clean_range(buf.virt, 2048) };
                        }
                        genet_driver.reclaim_tx(&genet_bank, &mut tx_pool);
                        match genet_driver.send(&mut genet_bank, &frame, &mut tx_pool) {
                            Ok(()) => {
                                let _ = writeln!(serial, "[TX] {} bytes on eth0", frame.len());
                            }
                            Err(e) => {
                                let _ = writeln!(serial, "[TX] send error: {:?}", e);
                            }
                        }
                    }
                }
                if !sent {
                    dispatch_action(action, &mut serial);
                }
            }
            #[cfg(not(feature = "rpi5"))]
            dispatch_action(action, &mut serial);
        }

        // WFE = Wait For Event — ARM equivalent of HLT, saves power.
        // Timer interrupt will wake us for the next tick.
        unsafe { core::arch::asm!("wfe") };
    }
}

/// Idle task — executes WFI in a loop. Always Ready; the scheduler
/// falls through to it when no other task is schedulable.
#[cfg(all(feature = "qemu-virt", target_os = "uefi"))]
fn idle_task() -> ! {
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

/// System task — network poller and waker.
///
/// Polls smoltcp via the Linuxulator, runs the Harmony runtime tick,
/// then checks all blocked tasks and wakes any whose I/O is ready.
/// This is the sole task that touches LINUXULATOR and RUNTIME in the
/// main loop, ensuring single-threaded access.
#[cfg(all(feature = "qemu-virt", target_os = "uefi"))]
fn system_task() -> ! {
    use core::fmt::Write;
    let mut serial =
        harmony_unikernel::SerialWriter::new(|byte| unsafe { pl011::write_byte(byte) });
    let _ = writeln!(serial, "[System] Event loop started");

    loop {
        let now = timer::now_ms();

        // 1. Poll smoltcp — track whether the network stack had activity
        let linuxulator = unsafe { LINUXULATOR.as_mut().unwrap() };
        let network_polled = linuxulator.poll_network();
        unsafe { NETWORK_CHANGED = network_polled };

        // 2. Run Harmony runtime
        let runtime = unsafe { RUNTIME.as_mut().unwrap() };
        let actions = runtime.tick(now);
        for action in &actions {
            dispatch_action(action, &mut serial);
        }

        // 3. Check blocked tasks — wake any whose I/O is ready
        check_and_wake_blocked_tasks();

        // 4. Low-power wait
        unsafe { core::arch::asm!("wfi") };
    }
}

/// ELF task — loads and runs the embedded test ELF binary.
///
/// Moved out of main() so the ELF binary runs as a separate scheduled
/// task (PID 2) that can be preempted and blocked by the scheduler.
/// DISPATCH_FN is already installed during boot init, so SVC dispatch
/// works from the first instruction of the binary.
#[cfg(all(feature = "qemu-virt", target_os = "uefi"))]
fn elf_task() -> ! {
    use core::fmt::Write;
    use harmony_microkernel::vm::{FrameClassification, PageFlags, VmError};
    use harmony_os::elf_loader::{ElfLoader, InterpreterLoader};
    use harmony_os::linuxulator::SyscallBackend;

    let mut serial =
        harmony_unikernel::SerialWriter::new(|byte| unsafe { pl011::write_byte(byte) });
    let _ = writeln!(serial, "[ELF] Task started");

    // Embedded at compile time from the cross-compiled test binary.
    static TEST_ELF: &[u8] = include_bytes!(
        "../../../crates/harmony-test-elf/target/aarch64-unknown-linux-musl/release/harmony-test-elf"
    );

    let _ = writeln!(
        serial,
        "[ELF] Loading test binary ({} bytes)",
        TEST_ELF.len()
    );

    // Bare-metal identity-map backend for the ELF loader.
    //
    // With the MMU identity map active, all RAM is directly
    // accessible at its physical address. vm_mmap just returns the
    // requested address (no page table manipulation needed — the
    // identity map already covers it).
    struct IdentityMapBackend;

    impl SyscallBackend for IdentityMapBackend {
        fn walk(
            &mut self,
            _path: &str,
            _new_fid: harmony_microkernel::Fid,
        ) -> Result<harmony_microkernel::QPath, harmony_microkernel::IpcError> {
            Err(harmony_microkernel::IpcError::NotFound)
        }
        fn open(
            &mut self,
            _fid: harmony_microkernel::Fid,
            _mode: harmony_microkernel::OpenMode,
        ) -> Result<(), harmony_microkernel::IpcError> {
            Err(harmony_microkernel::IpcError::NotFound)
        }
        fn read(
            &mut self,
            _fid: harmony_microkernel::Fid,
            _offset: u64,
            _count: u32,
        ) -> Result<alloc::vec::Vec<u8>, harmony_microkernel::IpcError> {
            Err(harmony_microkernel::IpcError::NotFound)
        }
        fn write(
            &mut self,
            _fid: harmony_microkernel::Fid,
            _offset: u64,
            _data: &[u8],
        ) -> Result<u32, harmony_microkernel::IpcError> {
            Err(harmony_microkernel::IpcError::NotFound)
        }
        fn clunk(
            &mut self,
            _fid: harmony_microkernel::Fid,
        ) -> Result<(), harmony_microkernel::IpcError> {
            Ok(())
        }
        fn stat(
            &mut self,
            _fid: harmony_microkernel::Fid,
        ) -> Result<harmony_microkernel::FileStat, harmony_microkernel::IpcError> {
            Err(harmony_microkernel::IpcError::NotFound)
        }

        fn has_vm_support(&self) -> bool {
            true
        }

        fn vm_mmap(
            &mut self,
            vaddr: u64,
            _len: usize,
            _flags: PageFlags,
            _classification: FrameClassification,
        ) -> Result<u64, VmError> {
            // Identity-mapped: the address is already accessible.
            Ok(vaddr)
        }

        fn vm_munmap(&mut self, _vaddr: u64, _len: usize) -> Result<(), VmError> {
            Ok(())
        }

        fn vm_mprotect(
            &mut self,
            _vaddr: u64,
            _len: usize,
            _flags: PageFlags,
        ) -> Result<(), VmError> {
            // No-op: identity map has full RWX in EL1.
            Ok(())
        }

        fn vm_find_free_region(&self, _len: usize) -> Result<u64, VmError> {
            Err(VmError::PageTableError)
        }
    }

    let mut backend = IdentityMapBackend;
    let mut loader = InterpreterLoader::default();

    match loader.load(TEST_ELF, &mut backend) {
        Ok(load_result) => {
            let _ = writeln!(serial, "[ELF] Loaded: entry={:#x}", load_result.entry_point);

            // Allocate an 8 KiB stack (2 pages) for the test binary.
            // Uses the heap allocator since we don't have access to the bump
            // allocator from this task context.
            let stack_layout = core::alloc::Layout::from_size_align(8192, 4096).unwrap();
            let stack_base = unsafe { alloc::alloc::alloc(stack_layout) } as u64;
            assert!(stack_base != 0, "stack alloc failed");
            let stack_top = stack_base + 8192;

            let _ = writeln!(
                serial,
                "[ELF] Stack: base={:#x} top={:#x}",
                stack_base, stack_top,
            );

            // Flush instruction cache for the loaded ELF text segment.
            unsafe {
                let start = load_result.entry_point & !0xFFFF; // page-align down
                let end = start + (TEST_ELF.len() as u64);
                let mut addr = start;
                while addr < end {
                    core::arch::asm!("dc cvau, {}", in(reg) addr);
                    addr += 64;
                }
                core::arch::asm!("dsb ish");
                addr = start;
                while addr < end {
                    core::arch::asm!("ic ivau, {}", in(reg) addr);
                    addr += 64;
                }
                core::arch::asm!("dsb ish", "isb");
            }

            let _ = writeln!(serial, "[ELF] Jumping to entry point...");

            let code = unsafe { run_elf_binary(load_result.entry_point, stack_top) };
            // Clear stale return context so a future exit_group doesn't
            // redirect to an invalid stack frame.
            unsafe { syscall::reset_return_context() };

            let _ = writeln!(serial, "[ELF] Test binary exited with code {}", code);
        }
        Err(e) => {
            let _ = writeln!(serial, "[ELF] FATAL: Load failed: {:?}", e);
        }
    }

    let _ = writeln!(serial, "[ELF] Binary exited, task halting");
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

/// Check all blocked tasks and wake any whose I/O condition is satisfied.
///
/// Called by the system task after polling smoltcp. Uses the Linuxulator's
/// `is_wait_ready` to evaluate whether each blocked task's wait condition
/// has been met.
#[cfg(all(feature = "qemu-virt", target_os = "uefi"))]
fn check_and_wake_blocked_tasks() {
    let linuxulator = unsafe { LINUXULATOR.as_ref().unwrap() };
    let network_changed = unsafe { NETWORK_CHANGED };
    unsafe {
        sched::for_each_blocked(|idx, reason| {
            match reason {
                sched::WaitReason::PollWait => {
                    // Only wake poll/select/epoll tasks when the network stack
                    // actually processed packets. Without this gate, PollWait
                    // tasks would be woken every system-task iteration (busy-poll).
                    if network_changed {
                        sched::wake(idx);
                    }
                }
                sched::WaitReason::FdReadable(fd) => {
                    if linuxulator.is_wait_ready(0, fd) {
                        sched::wake(idx);
                    }
                }
                sched::WaitReason::FdWritable(fd) => {
                    if linuxulator.is_wait_ready(1, fd) {
                        sched::wake(idx);
                    }
                }
                sched::WaitReason::FdConnectDone(fd) => {
                    if linuxulator.is_wait_ready(2, fd) {
                        sched::wake(idx);
                    }
                }
                sched::WaitReason::Futex(_) => {
                    // Futex waiters are woken by futex_wake(), not by I/O
                    // readiness. The system task has nothing to do here.
                }
            }
        });
    }
}

#[cfg(target_os = "uefi")]
fn dispatch_action(action: &harmony_unikernel::RuntimeAction, serial: &mut impl core::fmt::Write) {
    use harmony_unikernel::RuntimeAction;
    match action {
        RuntimeAction::SendOnInterface {
            interface_name,
            raw,
        } => {
            let _ = writeln!(serial, "[TX] {} bytes on {}", raw.len(), interface_name);
        }
        RuntimeAction::PeerDiscovered { address_hash, hops } => {
            let _ = writeln!(
                serial,
                "[Peer] Discovered {:02x}{:02x}{:02x}{:02x} ({} hops)",
                address_hash[0], address_hash[1], address_hash[2], address_hash[3], hops,
            );
        }
        RuntimeAction::PeerLost { address_hash } => {
            let _ = writeln!(
                serial,
                "[Peer] Lost {:02x}{:02x}{:02x}{:02x}",
                address_hash[0], address_hash[1], address_hash[2], address_hash[3],
            );
        }
        RuntimeAction::HeartbeatReceived {
            address_hash,
            uptime_ms,
        } => {
            let _ = writeln!(
                serial,
                "[Peer] Heartbeat {:02x}{:02x}{:02x}{:02x} uptime={}ms",
                address_hash[0], address_hash[1], address_hash[2], address_hash[3], uptime_ms,
            );
        }
        RuntimeAction::DeliverLocally {
            destination_hash,
            payload,
        } => {
            let _ = writeln!(
                serial,
                "[Local] {} bytes for {:02x}{:02x}{:02x}{:02x}",
                payload.len(),
                destination_hash[0],
                destination_hash[1],
                destination_hash[2],
                destination_hash[3],
            );
        }
    }
}

// ── ELF binary trampoline ─────────────────────────────────────────────
// Saves kernel context (SP, LR), installs a return-address for the SVC
// handler's exit_group path, switches to the binary's stack, and jumps
// to the ELF entry point.  When exit_group fires, the SVC handler
// rewrites ELR to .Lelf_return (via set_return_context), restoring the
// kernel SP and LR so that `ret` returns to the Rust caller.

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global run_elf_binary",
    "run_elf_binary:",
    // x0 = entry_point, x1 = stack_top
    // AAPCS64 prologue: save callee-saved regs + LR
    "stp x19, x20, [sp, #-32]!",
    "stp x29, x30, [sp, #16]",
    "mov x29, sp",
    // Save args in callee-saved regs
    "mov x19, x0", // x19 = entry_point
    "mov x20, x1", // x20 = stack_top
    // Register return context for the SVC handler's exit_group path.
    // SP is captured AFTER the prologue push so .Lelf_return can pop.
    "adr x0, .Lelf_return", // arg0 = return address
    "mov x1, sp",           // arg1 = kernel SP (post-prologue)
    "mov x2, x30",          // arg2 = kernel LR
    "bl set_return_context",
    // Switch to binary stack and jump to entry
    "mov sp, x20",
    "br x19",
    // Landing pad — SVC handler sets ELR here on exit_group.
    // Register state is fully controlled by the TrapFrame restore:
    //   x0 = exit code
    //   x1 = saved kernel SP (post-prologue)
    //   x2 = saved kernel LR
    ".Lelf_return:",
    "mov sp, x1", // restore kernel SP (post-prologue)
    // AAPCS64 epilogue: restore callee-saved regs + LR
    "ldp x29, x30, [sp, #16]",
    "ldp x19, x20, [sp], #32",
    "ret", // return to Rust caller with exit code in x0
);

#[cfg(target_arch = "aarch64")]
extern "C" {
    /// Run an ELF binary at `entry_point` with `stack_top` as its SP.
    ///
    /// Returns the process exit code when exit_group fires.  The SVC
    /// handler redirects control to `.Lelf_return` which restores the
    /// kernel context and returns here.
    fn run_elf_binary(entry_point: u64, stack_top: u64) -> i64;
}

// ── Panic handler ──────────────────────────────────────────────────────
// The uefi crate's panic_handler feature is disabled because after
// ExitBootServices the UEFI console is gone. This custom handler
// prints to PL011 serial so panics are visible in QEMU.

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        let mut serial = harmony_unikernel::SerialWriter::new(|byte: u8| {
            unsafe { pl011::write_byte(byte) };
        });
        use core::fmt::Write;
        let _ = writeln!(serial, "\n!!! PANIC: {}", info);
    }
    loop {
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfe")
        };
        #[cfg(not(target_arch = "aarch64"))]
        core::hint::spin_loop();
    }
}
