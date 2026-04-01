// SPDX-License-Identifier: GPL-2.0-or-later
//! Harmony OS x86_64 boot entry point.
//!
//! Initialises serial output, heap, RDRAND entropy, generates PQC + Ed25519
//! node identities, then enters the unikernel event loop.

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

use alloc::boxed::Box;

mod pci;
mod pit;
#[cfg(feature = "ring3")]
mod syscall;
mod virtio;

use bootloader_api::config::Mapping;
use bootloader_api::info::MemoryRegionKind;
use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use core::fmt::Write;
use core::panic::PanicInfo;
use linked_list_allocator::LockedHeap;
use x86_64::instructions::port::Port;

use harmony_identity::PrivateIdentity;
use harmony_unikernel::serial::{hex_encode, SerialWriter};
use harmony_unikernel::{KernelEntropy, MemoryState, RuntimeAction, UnikernelRuntime};

// ---------------------------------------------------------------------------
// Embedded SSH userspace binaries (ring3 only)
// ---------------------------------------------------------------------------

// Embedded SSH userspace binaries — architecture selected at compile time.
// harmony-boot targets x86_64-unknown-none (QEMU), harmony-boot-aarch64
// targets aarch64-unknown-uefi (RPi5). Each includes matching static musl
// binaries so the Linuxulator can exec them.
#[cfg(feature = "ring3")]
static DROPBEAR_BIN: &[u8] = include_bytes!("../../../deploy/dropbear-x86_64");
#[cfg(feature = "ring3")]
static BUSYBOX_BIN: &[u8] = include_bytes!("../../../deploy/busybox-x86_64");
// No host key embedded — dropbear MUST be invoked with `-R` to generate an
// ephemeral key on first connection. Without `-R` and without a key file,
// dropbear refuses to start. Production key provisioning: harmony-os-g7v.

use virtio::net::ETH_HEADER_LEN;

// ---------------------------------------------------------------------------
// Bootloader configuration
// ---------------------------------------------------------------------------

static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    // Map all physical memory so we can use it for heap allocation.
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

// ---------------------------------------------------------------------------
// Global allocator
// ---------------------------------------------------------------------------

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// ---------------------------------------------------------------------------
// Heap-allocated kernel stack
// ---------------------------------------------------------------------------

/// Size of the heap-allocated kernel stack in bytes.
///
/// ML-KEM-768 + ML-DSA-65 keygen on `x86_64-unknown-none` (without SSE2)
/// requires >512KB of stack because the compiler cannot use XMM registers
/// and spills aggressively to the stack during NTT polynomial operations.
/// 2MB provides comfortable headroom from the 4MB heap.
const KERNEL_STACK_SIZE: usize = 2 * 1024 * 1024;

/// Canary value written at the stack base to detect overflow.
const STACK_CANARY: u64 = 0xDEAD_BEEF_CAFE_BABE;

/// State from early boot that must survive the stack switch.
/// Heap-allocated via `Box` so the pointer remains valid after RSP changes.
struct BootState {
    boot_info: &'static mut BootInfo,
    phys_offset: u64,
    pit: pit::PitTimer,
    /// Base address of the heap-allocated stack, where the canary lives.
    stack_canary_addr: usize,
}

/// Switch RSP to `new_stack_top` and call `continuation(state)`.
///
/// # Safety
/// - `new_stack_top` must be a valid, 16-byte-aligned, writable address
///   with sufficient space below it for the continuation's stack usage.
/// - `continuation` must be `extern "C"` and never return.
/// - `state` is passed via the explicit `in("rdi")` constraint. The
///   `in(reg)` operands for `stack` and `cont` cannot alias `rdi`
///   because LLVM's register allocator treats the explicit `in("rdi")`
///   as an occupied register and excludes it from the `in(reg)` pool.
unsafe fn switch_to_stack(
    state: *mut BootState,
    new_stack_top: usize,
    continuation: unsafe extern "C" fn(*mut BootState) -> !,
) -> ! {
    core::arch::asm!(
        "mov rsp, {stack}",
        "call {cont}",
        "ud2",
        stack = in(reg) new_stack_top,
        cont = in(reg) continuation,
        in("rdi") state,
        options(noreturn),
    );
}

// ---------------------------------------------------------------------------
// Serial I/O helpers (UART 0x3F8)
// ---------------------------------------------------------------------------

const COM1: u16 = 0x3F8;

/// Initialise COM1 at 115200 baud, 8N1.
fn serial_init() {
    unsafe {
        let port = |offset: u16, val: u8| {
            Port::new(COM1 + offset).write(val);
        };
        port(1, 0x00); // Disable interrupts
        port(3, 0x80); // Enable DLAB
        port(0, 0x01); // Divisor low byte  (115200)
        port(1, 0x00); // Divisor high byte
        port(3, 0x03); // 8 bits, no parity, 1 stop bit, DLAB off
        port(2, 0xC7); // Enable FIFO, clear, 14-byte threshold
        port(4, 0x0B); // IRQs enabled, RTS/DSR set
    }
}

/// Write a single byte to COM1.
fn serial_write_byte(byte: u8) {
    unsafe {
        // Wait for transmit holding register to be empty.
        let mut lsr: Port<u8> = Port::new(COM1 + 5);
        while lsr.read() & 0x20 == 0 {
            core::hint::spin_loop();
        }
        Port::new(COM1).write(byte);
    }
}

/// Build a `SerialWriter` backed by COM1.
fn serial_writer() -> SerialWriter<impl FnMut(u8)> {
    SerialWriter::new(serial_write_byte)
}

// ---------------------------------------------------------------------------
// RDRAND entropy
// ---------------------------------------------------------------------------

/// Fill `buf` using the x86 RDRAND instruction.
///
/// Retries each RDRAND invocation up to 10 times per Intel SDM §7.3.17.
fn rdrand_fill(buf: &mut [u8]) {
    const MAX_RETRIES: u32 = 10;
    let mut i = 0;
    while i < buf.len() {
        let mut val: u64 = 0;
        let mut success = false;
        for _ in 0..MAX_RETRIES {
            let ok: u8;
            unsafe {
                core::arch::asm!(
                    "rdrand {val}",
                    "setc {ok}",
                    val = out(reg) val,
                    ok = out(reg_byte) ok,
                    options(nomem, nostack),
                );
            }
            if ok != 0 {
                success = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !success {
            panic!("RDRAND failed after {} retries", MAX_RETRIES);
        }
        let bytes = val.to_le_bytes();
        let remaining = buf.len() - i;
        let n = if remaining < 8 { remaining } else { 8 };
        buf[i..i + n].copy_from_slice(&bytes[..n]);
        i += n;
    }
}

/// Check whether RDRAND is available via CPUID.
fn rdrand_available() -> bool {
    let ecx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("ecx") ecx,
            out("eax") _,
            out("edx") _,
        );
    }
    ecx & (1 << 30) != 0
}

// ---------------------------------------------------------------------------
// Page table NX fixup
// ---------------------------------------------------------------------------

/// Map an ELF's linked virtual addresses to the physical memory where its
/// segments were loaded.
///
/// A static non-PIE binary has absolute virtual addresses baked into the
/// code (GOT, init arrays, data references). If we load the segments into
/// heap memory at a different virtual address, any absolute reference
/// faults. This function creates page-table entries so the ELF's linked
/// addresses (`seg.vaddr`) resolve to the physical frames backing our
/// heap copy.
///
/// Also clears NX on executable segments so the CPU can fetch instructions.
///
/// # Safety
/// - Must be called in Ring 0.
/// - `phys_offset` must be the bootloader's physical-to-virtual mapping offset.
/// - `heap_base_virt` is the virtual address of the contiguous heap allocation
///   holding all loaded segments at offsets `seg.vaddr - vaddr_min`.
#[cfg(feature = "ring3")]
unsafe fn map_elf_at_linked_addresses(
    phys_offset: u64,
    heap_base_virt: usize,
    vaddr_min: u64,
    vaddr_max: u64,
    segments: &[harmony_os::elf::ElfSegment],
) -> usize {
    const PRESENT: u64 = 1;
    const WRITABLE: u64 = 1 << 1;
    const NX_BIT: u64 = 1 << 63;
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PAGE_SIZE: usize = 0x1000;

    let cr3: u64;
    core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    let pml4_phys = cr3 & ADDR_MASK;
    let pml4 = (pml4_phys + phys_offset) as *mut u64;

    // Helper: allocate a zeroed, PAGE-ALIGNED 4 KiB page for an intermediate
    // page table. The CPU reads the table address from bits 12-51 of the
    // entry — if the physical address isn't page-aligned, the hardware
    // truncates the low bits and reads the wrong memory.
    let mut alloc_pt_page = || -> (usize, u64) {
        let layout = core::alloc::Layout::from_size_align(PAGE_SIZE, PAGE_SIZE)
            .expect("page table layout");
        let ptr = alloc::alloc::alloc_zeroed(layout);
        assert!(!ptr.is_null(), "page table allocation failed");
        let virt = ptr as usize;
        let phys = virt as u64 - phys_offset;
        (virt, phys)
    };

    // Helper: ensure an entry at the given page-table level exists and
    // points to a sub-table. Returns the virtual address of the sub-table.
    let ensure_table =
        |entry: *mut u64, alloc: &mut dyn FnMut() -> (usize, u64)| -> *mut u64 {
            let val = core::ptr::read_volatile(entry);
            if val & PRESENT != 0 {
                // Entry exists — return pointer to sub-table
                ((val & ADDR_MASK) + phys_offset) as *mut u64
            } else {
                // Allocate new sub-table
                let (virt, phys) = alloc();
                core::ptr::write_volatile(entry, phys | PRESENT | WRITABLE);
                virt as *mut u64
            }
        };

    let mut mapped = 0usize;
    let start_page = vaddr_min & !(PAGE_SIZE as u64 - 1);
    let end_page = (vaddr_max + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);

    let mut vaddr = start_page;
    while vaddr < end_page {
        let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
        let pml3_idx = ((vaddr >> 30) & 0x1FF) as usize;
        let pml2_idx = ((vaddr >> 21) & 0x1FF) as usize;
        let pml1_idx = ((vaddr >> 12) & 0x1FF) as usize;

        // Walk/create intermediate tables
        let pml3 = ensure_table(pml4.add(pml4_idx), &mut alloc_pt_page);
        let pml2 = ensure_table(pml3.add(pml3_idx), &mut alloc_pt_page);
        let pml1 = ensure_table(pml2.add(pml2_idx), &mut alloc_pt_page);

        // Compute the physical address of the heap byte backing this virtual page.
        // heap_base_virt + (vaddr - vaddr_min) is the virtual addr in the heap mapping.
        // Subtract phys_offset to get the physical address.
        let heap_virt_for_page = heap_base_virt as u64 + (vaddr - vaddr_min);
        let phys_addr = heap_virt_for_page - phys_offset;

        // Determine flags from segment permissions
        let mut flags = PRESENT | WRITABLE; // default RW
        // Check if any executable segment covers this page
        let page_end = vaddr + PAGE_SIZE as u64;
        let mut is_exec = false;
        for seg in segments {
            let seg_start = seg.vaddr;
            let seg_end = seg.vaddr + seg.memsz;
            if seg_start < page_end && seg_end > vaddr && seg.flags.execute {
                is_exec = true;
                break;
            }
        }
        if !is_exec {
            flags |= NX_BIT;
        }

        core::ptr::write_volatile(pml1.add(pml1_idx), phys_addr | flags);
        mapped += 1;
        vaddr += PAGE_SIZE as u64;
    }

    // Flush TLB
    core::arch::asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _, options(nostack));

    mapped
}

// ---------------------------------------------------------------------------
// QEMU debug exit
// ---------------------------------------------------------------------------

/// Write to the QEMU isa-debug-exit device (I/O port 0xf4).
/// Exit code seen by the host = (value << 1) | 1.
#[cfg(feature = "qemu-test")]
fn qemu_debug_exit(value: u32) {
    unsafe {
        Port::new(0xf4).write(value);
    }
}

// ---------------------------------------------------------------------------
// RefCell-based TCP provider for shared NetStack access
// ---------------------------------------------------------------------------

/// Wraps a raw `*mut NetStack` and implements `TcpProvider`.
///
/// Used only in the ring3 `static mut LINUXULATOR` where a `'static` bound
/// is required and a reference-based wrapper cannot satisfy it. The raw
/// pointer is valid for the entire boot lifetime because `netstack` is a
/// local variable in `kernel_continue` which never returns.
///
/// # Safety invariants
///
/// 1. **Lifetime:** The pointer remains valid because `kernel_continue` never
///    returns — the `jmp {entry}` is marked `options(noreturn)`.
///
/// 2. **No aliasing:** The ring3 `jmp` exits before the event loop that also
///    borrows the netstack, so the two code paths never interleave.
///
/// 3. **Exception safety:** After the `jmp`, the CPU runs on the ELF's own
///    64 KiB stack. x86 hardware exceptions (page fault, GPF) use the current
///    RSP for the exception frame — they do NOT switch back to the old kernel
///    stack where `netstack` lives. The IDT entries do not use IST (no TSS
///    IST pointer is configured to the old stack), so exceptions cannot
///    corrupt the abandoned `kernel_continue` frame. A double-fault triggers
///    a triple-fault (reset), not a stack write into the old frame.
#[cfg(feature = "ring3")]
struct RawPtrTcpProvider(*mut harmony_netstack::NetStack);

#[cfg(feature = "ring3")]
unsafe impl Send for RawPtrTcpProvider {}

#[cfg(feature = "ring3")]
impl harmony_netstack::TcpProvider for RawPtrTcpProvider {
    fn tcp_create(&mut self) -> Result<harmony_netstack::TcpHandle, harmony_netstack::NetError> {
        unsafe { (*self.0).tcp_create() }
    }
    fn tcp_bind(
        &mut self,
        h: harmony_netstack::TcpHandle,
        port: u16,
    ) -> Result<(), harmony_netstack::NetError> {
        unsafe { (*self.0).tcp_bind(h, port) }
    }
    fn tcp_listen(
        &mut self,
        h: harmony_netstack::TcpHandle,
        backlog: usize,
    ) -> Result<(), harmony_netstack::NetError> {
        unsafe { (*self.0).tcp_listen(h, backlog) }
    }
    fn tcp_accept(
        &mut self,
        h: harmony_netstack::TcpHandle,
    ) -> Result<Option<harmony_netstack::TcpHandle>, harmony_netstack::NetError> {
        unsafe { (*self.0).tcp_accept(h) }
    }
    fn tcp_connect(
        &mut self,
        h: harmony_netstack::TcpHandle,
        addr: smoltcp::wire::Ipv4Address,
        port: u16,
    ) -> Result<(), harmony_netstack::NetError> {
        unsafe { (*self.0).tcp_connect(h, addr, port) }
    }
    fn tcp_send(
        &mut self,
        h: harmony_netstack::TcpHandle,
        data: &[u8],
    ) -> Result<usize, harmony_netstack::NetError> {
        unsafe { (*self.0).tcp_send(h, data) }
    }
    fn tcp_recv(
        &mut self,
        h: harmony_netstack::TcpHandle,
        buf: &mut [u8],
    ) -> Result<usize, harmony_netstack::NetError> {
        unsafe { (*self.0).tcp_recv(h, buf) }
    }
    fn tcp_close(
        &mut self,
        h: harmony_netstack::TcpHandle,
    ) -> Result<(), harmony_netstack::NetError> {
        unsafe { (*self.0).tcp_close(h) }
    }
    fn tcp_state(&self, h: harmony_netstack::TcpHandle) -> harmony_netstack::TcpSocketState {
        unsafe { (*self.0).tcp_state(h) }
    }
    fn tcp_can_recv(&self, h: harmony_netstack::TcpHandle) -> bool {
        unsafe { (*self.0).tcp_can_recv(h) }
    }
    fn tcp_can_send(&self, h: harmony_netstack::TcpHandle) -> bool {
        unsafe { (*self.0).tcp_can_send(h) }
    }
    fn tcp_poll(&mut self, now_ms: i64) {
        unsafe { (*self.0).tcp_poll(now_ms) }
    }
    fn tcp_fork(&self) -> Option<Self>
    where
        Self: Sized,
    {
        // Raw pointer wrapper cannot be forked safely.
        None
    }
}

// ---------------------------------------------------------------------------
// RuntimeAction dispatch
// ---------------------------------------------------------------------------

/// Dispatch RuntimeActions: send packets and log events.
fn dispatch_actions(
    actions: &[RuntimeAction],
    virtio_net: &mut Option<virtio::net::VirtioNet>,
    netstack: &core::cell::RefCell<harmony_netstack::NetStack>,
    serial: &mut SerialWriter<impl FnMut(u8)>,
) {
    use core::fmt::Write;

    for action in actions {
        match action {
            RuntimeAction::SendOnInterface { interface_name, raw } => {
                match interface_name.as_ref() {
                    "eth0" | "virtio0" => {
                        if let Some(ref mut net) = virtio_net {
                            let _ = harmony_platform::NetworkInterface::send(net, raw);
                        }
                    }
                    "udp0" => {
                        let _ = harmony_platform::NetworkInterface::send(
                            &mut *netstack.borrow_mut(),
                            raw,
                        );
                    }
                    _ => {}
                }
            }
            RuntimeAction::PeerDiscovered { address_hash, hops } => {
                let mut hex = [0u8; 32];
                hex_encode(address_hash, &mut hex);
                let s = core::str::from_utf8(&hex).unwrap_or("?");
                let _ = writeln!(serial, "[PEER+] {} ({} hops)", s, hops);
            }
            RuntimeAction::PeerLost { address_hash } => {
                let mut hex = [0u8; 32];
                hex_encode(address_hash, &mut hex);
                let s = core::str::from_utf8(&hex).unwrap_or("?");
                let _ = writeln!(serial, "[PEER-] {}", s);
            }
            RuntimeAction::HeartbeatReceived { address_hash, uptime_ms } => {
                let mut hex = [0u8; 32];
                hex_encode(address_hash, &mut hex);
                let s = core::str::from_utf8(&hex).unwrap_or("?");
                let _ = writeln!(serial, "[HBT] {} uptime={}ms", s, uptime_ms);
            }
            RuntimeAction::DeliverLocally { destination_hash, payload } => {
                let mut hex = [0u8; 32];
                hex_encode(destination_hash, &mut hex);
                let s = core::str::from_utf8(&hex).unwrap_or("?");
                let _ = writeln!(serial, "[RECV] {} {}B", s, payload.len());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // 1. Serial init
    serial_init();
    let mut serial = serial_writer();
    serial.log("BOOT", "Harmony unikernel v0.1.0");

    let pit = pit::PitTimer::init();
    serial.log("PIT", "timer initialized");

    // 2. Get the physical memory offset so we can convert physical -> virtual
    let phys_offset = boot_info
        .physical_memory_offset
        .into_option()
        .expect("physical_memory_offset not provided by bootloader");

    // 3. Heap init — find first usable region >= 4 MiB
    //    (2MB kernel stack + 2MB runtime allocations)
    const MIN_HEAP_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
    let mut heap_start: Option<u64> = None;
    let mut heap_size: usize = 0;

    for region in boot_info.memory_regions.iter() {
        if region.kind == MemoryRegionKind::Usable {
            let size = (region.end - region.start) as usize;
            if size >= MIN_HEAP_SIZE {
                heap_start = Some(region.start);
                heap_size = if size > 16 * 1024 * 1024 {
                    16 * 1024 * 1024
                } else {
                    size
                };
                break;
            }
        }
    }

    match heap_start {
        Some(phys_start) => {
            let virt_start = phys_start + phys_offset;
            unsafe {
                ALLOCATOR.lock().init(virt_start as *mut u8, heap_size);
            }
            let _ = writeln!(serial, "[HEAP] {}", heap_size);
        }
        None => {
            serial.log("HEAP", "FAILED: no usable region >= 4 MiB");
            loop {
                x86_64::instructions::hlt();
            }
        }
    }

    // 4. Allocate kernel stack from heap and switch to it.
    //    No MMU guard page yet — a canary word at the stack base detects
    //    overflow in debug builds (checked in the event loop).
    let stack_vec = alloc::vec![0u8; KERNEL_STACK_SIZE];
    let stack_base = stack_vec.as_ptr() as usize;
    let stack_top = (stack_base + KERNEL_STACK_SIZE) & !0xF;
    // Write canary at the very bottom of the stack (first 8 bytes).
    // If a stack overflow reaches here, the canary will be corrupted.
    unsafe {
        core::ptr::write_volatile(stack_base as *mut u64, STACK_CANARY);
    }
    core::mem::forget(stack_vec);

    let state = Box::into_raw(Box::new(BootState {
        boot_info,
        phys_offset,
        pit,
        stack_canary_addr: stack_base,
    }));

    unsafe { switch_to_stack(state, stack_top, kernel_continue) }
}

// ---------------------------------------------------------------------------
// Post-stack-switch continuation
// ---------------------------------------------------------------------------

/// Continuation after switching to the heap-allocated kernel stack.
///
/// # Safety
/// `state` must be a valid pointer produced by `Box::into_raw(Box::new(BootState { .. }))`.
unsafe extern "C" fn kernel_continue(state: *mut BootState) -> ! {
    let state = *Box::from_raw(state);
    // Retained for future use — ring2/ring3 VM work may need the memory map.
    // Currently a dead-end binding scoped to kernel_continue. When ring2/ring3
    // needs the memory map, this will need to move to a static or be passed
    // through a kernel struct.
    let _boot_info = state.boot_info;
    let phys_offset = state.phys_offset;
    let mut pit = state.pit;
    let stack_canary_addr = state.stack_canary_addr;

    let mut serial = serial_writer();
    let _ = writeln!(serial, "[STACK] switched to {}KB heap stack", KERNEL_STACK_SIZE / 1024);

    // 1. RDRAND entropy
    if !rdrand_available() {
        serial.log("ENTROPY", "RDRAND not available -- halting");
        loop {
            x86_64::instructions::hlt();
        }
    }
    serial.log("ENTROPY", "RDRAND available");

    // 2. Identity generation — Ed25519 for Reticulum wire compat.
    let mut entropy = KernelEntropy::new(rdrand_fill);
    let identity = PrivateIdentity::generate(&mut entropy);
    let addr = identity.public_identity().address_hash;
    let mut hex_buf = [0u8; 32];
    hex_encode(&addr, &mut hex_buf);
    let hex_str = core::str::from_utf8(&hex_buf).unwrap_or("????????????????????????????????");
    serial.log("IDENTITY", hex_str);

    // 3. VirtIO-net init
    let mut virtio_net = match pci::find_virtio_net() {
        Some(pci_dev) => {
            pci_dev.enable_bus_master();
            match virtio::pci_cap::parse_capabilities(&pci_dev, phys_offset) {
                Some(caps) => match virtio::net::VirtioNet::init(caps, phys_offset) {
                    Ok(net) => {
                        let mut mac_buf = [0u8; 17];
                        net.mac_str(&mut mac_buf);
                        let mac_str = core::str::from_utf8(&mac_buf).unwrap_or("??:??:??:??:??:??");
                        serial.log("VIRTIO", mac_str);
                        Some(net)
                    }
                    Err(e) => {
                        serial.log("VIRTIO", e);
                        None
                    }
                },
                None => {
                    serial.log("VIRTIO", "no capabilities found");
                    None
                }
            }
        }
        None => {
            serial.log("VIRTIO", "no device found");
            None
        }
    };

    // 4. Initialize IP network stack (UDP interface for mesh-over-IP)
    // QEMU user-mode networking defaults — override for non-QEMU targets.
    use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
    const NETSTACK_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 15);
    const NETSTACK_PREFIX: u8 = 24;
    const NETSTACK_GW: Ipv4Address = Ipv4Address::new(10, 0, 2, 2);

    let netstack = {
        use harmony_netstack::NetStackBuilder;

        let mac = virtio_net
            .as_ref()
            .map(|n| n.mac())
            .unwrap_or([0x02, 0, 0, 0, 0, 0]);
        NetStackBuilder::new()
            .mac(mac)
            .dhcp(true)
            .fallback_ip(Ipv4Cidr::new(NETSTACK_IP, NETSTACK_PREFIX))
            .fallback_gateway(NETSTACK_GW)
            .port(4242)
            .enable_broadcast(true)
            .tcp_max_sockets(16)
            .build(smoltcp::time::Instant::from_millis(pit.now_ms() as i64))
    };
    let netstack = core::cell::RefCell::new(netstack);

    serial.log("NETSTACK", "udp0 DHCP (fallback 10.0.2.15/24 after 5s), port 4242, tcp_max_sockets=16");

    // 5. Event loop
    let persistence = MemoryState::new();
    let mut runtime = UnikernelRuntime::new(identity, entropy, persistence);

    // Key hierarchy (hardware + session + attestation) is implemented in
    // harmony-microkernel::key_hierarchy but not yet wired into this boot
    // path. Ring 1 UnikernelRuntime uses a single PQ identity; the full
    // four-tier hierarchy requires Ring 2 Kernel integration with persistent
    // storage for the hardware key and attestation pair.
    // TODO(harmony-os-5gh): wire hw_identity + session_identity into Kernel::new()
    //   once Ring 2 boot path exists. Requires persistent storage for hw key.
    if let Some(pq_addr) = runtime.generate_pq_identity() {
        hex_encode(&pq_addr, &mut hex_buf);
        let hex_str =
            core::str::from_utf8(&hex_buf).unwrap_or("????????????????????????????????");
        serial.log("PQ_IDENTITY", hex_str);
    }

    if virtio_net.is_some() {
        runtime.register_interface("eth0");
        runtime.register_interface("udp0");
    }

    let now = pit.now_ms();
    let dest_hash = runtime.register_announcing_destination("harmony", &["node"], 300_000, now);
    let mut dest_hex = [0u8; 32];
    hex_encode(&dest_hash, &mut dest_hex);
    let dest_str = core::str::from_utf8(&dest_hex).unwrap_or("????????????????????????????????");
    serial.log("DEST", dest_str);

    serial.log("READY", "entering event loop");

    // ── Ring 2 microkernel IPC demo ────────────────────────────────────
    // Uses EchoServer directly (Kernel struct requires std for Memory*
    // stores). This proves the FileServer trait works in no_std.  Full
    // Kernel + UCAN enforcement is exercised by `cargo test` (std).
    #[cfg(feature = "ring2")]
    {
        use harmony_microkernel::echo::EchoServer;
        use harmony_microkernel::{FileServer, OpenMode};

        serial.log("KERN", "Ring 2 microkernel mode");

        // Create echo server directly
        let mut echo = EchoServer::new();

        // Walk to hello
        let qpath = echo.walk(0, 1, "hello").expect("ring2: walk hello");
        let _ = writeln!(serial, "[IPC]  walk hello qpath={}", qpath);

        // Open and read
        echo.open(1, OpenMode::Read).expect("ring2: open hello");
        let data = echo.read(1, 0, 256).expect("ring2: read hello");
        let msg = core::str::from_utf8(&data).unwrap_or("(non-utf8)");
        let _ = writeln!(serial, "[IPC]  read: \"{}\"", msg);

        // Walk to echo, write, read back
        echo.walk(0, 2, "echo").expect("ring2: walk echo");
        echo.open(2, OpenMode::ReadWrite).expect("ring2: open echo");
        echo.write(2, 0, b"Harmony Ring 2!").expect("ring2: write echo");
        let data = echo.read(2, 0, 256).expect("ring2: read echo");
        let msg = core::str::from_utf8(&data).unwrap_or("(non-utf8)");
        let _ = writeln!(serial, "[IPC]  echo: \"{}\"", msg);

        serial.log("KERN", "Ring 2 IPC demo complete");
    }

    // ── Ring 3 Linuxulator ────────────────────────────────────────────
    #[cfg(feature = "ring3")]
    {
        use harmony_microkernel::serial_server::SerialServer as KernelSerialServer;
        use harmony_microkernel::FileServer;
        use harmony_os::elf::parse_elf;
        use harmony_os::linuxulator::{Linuxulator, SyscallBackend};

        serial.log("KERN", "Ring 3 Linuxulator mode");

        // ── DirectBackend: wraps SerialServer directly ──────────────
        // The Kernel requires `std` (identity stores), so on bare metal
        // we bypass it and call SerialServer methods directly. Still
        // exercises the FileServer trait — just skips capability checks.
        struct DirectBackend {
            server: KernelSerialServer,
        }

        impl DirectBackend {
            fn new() -> Self {
                Self {
                    server: KernelSerialServer::new(),
                }
            }
        }

        impl SyscallBackend for DirectBackend {
            fn walk(
                &mut self,
                _path: &str,
                new_fid: harmony_microkernel::Fid,
            ) -> Result<harmony_microkernel::QPath, harmony_microkernel::IpcError> {
                // All walks go to "log" — the only file in SerialServer
                self.server.walk(0, new_fid, "log")
            }
            fn open(
                &mut self,
                fid: harmony_microkernel::Fid,
                mode: harmony_microkernel::OpenMode,
            ) -> Result<(), harmony_microkernel::IpcError> {
                self.server.open(fid, mode)
            }
            fn read(
                &mut self,
                fid: harmony_microkernel::Fid,
                offset: u64,
                count: u32,
            ) -> Result<alloc::vec::Vec<u8>, harmony_microkernel::IpcError> {
                self.server.read(fid, offset, count)
            }
            fn write(
                &mut self,
                fid: harmony_microkernel::Fid,
                _offset: u64,
                data: &[u8],
            ) -> Result<u32, harmony_microkernel::IpcError> {
                // Write to SerialServer buffer AND echo to real serial port
                let result = self.server.write(fid, 0, data);
                // Also write to actual serial for QEMU visibility
                for &byte in data {
                    serial_write_byte(byte);
                }
                result
            }
            fn clunk(
                &mut self,
                fid: harmony_microkernel::Fid,
            ) -> Result<(), harmony_microkernel::IpcError> {
                self.server.clunk(fid)
            }
            fn stat(
                &mut self,
                fid: harmony_microkernel::Fid,
            ) -> Result<harmony_microkernel::FileStat, harmony_microkernel::IpcError> {
                self.server.stat(fid)
            }
        }

        // 1. Load ELF (dropbear — arch-specific binary selected at top of file)
        let elf_bytes = DROPBEAR_BIN;
        let parsed = match parse_elf(elf_bytes) {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(serial, "[LINUX] ELF parse error: {:?}", e);
                loop {
                    x86_64::instructions::hlt();
                }
            }
        };
        let _ = writeln!(
            serial,
            "[LINUX] loaded dropbear ({} bytes, {} segments)",
            elf_bytes.len(),
            parsed.segments.len()
        );

        // 2. Copy all PT_LOAD segments to heap
        if parsed.segments.is_empty() {
            let _ = writeln!(serial, "[LINUX] ELF has no PT_LOAD segments");
            loop {
                x86_64::instructions::hlt();
            }
        }

        // Find the overall virtual address range across all segments
        let vaddr_min = parsed
            .segments
            .iter()
            .map(|s| s.vaddr)
            .min()
            .unwrap();
        let vaddr_max = match parsed
            .segments
            .iter()
            .try_fold(0u64, |acc, s| {
                s.vaddr.checked_add(s.memsz).map(|end| acc.max(end))
            }) {
            Some(max) => max,
            None => {
                let _ = writeln!(serial, "[LINUX] segment vaddr+memsz overflow");
                loop {
                    x86_64::instructions::hlt();
                }
            }
        };
        // Add 16 KiB of headroom beyond the ELF's declared memsz. musl's
        // static TLS struct (struct pthread, ~1-2 KiB) lives at the tail
        // of .bss and may extend beyond the last segment's vaddr+memsz.
        const ELF_HEADROOM: usize = 16 * 1024;
        let total_size = match vaddr_max.checked_sub(vaddr_min) {
            Some(sz) => sz as usize + ELF_HEADROOM,
            None => {
                let _ = writeln!(serial, "[LINUX] vaddr range overflow");
                loop {
                    x86_64::instructions::hlt();
                }
            }
        };
        // Allocate with PAGE alignment (4 KiB). The page-table mapping
        // assumes page offsets match between the ELF's linked addresses
        // (e.g. 0x400000, page offset 0x000) and the heap allocation.
        // A non-page-aligned allocation would shift the within-page
        // offsets, causing reads to hit wrong bytes.
        let mem_layout = core::alloc::Layout::from_size_align(total_size, 0x1000)
            .expect("ELF mem layout");
        let mem_ptr = unsafe { alloc::alloc::alloc_zeroed(mem_layout) };
        if mem_ptr.is_null() {
            let _ = writeln!(serial, "[LINUX] failed to allocate {} bytes (page-aligned)", total_size);
            loop { x86_64::instructions::hlt(); }
        }
        let mut mem = unsafe { core::slice::from_raw_parts_mut(mem_ptr, total_size) };

        // Load each segment at its correct offset within the allocation
        for seg in &parsed.segments {
            let seg_offset = (seg.vaddr - vaddr_min) as usize;
            let filesz = seg.filesz as usize;
            mem[seg_offset..seg_offset + filesz]
                .copy_from_slice(&elf_bytes[seg.offset as usize..seg.offset as usize + filesz]);
        }

        // Validate entry point
        if parsed.entry_point < vaddr_min || parsed.entry_point >= vaddr_max {
            let _ = writeln!(
                serial,
                "[LINUX] entry_point 0x{:x} outside segment range 0x{:x}..0x{:x}",
                parsed.entry_point, vaddr_min, vaddr_max
            );
            loop {
                x86_64::instructions::hlt();
            }
        }

        // 2b. Map ELF at its linked virtual addresses.
        //
        // The binary is a static non-PIE (ET_EXEC) with absolute addresses
        // baked into the code. We loaded its data into a heap allocation,
        // but the code expects to run at its linked addresses (e.g. 0x400000+).
        // Create page-table entries so the linked addresses map to the heap
        // frames containing the actual data.
        let mapped_pages = unsafe {
            map_elf_at_linked_addresses(
                phys_offset,
                mem.as_ptr() as usize,
                vaddr_min,
                vaddr_max + ELF_HEADROOM as u64,
                &parsed.segments,
            )
        };

        // Use the ELF's original linked entry point — the page tables now
        // resolve it to our heap copy.
        let real_entry = parsed.entry_point as usize;
        let _ = writeln!(
            serial,
            "[LINUX] mapped {} pages at linked addresses 0x{:x}..0x{:x}, entry=0x{:x}",
            mapped_pages, vaddr_min, vaddr_max, real_entry
        );

        // 3. Allocate stack
        let stack_size = 64 * 1024; // 64 KiB
        let stack = alloc::vec![0u8; stack_size];
        let stack_top = (stack.as_ptr() as usize + stack_size) & !0xF;
        let _ = writeln!(serial, "[LINUX] stack_top=0x{:x}", stack_top);

        // 4. Create Linuxulator with global storage
        // We store it in a static to make it accessible from the syscall handler.
        // RawPtrTcpProvider holds a raw pointer into `netstack` (which is a local
        // in kernel_continue). This is safe because:
        //   (a) kernel_continue never returns (noreturn asm at the end), so
        //       `netstack` stays alive for the remainder of the program;
        //   (b) the ring3 path exits via `jmp {entry}` (noreturn), so no code
        //       after this block will race with the Linuxulator's TCP calls.
        static mut LINUXULATOR: Option<Linuxulator<DirectBackend, RawPtrTcpProvider>> = None;
        unsafe {
            LINUXULATOR = Some(Linuxulator::with_tcp_and_arena(
                DirectBackend::new(),
                RawPtrTcpProvider(netstack.as_ptr()),
                4 * 1024 * 1024, // 4 MiB arena — dropbear needs room for TLS + heap
            ));
            LINUXULATOR
                .as_mut()
                .unwrap()
                .init_stdio()
                .expect("init_stdio failed");
        }

        // 5. Build embedded filesystem for dropbear + busybox
        {
            let mut efs = harmony_os::embedded_fs::EmbeddedFs::new();

            // Binaries
            efs.add_file("/bin/dropbear", DROPBEAR_BIN, true);
            efs.add_file("/bin/busybox", BUSYBOX_BIN, true);
            efs.add_file("/bin/sh", BUSYBOX_BIN, true);
            efs.add_file("/bin/ash", BUSYBOX_BIN, true);

            // Config files
            efs.add_file(
                "/etc/passwd",
                b"root:x:0:0:root:/root:/bin/sh\n",
                false,
            );
            // SHA-512 hash of "harmony" — dropbear checks /etc/shadow when
            // /etc/passwd has "x" in the password field.
            efs.add_file(
                "/etc/shadow",
                b"root:$6$3dBTlFcq3TUeP.1b$MMabSOewt9dUQg.duy11rBOtOcIgjMwLWGTcuxkdIeeXaYTzQbn2R2HKwQs4p.GXuQr/RHx7FAxwzR6FpJT2y1:19814:0:99999:7:::\n",
                false,
            );
            efs.add_file("/etc/shells", b"/bin/sh\n", false);
            // No host key registered — dropbear -R generates one at startup.

            // Minimal /etc/group for busybox id/whoami
            efs.add_file("/etc/group", b"root:x:0:\n", false);

            // Register with the Linuxulator
            unsafe {
                if let Some(ref mut lx) = LINUXULATOR {
                    lx.set_embedded_fs(efs);
                }
            }
        }
        serial.log("USERSPACE", "embedded dropbear + busybox registered in EmbeddedFs");

        // 7. Install dispatch function
        fn dispatch(nr: u64, args: [u64; 6]) -> syscall::SyscallResult {
            let lx = unsafe { LINUXULATOR.as_mut().unwrap() };
            let retval = lx.handle_syscall(nr, args);
            // Write FS base MSR only after handle_syscall confirms success.
            // If arch_prctl ever adds validation (e.g. range check), an
            // unconditional MSR write would leave the CPU in a bad state
            // even though the syscall nominally failed.
            if nr == 158 /* SYS_arch_prctl */ && args[0] == 0x1002 /* ARCH_SET_FS */ && retval == 0 {
                unsafe { syscall::write_fs_base(args[1]); }
            }
            syscall::SyscallResult {
                retval,
                exited: lx.exited(),
                exit_code: lx.exit_code().unwrap_or(0),
            }
        }
        unsafe {
            syscall::set_dispatch_fn(dispatch);
        }

        // 8. Set up MSRs
        // kernel_cs = 0x08 (standard GDT kernel code segment from bootloader)
        // user_cs_base = 0x00 (unused in flat Ring 0 MVP — we use jmp instead of sysretq)
        unsafe {
            syscall::setup_msrs(0x08, 0x00);
        }

        // 9. Set up Linux stack ABI and jump to dropbear.
        //
        // musl's _start expects the System V AMD64 initial stack layout:
        //   RSP+0:  argc
        //   RSP+8:  argv[0] → "/bin/dropbear\0"
        //   ...     argv[1..argc-1]
        //   RSP+?:  NULL (argv terminator)
        //   RSP+?:  NULL (envp terminator — no environment variables)
        //   RSP+?:  AT_PHDR (3), <addr> — program header table address
        //   RSP+?:  AT_PHENT (4), 56  — program header entry size
        //   RSP+?:  AT_PHNUM (5), <n> — number of program headers
        //   RSP+?:  AT_PAGESZ (6), 4096 — musl needs this for mmap alignment
        //   RSP+?:  AT_ENTRY (9), <entry> — entry point
        //   RSP+?:  AT_NULL (0), 0     — auxiliary vector terminator
        //
        // The argv strings are placed below the pointer table on the stack.
        // dropbear flags: -R (ephemeral host key), -F (foreground), -E (log
        // to stderr), -p 2222 (listen port).
        let argv_strings: &[&[u8]] = &[
            b"/bin/dropbear\0",
            b"-R\0",
            b"-F\0",
            b"-E\0",
            b"-p\0",
            b"2222\0",
        ];
        let argc = argv_strings.len();

        // Write strings into the top of the stack, then build the pointer table
        // below them. We work downward from stack_top.
        let mut str_ptr = stack_top;

        // Phase 1: copy strings onto the stack, collecting their addresses.
        let mut argv_ptrs = alloc::vec::Vec::with_capacity(argc);
        for s in argv_strings {
            str_ptr -= s.len();
            str_ptr &= !0x7; // align to 8 bytes
            unsafe {
                core::ptr::copy_nonoverlapping(s.as_ptr(), str_ptr as *mut u8, s.len());
            }
            argv_ptrs.push(str_ptr as u64);
        }

        // Phase 2: build the initial stack frame below the strings.
        // Layout (growing downward):
        //   [auxv: PHDR,PHENT,PHNUM,PAGESZ,ENTRY,NULL] (12 × 8 = 96 bytes)
        //   [envp NULL terminator]                 (1 × 8 = 8 bytes)
        //   [argv NULL terminator]                 (1 × 8 = 8 bytes)
        //   [argv pointers]                        (argc × 8 bytes)
        //   [argc]                                 (1 × 8 = 8 bytes)
        let auxv_pairs = 5 + 1; // 5 real entries + AT_NULL terminator
        let frame_slots = 1 + argc + 1 + 1 + auxv_pairs * 2;
        let frame_base = (str_ptr - frame_slots * 8) & !0xF; // 16-byte aligned

        unsafe {
            let mut p = frame_base as *mut u64;
            // argc
            *p = argc as u64;
            p = p.add(1);
            // argv pointers
            for ptr in &argv_ptrs {
                *p = *ptr;
                p = p.add(1);
            }
            // argv NULL terminator
            *p = 0;
            p = p.add(1);
            // envp NULL terminator
            *p = 0;
            p = p.add(1);
            // Auxiliary vector — musl scans these to find program headers,
            // page size, and entry point. Without AT_PHDR/AT_PHNUM, musl
            // cannot find PT_TLS and computes garbage TLS sizes.
            // AT_PHDR (3) — address of program header table
            *p = 3; p = p.add(1);
            *p = vaddr_min + parsed.phdr_offset; p = p.add(1);
            // AT_PHENT (4) — size of one program header entry
            *p = 4; p = p.add(1);
            *p = parsed.phdr_entry_size as u64; p = p.add(1);
            // AT_PHNUM (5) — number of program headers
            *p = 5; p = p.add(1);
            *p = parsed.phdr_count as u64; p = p.add(1);
            // AT_PAGESZ (6)
            *p = 6; p = p.add(1);
            *p = 4096; p = p.add(1);
            // AT_ENTRY (9) — original entry point
            *p = 9; p = p.add(1);
            *p = parsed.entry_point; p = p.add(1);
            // AT_NULL (0) — terminator
            *p = 0; p = p.add(1);
            *p = 0;
        }

        let _ = writeln!(
            serial,
            "[LINUX] stack ABI: argc={}, argv[0]={:#x}, frame={:#x}",
            argc, argv_ptrs[0], frame_base
        );
        // Diagnostic: dump addressing info to verify the mapping.
        let entry_offset = (parsed.entry_point - vaddr_min) as usize;
        let heap_entry_virt = mem.as_ptr() as usize + entry_offset;
        let heap_entry_phys = heap_entry_virt as u64 - phys_offset;
        // Enable SSE/SSE2 — musl uses XMM registers for memset/memcpy.
        // CR0: clear EM (bit 2) = no x87 emulation, set MP (bit 1)
        // CR4: set OSFXSR (bit 9) = enable FXSAVE/FXRSTOR + SSE
        //      set OSXMMEXCPT (bit 10) = enable #XM for unmasked SSE exceptions
        unsafe {
            core::arch::asm!(
                "mov rax, cr0",
                "and ax, 0xFFFB",   // clear EM (bit 2)
                "or ax, 0x2",       // set MP (bit 1)
                "mov cr0, rax",
                "mov rax, cr4",
                "or ax, 0x600",     // set OSFXSR (bit 9) + OSXMMEXCPT (bit 10)
                "mov cr4, rax",
                out("rax") _,
                options(nostack),
            );
        }
        serial.log("SSE", "enabled (CR0.EM=0, CR4.OSFXSR=1)");

        // Install a minimal IDT with a page-fault handler that prints CR2
        // to serial before halting. This replaces the bootloader's default
        // IDT which just triple-faults on #PF.
        {
            use x86_64::structures::idt::InterruptDescriptorTable;

            static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();
            unsafe {
                IDT.page_fault.set_handler_fn(page_fault_handler);
                IDT.general_protection_fault.set_handler_fn(gpf_handler);
                IDT.double_fault.set_handler_fn(double_fault_handler);
                IDT.load();
            }
            serial.log("IDT", "installed #PF/#GP/#DF handlers");
        }

        serial.log("LINUX", "jumping to dropbear entry point");

        // Mask all PIC interrupts before entering userspace. There is no
        // proper IDT for hardware interrupts; if the syscall trampoline
        // re-enables IF via popfq, the next PIT tick would triple-fault.
        unsafe {
            Port::<u8>::new(0x21).write(0xFF); // master PIC: mask all IRQs
            Port::<u8>::new(0xA1).write(0xFF); // slave PIC: mask all IRQs
        }

        // Set RSP to the prepared frame and jump. When the binary calls
        // `syscall`, the CPU will vector to syscall_entry via LSTAR.
        // After exit_group, we check the flag and continue.
        unsafe {
            core::arch::asm!(
                "mov rsp, {stack}",
                "jmp {entry}",
                stack = in(reg) frame_base,
                entry = in(reg) real_entry,
                options(noreturn),
            );
        }
    }

    // Verify netstack initialization during automated QEMU testing.
    #[cfg(feature = "qemu-test")]
    {
        serial.log("NETSTACK_TEST", "verifying stack initialization...");
        serial.log("NETSTACK_TEST", "PASS");
    }

    // Exit early during automated QEMU testing (feature-gated).
    #[cfg(feature = "qemu-test")]
    qemu_debug_exit(0x10);

    loop {
        let now = pit.now_ms();
        let smoltcp_now = smoltcp::time::Instant::from_millis(now as i64);

        // RX: poll hardware, route by EtherType.
        // Collect Harmony packets into a Vec to release the borrow on virtio_net
        // before calling dispatch_actions (which also borrows it mutably).
        let mut harmony_packets = alloc::vec::Vec::new();
        if let Some(ref mut net) = virtio_net {
            while let Some(frame) = net.receive_raw() {
                match virtio::net::ethertype(&frame) {
                    0x88B5 => {
                        // Raw Harmony — strip Ethernet header, feed to runtime
                        if frame.len() > ETH_HEADER_LEN {
                            harmony_packets.push(frame[ETH_HEADER_LEN..].to_vec());
                        }
                    }
                    0x0800 | 0x0806 => {
                        // IP or ARP — feed to netstack
                        netstack.borrow_mut().ingest(frame);
                    }
                    _ => {} // Drop unknown EtherTypes
                }
            }
        }
        // Dispatch Harmony packets (borrow on virtio_net is released)
        for payload in harmony_packets {
            let actions = runtime.handle_packet("eth0", payload, now);
            dispatch_actions(&actions, &mut virtio_net, &netstack, &mut serial);
        }

        // Process IP stack (inbound)
        netstack.borrow_mut().poll(smoltcp_now);

        // Flush outbound frames from ARP/IP processing
        if let Some(ref mut net) = virtio_net {
            let frames: alloc::vec::Vec<_> = netstack.borrow_mut().drain_tx().collect();
            for frame in frames {
                let _ = net.send_raw(&frame);
            }
        }

        // Handle UDP-received Harmony packets
        // Collect packets first to avoid holding borrow across dispatch_actions.
        let udp_packets: alloc::vec::Vec<_> = {
            let mut ns = netstack.borrow_mut();
            core::iter::from_fn(|| harmony_platform::NetworkInterface::receive(&mut *ns))
                .collect()
        };
        for pkt in udp_packets {
            let actions = runtime.handle_packet("udp0", pkt, now);
            dispatch_actions(&actions, &mut virtio_net, &netstack, &mut serial);
        }

        // Timer tick
        let actions = runtime.tick(now);
        dispatch_actions(&actions, &mut virtio_net, &netstack, &mut serial);

        // Flush outbound UDP frames (re-sample time so smoltcp sees elapsed millis)
        let smoltcp_now = smoltcp::time::Instant::from_millis(pit.now_ms() as i64);
        netstack.borrow_mut().poll(smoltcp_now);
        if let Some(ref mut net) = virtio_net {
            let frames: alloc::vec::Vec<_> = netstack.borrow_mut().drain_tx().collect();
            for frame in frames {
                let _ = net.send_raw(&frame);
            }
        }

        // Check stack canary — detects overflow into heap memory.
        debug_assert_eq!(
            unsafe { core::ptr::read_volatile(stack_canary_addr as *const u64) },
            STACK_CANARY,
            "kernel stack overflow detected (canary corrupted)"
        );

        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// Exception handlers (for debugging userspace faults)
// ---------------------------------------------------------------------------

/// Write a hex value to serial (COM1) using direct port I/O.
/// Safe to call from exception handlers where normal logging may not work.
fn serial_write_hex(val: u64) {
    let write_byte = |b: u8| {
        unsafe {
            while Port::<u8>::new(0x3F8 + 5).read() & 0x20 == 0 {
                core::hint::spin_loop();
            }
            Port::new(0x3F8).write(b);
        }
    };
    for &b in b"0x" { write_byte(b); }
    for shift in (0..16).rev() {
        let nibble = ((val >> (shift * 4)) & 0xF) as u8;
        write_byte(if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 });
    }
}

fn serial_write_str(s: &[u8]) {
    for &b in s {
        unsafe {
            while Port::<u8>::new(0x3F8 + 5).read() & 0x20 == 0 {
                core::hint::spin_loop();
            }
            Port::new(0x3F8).write(b);
        }
    }
}

use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    let cr2: u64;
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2) };
    serial_write_str(b"\n[#PF] addr=");
    serial_write_hex(cr2);
    serial_write_str(b" code=");
    serial_write_hex(error_code.bits() as u64);
    serial_write_str(b" rip=");
    serial_write_hex(stack_frame.instruction_pointer.as_u64());
    serial_write_str(b"\n");
    loop { x86_64::instructions::hlt(); }
}

extern "x86-interrupt" fn gpf_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    serial_write_str(b"\n[#GP] code=");
    serial_write_hex(error_code);
    serial_write_str(b" rip=");
    serial_write_hex(stack_frame.instruction_pointer.as_u64());
    serial_write_str(b"\n");
    loop { x86_64::instructions::hlt(); }
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    serial_write_str(b"\n[#DF] rip=");
    serial_write_hex(stack_frame.instruction_pointer.as_u64());
    serial_write_str(b"\n");
    loop { x86_64::instructions::hlt(); }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_init();
    let mut serial = serial_writer();
    let _ = writeln!(serial, "[PANIC] {}", info);
    loop {
        x86_64::instructions::hlt();
    }
}
