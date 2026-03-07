// SPDX-License-Identifier: GPL-2.0-or-later
//! Harmony OS x86_64 boot entry point.
//!
//! Initialises serial output, heap, RDRAND entropy, generates a node
//! identity, then enters the unikernel event loop.

#![no_std]
#![no_main]

extern crate alloc;

mod pci;
mod pit;
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
// RuntimeAction dispatch
// ---------------------------------------------------------------------------

/// Dispatch RuntimeActions: send packets and log events.
fn dispatch_actions(
    actions: &[RuntimeAction],
    virtio_net: &mut Option<virtio::net::VirtioNet>,
    serial: &mut SerialWriter<impl FnMut(u8)>,
) {
    use core::fmt::Write;
    use harmony_unikernel::serial::hex_encode;

    for action in actions {
        match action {
            RuntimeAction::SendOnInterface { interface_name, raw } => {
                if interface_name.as_ref() == "virtio0" {
                    if let Some(ref mut net) = virtio_net {
                        let _ = harmony_platform::NetworkInterface::send(net, raw);
                    }
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

    let mut pit = pit::PitTimer::init();
    serial.log("PIT", "timer initialized");

    // 2. Get the physical memory offset so we can convert physical -> virtual
    let phys_offset = boot_info
        .physical_memory_offset
        .into_option()
        .expect("physical_memory_offset not provided by bootloader");

    // 3. Heap init — find first usable region >= 1 MiB
    const MIN_HEAP_SIZE: usize = 1024 * 1024; // 1 MiB
    let mut heap_start: Option<u64> = None;
    let mut heap_size: usize = 0;

    for region in boot_info.memory_regions.iter() {
        if region.kind == MemoryRegionKind::Usable {
            let size = (region.end - region.start) as usize;
            if size >= MIN_HEAP_SIZE {
                heap_start = Some(region.start);
                heap_size = if size > 4 * 1024 * 1024 {
                    4 * 1024 * 1024
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
            serial.log("HEAP", "FAILED: no usable region >= 1 MiB");
            loop {
                x86_64::instructions::hlt();
            }
        }
    }

    // 4. RDRAND entropy
    if !rdrand_available() {
        serial.log("ENTROPY", "RDRAND not available -- halting");
        loop {
            x86_64::instructions::hlt();
        }
    }
    serial.log("ENTROPY", "RDRAND available");

    // 5. Identity generation
    let mut entropy = KernelEntropy::new(rdrand_fill);
    let identity = PrivateIdentity::generate(&mut entropy);
    let addr = identity.public_identity().address_hash;
    let mut hex_buf = [0u8; 32];
    hex_encode(&addr, &mut hex_buf);
    let hex_str = core::str::from_utf8(&hex_buf).unwrap_or("????????????????????????????????");
    serial.log("IDENTITY", hex_str);

    // 5.5 VirtIO-net init
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

    // 6. Event loop
    let persistence = MemoryState::new();
    let mut runtime = UnikernelRuntime::new(identity, entropy, persistence);

    if virtio_net.is_some() {
        runtime.register_interface("virtio0");
    }

    let now = pit.now_ms();
    let dest_hash = runtime.register_announcing_destination("harmony", &["node"], 300_000, now);
    let mut dest_hex = [0u8; 32];
    hex_encode(&dest_hash, &mut dest_hex);
    let dest_str = core::str::from_utf8(&dest_hex).unwrap_or("????????????????????????????????");
    serial.log("DEST", dest_str);

    serial.log("READY", "entering event loop");

    // Exit early during automated QEMU testing (feature-gated).
    #[cfg(feature = "qemu-test")]
    qemu_debug_exit(0x10);

    loop {
        let now = pit.now_ms();

        // Poll network for inbound packets.
        // Collect received packets first to release the borrow on virtio_net.
        let mut rx_packets = alloc::vec::Vec::new();
        if let Some(ref mut net) = virtio_net {
            while let Some(data) = harmony_platform::NetworkInterface::receive(net) {
                rx_packets.push(data);
            }
        }
        for data in rx_packets {
            let actions = runtime.handle_packet("virtio0", data, now);
            dispatch_actions(&actions, &mut virtio_net, &mut serial);
        }

        // Timer tick.
        let actions = runtime.tick(now);
        dispatch_actions(&actions, &mut virtio_net, &mut serial);

        core::hint::spin_loop();
    }
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
