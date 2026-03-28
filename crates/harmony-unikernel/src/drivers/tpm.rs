// SPDX-License-Identifier: GPL-2.0-or-later

//! TPM 2.0 driver for hardware key derivation.
//!
//! Three-layer architecture:
//! 1. **SPI PTP transport** — register read/write over [`SpiBus`]
//! 2. **Command engine** — FIFO-based command execution
//! 3. **Key derivation** — HMAC workflow for hardware-bound keys
//!
extern crate alloc;
use alloc::vec::Vec;

use super::spi_bus::SpiBus;

// ── TPM register addresses (Locality 0) ──────────────────────────────

#[allow(dead_code)]
const TPM_ACCESS: u32 = 0xD4_0000;
#[allow(dead_code)]
const TPM_STS: u32 = 0xD4_0018;
#[allow(dead_code)]
const TPM_DATA_FIFO: u32 = 0xD4_0024;
#[allow(dead_code)]
const TPM_DID_VID: u32 = 0xD4_0F00;

// ── TPM_ACCESS bit masks ─────────────────────────────────────────────

#[allow(dead_code)]
const ACCESS_VALID: u8 = 1 << 7; // tpmRegValidSts
#[allow(dead_code)]
const ACCESS_ACTIVE: u8 = 1 << 4; // activeLocality
#[allow(dead_code)]
const ACCESS_REQUEST: u8 = 1 << 1; // requestUse

// ── TPM_STS bit masks ────────────────────────────────────────────────

#[allow(dead_code)]
const STS_COMMAND_READY: u32 = 1 << 6;
#[allow(dead_code)]
const STS_TPM_GO: u32 = 1 << 5;
#[allow(dead_code)]
const STS_DATA_AVAIL: u32 = 1 << 4;

/// Maximum wait-state polling iterations before timeout.
#[allow(dead_code)]
const MAX_WAIT_CYCLES: usize = 10_000;
/// Maximum status register polling iterations.
#[allow(dead_code)]
const MAX_POLL_CYCLES: usize = 100_000;
/// Maximum bytes per SPI register transfer (stack buffer size).
#[allow(dead_code)]
const MAX_BURST: usize = 64;

// ── Error type ───────────────────────────────────────────────────────

/// Errors returned by TPM driver operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmError {
    /// SPI wait-state or status polling exceeded iteration limit.
    Timeout,
    /// TPM_ACCESS validity check failed.
    LocalityUnavailable,
    /// TPM returned non-zero response code.
    CommandFailed { rc: u32 },
    /// Response exceeds caller-provided buffer.
    BufferTooSmall,
    /// TPM driver is in the wrong state for the operation.
    InvalidState,
    /// tpm2-protocol marshaling/unmarshaling failed.
    ProtocolError,
}

// ── Driver state ─────────────────────────────────────────────────────

/// Lifecycle state of a [`TpmDriver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmState {
    /// Driver created but init() not yet called.
    Uninitialized,
    /// TPM2_Startup + SelfTest completed.
    Ready,
}

// ── Driver struct ────────────────────────────────────────────────────

/// TPM 2.0 driver for hardware key derivation via HMAC.
#[derive(Debug)]
pub struct TpmDriver<S: SpiBus> {
    #[allow(dead_code)]
    bus: S,
    state: TpmState,
}

// ── SPI PTP transport (Layer 1) ──────────────────────────────────────

#[allow(dead_code)]
impl<S: SpiBus> TpmDriver<S> {
    /// Build a 4-byte SPI PTP header.
    ///
    /// `is_read`: true for read, false for write.
    /// `size`: number of bytes to transfer (1-64).
    /// `addr`: 24-bit TPM register address.
    fn spi_header(is_read: bool, size: u8, addr: u32) -> [u8; 4] {
        let dir = if is_read { 0x80 } else { 0x00 };
        [
            dir | (size - 1),
            ((addr >> 16) & 0xFF) as u8,
            ((addr >> 8) & 0xFF) as u8,
            (addr & 0xFF) as u8,
        ]
    }

    /// Poll MISO for wait-state ACK (bit 0 set).
    fn poll_wait_state(&mut self) -> Result<(), TpmError> {
        for _ in 0..MAX_WAIT_CYCLES {
            let mut rx = [0u8; 1];
            self.bus.transfer(&[0x00], &mut rx);
            if rx[0] & 0x01 != 0 {
                return Ok(());
            }
        }
        Err(TpmError::Timeout)
    }

    /// Read `buf.len()` bytes from TPM register at `addr`.
    /// Capped at `MAX_BURST` bytes per call.
    fn read_register(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), TpmError> {
        let len = buf.len().min(MAX_BURST);
        let header = Self::spi_header(true, len as u8, addr);

        self.bus.assert_cs();
        let mut rx_header = [0u8; 4];
        self.bus.transfer(&header, &mut rx_header);
        if let Err(e) = self.poll_wait_state() {
            self.bus.deassert_cs();
            return Err(e);
        }

        let tx_zeros = [0u8; MAX_BURST];
        self.bus.transfer(&tx_zeros[..len], &mut buf[..len]);
        self.bus.deassert_cs();

        Ok(())
    }

    /// Write `data` to TPM register at `addr`.
    /// Capped at `MAX_BURST` bytes per call.
    fn write_register(&mut self, addr: u32, data: &[u8]) -> Result<(), TpmError> {
        let len = data.len().min(MAX_BURST);
        let header = Self::spi_header(false, len as u8, addr);

        self.bus.assert_cs();
        let mut rx_header = [0u8; 4];
        self.bus.transfer(&header, &mut rx_header);
        if let Err(e) = self.poll_wait_state() {
            self.bus.deassert_cs();
            return Err(e);
        }

        let mut rx_payload = [0u8; MAX_BURST];
        self.bus.transfer(&data[..len], &mut rx_payload[..len]);
        self.bus.deassert_cs();

        Ok(())
    }

    /// Return the current driver state.
    pub fn state(&self) -> TpmState {
        self.state
    }
}

// ── TPM command engine (Layer 2) ─────────────────────────────────────

#[allow(dead_code)]
impl<S: SpiBus> TpmDriver<S> {
    /// Ensure locality 0 is active. Request if needed.
    fn ensure_locality(&mut self) -> Result<(), TpmError> {
        let mut access = [0u8; 1];
        self.read_register(TPM_ACCESS, &mut access)?;

        if access[0] & ACCESS_VALID == 0 {
            return Err(TpmError::LocalityUnavailable);
        }

        if access[0] & ACCESS_ACTIVE == 0 {
            // Request locality
            self.write_register(TPM_ACCESS, &[ACCESS_REQUEST])?;
            // Poll until active
            for _ in 0..MAX_POLL_CYCLES {
                self.read_register(TPM_ACCESS, &mut access)?;
                if access[0] & ACCESS_ACTIVE != 0 {
                    return Ok(());
                }
            }
            return Err(TpmError::Timeout);
        }

        Ok(())
    }

    /// Read TPM_STS as a 4-byte little-endian u32.
    fn read_sts(&mut self) -> Result<u32, TpmError> {
        let mut buf = [0u8; 4];
        self.read_register(TPM_STS, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Extract burstCount from TPM_STS (bits 23:8).
    fn burst_count(sts: u32) -> u16 {
        ((sts >> 8) & 0xFFFF) as u16
    }

    /// Execute a pre-marshaled TPM command and read the response.
    ///
    /// Returns the number of response bytes written to `response`.
    pub fn execute_command(
        &mut self,
        command: &[u8],
        response: &mut [u8],
    ) -> Result<usize, TpmError> {
        // Step 1: Ensure locality is active
        self.ensure_locality()?;

        // Step 2: Set commandReady
        self.write_register(TPM_STS, &STS_COMMAND_READY.to_le_bytes())?;

        // Step 3: Poll commandReady
        let mut ready = false;
        for _ in 0..MAX_POLL_CYCLES {
            let sts = self.read_sts()?;
            if sts & STS_COMMAND_READY != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(TpmError::Timeout);
        }

        // Step 4-5: Write command to FIFO in chunks
        let mut offset = 0;
        let mut retries = 0usize;
        while offset < command.len() {
            let sts = self.read_sts()?;
            let burst = (Self::burst_count(sts) as usize).min(MAX_BURST);
            if burst == 0 {
                retries += 1;
                if retries > MAX_POLL_CYCLES {
                    return Err(TpmError::Timeout);
                }
                continue;
            }
            retries = 0;
            let chunk = (command.len() - offset).min(burst);
            self.write_register(TPM_DATA_FIFO, &command[offset..offset + chunk])?;
            offset += chunk;
        }

        // Step 6: Assert tpmGo
        self.write_register(TPM_STS, &STS_TPM_GO.to_le_bytes())?;

        // Step 7: Poll dataAvail
        let mut avail = false;
        for _ in 0..MAX_POLL_CYCLES {
            let sts = self.read_sts()?;
            if sts & STS_DATA_AVAIL != 0 {
                avail = true;
                break;
            }
        }
        if !avail {
            return Err(TpmError::Timeout);
        }

        // Step 8: Read response header (first 6 bytes to get size)
        let mut header = [0u8; 6];
        self.read_register(TPM_DATA_FIFO, &mut header)?;

        let resp_size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        if resp_size < 10 {
            return Err(TpmError::ProtocolError);
        }
        if resp_size > response.len() {
            return Err(TpmError::BufferTooSmall);
        }

        // Copy header into response
        response[..6].copy_from_slice(&header);

        // Read remaining bytes
        if resp_size > 6 {
            let remaining = resp_size - 6;
            let mut read_offset = 0;
            let mut retries = 0usize;
            while read_offset < remaining {
                let sts = self.read_sts()?;
                let burst = (Self::burst_count(sts) as usize).min(MAX_BURST);
                if burst == 0 {
                    retries += 1;
                    if retries > MAX_POLL_CYCLES {
                        return Err(TpmError::Timeout);
                    }
                    continue;
                }
                retries = 0;
                let chunk = (remaining - read_offset).min(burst);
                self.read_register(
                    TPM_DATA_FIFO,
                    &mut response[6 + read_offset..6 + read_offset + chunk],
                )?;
                read_offset += chunk;
            }
        }

        // Check response code (bytes 6-9, big-endian u32)
        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            return Err(TpmError::CommandFailed { rc });
        }

        Ok(resp_size)
    }
}

// ── Initialization ───────────────────────────────────────────────────

/// TPM_RC_INITIALIZE — returned when Startup was already called by firmware.
const TPM_RC_INITIALIZE: u32 = 0x00000100;

impl<S: SpiBus> TpmDriver<S> {
    /// Initialize the TPM: probe DID/VID, run Startup + SelfTest.
    pub fn init(bus: S) -> Result<Self, TpmError> {
        let mut driver = Self {
            bus,
            state: TpmState::Uninitialized,
        };

        // Step 1: Probe DID/VID to verify SPI connectivity
        let mut did_vid = [0u8; 4];
        driver.read_register(TPM_DID_VID, &mut did_vid)?;

        // Step 2: TPM2_Startup(TPM_SU_CLEAR)
        // Tag=0x8001 (NO_SESSIONS), Size=12, CC=0x00000144, SU=0x0000
        let startup_cmd = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        let mut resp = [0u8; 64];
        match driver.execute_command(&startup_cmd, &mut resp) {
            Ok(_) => {}
            Err(TpmError::CommandFailed { rc }) if rc == TPM_RC_INITIALIZE => {
                // Firmware already called Startup — that's fine
            }
            Err(e) => return Err(e),
        }

        // Step 3: TPM2_SelfTest(fullTest=yes)
        // Tag=0x8001, Size=11, CC=0x00000143, fullTest=0x01
        let selftest_cmd = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x01, 0x43, 0x01,
        ];
        driver.execute_command(&selftest_cmd, &mut resp)?;

        driver.state = TpmState::Ready;
        Ok(driver)
    }
}

// ── Key derivation (Layer 3) ──────────────────────────────────────

/// PWAP null-password auth area: authAreaSize(4) + sessionHandle(4)
/// + nonceCaller(2) + attrs(1) + hmac(2) = 13 bytes.
const PWAP_AUTH: [u8; 13] = [
    0x00, 0x00, 0x00, 0x09, // auth area size = 9 bytes (excludes own 4-byte size field)
    0x40, 0x00, 0x00, 0x09, // TPM_RS_PW
    0x00, 0x00, // nonceCaller size = 0
    0x01, // sessionAttributes = continueSession
    0x00, 0x00, // hmac size = 0
];

#[allow(dead_code)]
impl<S: SpiBus> TpmDriver<S> {
    /// Create an HMAC primary key under TPM_RH_OWNER.
    ///
    /// Sends TPM2_CreatePrimary (CC=0x00000131) with KEYEDHASH/SHA256
    /// parameters and PWAP auth. Returns the transient object handle.
    fn create_primary_hmac_key(&mut self, resp: &mut [u8]) -> Result<u32, TpmError> {
        // Build the entire command as one contiguous array.
        // Total structure:
        //   Header: tag(2) + size(4) + CC(4) = 10
        //   Handle: TPM_RH_OWNER = 4
        //   PWAP auth: 13
        //   inSensitive: TPM2B_SENSITIVE_CREATE = size(2)=4, inner: userAuth size(2)=0 + data size(2)=0 = 4+2=6
        //     Wait — TPM2B_SENSITIVE_CREATE: size(2) + TPMS_SENSITIVE_CREATE
        //     TPMS_SENSITIVE_CREATE: userAuth TPM2B(2) + data TPM2B(2) = 4 bytes inner
        //     So TPM2B_SENSITIVE_CREATE = size(2)=4 + 4 bytes = 6 bytes total
        //   inPublic: TPM2B_PUBLIC = size(2) + TPMT_PUBLIC
        //     TPMT_PUBLIC: type(2) + nameAlg(2) + attrs(4) + authPolicy TPM2B(2) + params(4) + unique TPM2B(2) = 16
        //     TPM2B_PUBLIC: size(2)=16 + 16 = 18 bytes total
        //   outsideInfo: TPM2B = size(2)=0 = 2 bytes
        //   creationPCR: TPML_PCR_SELECTION = count(4)=0 = 4 bytes
        //
        // Total = 10 + 4 + 13 + 6 + 18 + 2 + 4 = 57 bytes

        let total_size: u32 = 57;
        #[rustfmt::skip]
        let cmd: [u8; 57] = [
            // Header
            0x80, 0x02,                         // tag: TPM_ST_SESSIONS
            (total_size >> 24) as u8,
            (total_size >> 16) as u8,
            (total_size >> 8) as u8,
            total_size as u8,                   // size: 57
            0x00, 0x00, 0x01, 0x31,             // CC: TPM2_CreatePrimary

            // Handle: TPM_RH_OWNER
            0x40, 0x00, 0x00, 0x01,

            // PWAP auth area
            0x00, 0x00, 0x00, 0x09,             // auth area size = 9
            0x40, 0x00, 0x00, 0x09,             // TPM_RS_PW
            0x00, 0x00,                         // nonceCaller size = 0
            0x01,                               // sessionAttributes = continueSession
            0x00, 0x00,                         // hmac size = 0

            // inSensitive: TPM2B_SENSITIVE_CREATE
            0x00, 0x04,                         // size = 4
            0x00, 0x00,                         // userAuth size = 0
            0x00, 0x00,                         // data size = 0

            // inPublic: TPM2B_PUBLIC
            0x00, 0x10,                         // size = 16 (TPMT_PUBLIC)
            0x00, 0x08,                         // type: TPM_ALG_KEYEDHASH
            0x00, 0x0B,                         // nameAlg: TPM_ALG_SHA256
            0x00, 0x04, 0x00, 0x72,             // objectAttributes
            0x00, 0x00,                         // authPolicy size = 0
            0x00, 0x05,                         // scheme: TPM_ALG_HMAC
            0x00, 0x0B,                         // hashAlg: TPM_ALG_SHA256
            0x00, 0x00,                         // unique size = 0

            // outsideInfo: TPM2B
            0x00, 0x00,                         // size = 0

            // creationPCR: TPML_PCR_SELECTION
            0x00, 0x00, 0x00, 0x00,             // count = 0
        ];

        let n = self.execute_command(&cmd, resp)?;
        if n < 14 {
            return Err(TpmError::ProtocolError);
        }

        // Response bytes 10-13 = object handle (big-endian u32)
        let handle = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);
        Ok(handle)
    }

    /// Read SHA-256 PCR digests for the given indices.
    ///
    /// Sends TPM2_PCR_Read (CC=0x0000017E) and returns the concatenated
    /// 32-byte digests.
    fn read_pcr_digests(
        &mut self,
        pcr_indices: &[u8],
        resp: &mut [u8],
    ) -> Result<Vec<u8>, TpmError> {
        // Build the PCR selection bitmask: 3 bytes, bit N of byte N/8
        let mut pcr_select = [0u8; 3];
        for &idx in pcr_indices {
            if idx < 24 {
                pcr_select[(idx / 8) as usize] |= 1 << (idx % 8);
            }
        }

        // Command structure:
        //   Header: tag(2) + size(4) + CC(4) = 10
        //   pcrSelectionIn: TPML_PCR_SELECTION
        //     count(4) = 1
        //     TPMS_PCR_SELECTION: hash(2) + sizeOfSelect(1) + select(3) = 6
        // Total = 10 + 4 + 6 = 20 bytes
        let total_size: u32 = 20;
        let cmd: [u8; 20] = [
            // Header
            0x80,
            0x01, // tag: TPM_ST_NO_SESSIONS
            (total_size >> 24) as u8,
            (total_size >> 16) as u8,
            (total_size >> 8) as u8,
            total_size as u8,
            0x00,
            0x00,
            0x01,
            0x7E, // CC: TPM2_PCR_Read
            // pcrSelectionIn: TPML_PCR_SELECTION
            0x00,
            0x00,
            0x00,
            0x01, // count = 1
            // TPMS_PCR_SELECTION
            0x00,
            0x0B, // hash: TPM_ALG_SHA256
            0x03, // sizeOfSelect = 3
            pcr_select[0],
            pcr_select[1],
            pcr_select[2],
        ];

        let n = self.execute_command(&cmd, resp)?;

        // Response layout (after 10-byte header):
        //   pcrUpdateCounter: 4 bytes  (offset 10)
        //   pcrSelectionOut: TPML_PCR_SELECTION
        //     count(4)                  (offset 14)
        //     For each: hash(2) + sizeOfSelect(1) + select(sizeOfSelect)
        //   pcrValues: TPML_DIGEST
        //     count(4) then for each: size(2) + digest bytes

        if n < 18 {
            return Err(TpmError::ProtocolError);
        }

        // Parse pcrSelectionOut to skip it
        let sel_count = u32::from_be_bytes([resp[14], resp[15], resp[16], resp[17]]) as usize;
        let mut offset = 18;
        for _ in 0..sel_count {
            if offset + 3 > n {
                return Err(TpmError::ProtocolError);
            }
            let size_of_select = resp[offset + 2] as usize;
            offset += 3 + size_of_select; // hash(2) + sizeOfSelect(1) + select bytes
        }

        // Parse pcrValues: TPML_DIGEST
        if offset + 4 > n {
            return Err(TpmError::ProtocolError);
        }
        let digest_count = u32::from_be_bytes([
            resp[offset],
            resp[offset + 1],
            resp[offset + 2],
            resp[offset + 3],
        ]) as usize;
        offset += 4;

        let mut digests = Vec::new();
        for _ in 0..digest_count {
            if offset + 2 > n {
                return Err(TpmError::ProtocolError);
            }
            let digest_size = u16::from_be_bytes([resp[offset], resp[offset + 1]]) as usize;
            offset += 2;
            if offset + digest_size > n {
                return Err(TpmError::ProtocolError);
            }
            digests.extend_from_slice(&resp[offset..offset + digest_size]);
            offset += digest_size;
        }

        Ok(digests)
    }

    /// Compute HMAC over `data` using the key at `handle`.
    ///
    /// Sends TPM2_HMAC (CC=0x00000155) with PWAP auth.
    /// Returns the 32-byte SHA-256 HMAC output.
    fn hmac_with_key(
        &mut self,
        handle: u32,
        data: &[u8],
        resp: &mut [u8],
    ) -> Result<[u8; 32], TpmError> {
        // Command structure:
        //   Header: tag(2) + size(4) + CC(4) = 10
        //   handle: 4
        //   PWAP auth: 13
        //   buffer: TPM2B_MAX_BUFFER = size(2) + data
        //   hashAlg: 2
        // Total = 10 + 4 + 13 + 2 + data.len() + 2 = 31 + data.len()

        let total_size = (31 + data.len()) as u32;
        let data_len = data.len() as u16;
        let handle_bytes = handle.to_be_bytes();

        // Build command dynamically since data length varies
        let mut cmd = Vec::with_capacity(total_size as usize);

        // Header
        cmd.extend_from_slice(&[0x80, 0x02]); // tag: TPM_ST_SESSIONS
        cmd.extend_from_slice(&total_size.to_be_bytes());
        cmd.extend_from_slice(&[0x00, 0x00, 0x01, 0x55]); // CC: TPM2_HMAC

        // Handle
        cmd.extend_from_slice(&handle_bytes);

        // PWAP auth
        cmd.extend_from_slice(&PWAP_AUTH);

        // buffer: TPM2B_MAX_BUFFER
        cmd.extend_from_slice(&data_len.to_be_bytes());
        cmd.extend_from_slice(data);

        // hashAlg: TPM_ALG_SHA256
        cmd.extend_from_slice(&[0x00, 0x0B]);

        let n = self.execute_command(&cmd, resp)?;

        // Response (TPM_ST_SESSIONS): header(10) + auth response area + outHMAC
        // Auth response area: parameterSize(4) + auth response
        //   auth response: nonce(2) + attrs(1) + hmac(2) = 5 bytes minimum
        //   parameterSize includes everything after it until end
        //
        // For PWAP with null password:
        //   parameterSize(4) = size of (outHMAC)
        //   outHMAC: TPM2B_DIGEST = size(2) + 32 bytes = 34
        //   Then trailing auth: nonce(2=0) + attrs(1) + hmac(2=0) = 5
        //
        // Actually the layout for session response is:
        //   header(10) + parameterSize(4) + parameters + authArea
        // Where parameterSize tells us how many bytes of parameters follow,
        // then the auth area comes after.
        //
        // For TPM2_HMAC: parameters = outHMAC: TPM2B_DIGEST
        // So parameterSize = 2 + 32 = 34

        if n < 14 {
            return Err(TpmError::ProtocolError);
        }

        // parameterSize at offset 10
        let param_size = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]) as usize;
        if param_size < 34 {
            return Err(TpmError::ProtocolError);
        }

        // outHMAC starts at offset 14
        let hmac_size = u16::from_be_bytes([resp[14], resp[15]]) as usize;
        if hmac_size != 32 || 14 + 2 + hmac_size > n {
            return Err(TpmError::ProtocolError);
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&resp[16..48]);
        Ok(result)
    }

    /// Release a transient object handle.
    ///
    /// Sends TPM2_FlushContext (CC=0x00000165), no auth.
    fn flush_context(&mut self, handle: u32, resp: &mut [u8]) -> Result<(), TpmError> {
        // Command: header(10) + handle(4) = 14 bytes
        let total_size: u32 = 14;
        let handle_bytes = handle.to_be_bytes();
        let cmd: [u8; 14] = [
            // Header
            0x80,
            0x01, // tag: TPM_ST_NO_SESSIONS
            (total_size >> 24) as u8,
            (total_size >> 16) as u8,
            (total_size >> 8) as u8,
            total_size as u8,
            0x00,
            0x00,
            0x01,
            0x65, // CC: TPM2_FlushContext
            // Handle
            handle_bytes[0],
            handle_bytes[1],
            handle_bytes[2],
            handle_bytes[3],
        ];

        self.execute_command(&cmd, resp)?;
        Ok(())
    }

    /// Derive a 32-byte hardware-bound key from TPM primary seed,
    /// PCR digests, and caller-provided salt.
    ///
    /// Executes 4 TPM commands:
    /// 1. `TPM2_CreatePrimary` — derive HMAC key under owner hierarchy
    /// 2. `TPM2_PCR_Read` — read SHA-256 digests for requested PCRs
    /// 3. `TPM2_HMAC` — HMAC(key, pcr_digests || salt)
    /// 4. `TPM2_FlushContext` — release transient handle
    ///
    /// Requires `TpmState::Ready`. Can be called multiple times with
    /// different PCR sets or salts.
    pub fn derive_hardware_key(
        &mut self,
        pcr_indices: &[u8],
        salt: &[u8],
    ) -> Result<[u8; 32], TpmError> {
        if self.state != TpmState::Ready {
            return Err(TpmError::InvalidState);
        }

        let mut resp = [0u8; 1024];

        // Step 1: Create primary HMAC key
        let handle = self.create_primary_hmac_key(&mut resp)?;

        // Steps 2-3 wrapped in a closure so we can flush the transient
        // handle unconditionally — even if PCR_Read or HMAC fails.
        // TPM chips allow only 3-5 concurrent transient objects.
        let result = (|| {
            let pcr_digests = self.read_pcr_digests(pcr_indices, &mut resp)?;
            let mut hmac_input = pcr_digests;
            hmac_input.extend_from_slice(salt);
            self.hmac_with_key(handle, &hmac_input, &mut resp)
        })();

        // Step 4: Flush unconditionally so the transient slot is always released
        let _ = self.flush_context(handle, &mut resp);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::spi_bus::mock::MockSpiBus;
    use alloc::vec;

    fn make_driver() -> TpmDriver<MockSpiBus> {
        TpmDriver {
            bus: MockSpiBus::new(),
            state: TpmState::Uninitialized,
        }
    }

    // ── SPI PTP transport tests ──────────────────────────────────────

    #[test]
    fn spi_header_read_format() {
        // Read 4 bytes from TPM_DID_VID (0xD40F00)
        let hdr = TpmDriver::<MockSpiBus>::spi_header(true, 4, 0xD40F00);
        assert_eq!(hdr[0], 0x80 | 3); // read bit + size-1
        assert_eq!(hdr[1], 0xD4);
        assert_eq!(hdr[2], 0x0F);
        assert_eq!(hdr[3], 0x00);
    }

    #[test]
    fn spi_header_write_format() {
        // Write 1 byte to TPM_STS (0xD40018)
        let hdr = TpmDriver::<MockSpiBus>::spi_header(false, 1, 0xD40018);
        assert_eq!(hdr[0], 0x00); // write bit + size-1=0
        assert_eq!(hdr[1], 0xD4);
        assert_eq!(hdr[2], 0x00);
        assert_eq!(hdr[3], 0x18);
    }

    #[test]
    fn read_register_returns_mock_data() {
        let mut driver = make_driver();
        driver
            .bus
            .on_register(TPM_DID_VID, vec![0x15, 0xD1, 0x00, 0x1A]);

        let mut buf = [0u8; 4];
        driver.read_register(TPM_DID_VID, &mut buf).unwrap();
        assert_eq!(buf, [0x15, 0xD1, 0x00, 0x1A]);
    }

    #[test]
    fn read_register_with_wait_states() {
        let mut driver = make_driver();
        driver
            .bus
            .on_register(TPM_DID_VID, vec![0xAB, 0xCD, 0xEF, 0x01]);
        driver.bus.set_wait_states(TPM_DID_VID, 5);

        let mut buf = [0u8; 4];
        driver.read_register(TPM_DID_VID, &mut buf).unwrap();
        assert_eq!(buf, [0xAB, 0xCD, 0xEF, 0x01]);
    }

    #[test]
    fn wait_state_timeout() {
        let mut driver = make_driver();
        // Set wait states higher than MAX_WAIT_CYCLES
        driver.bus.on_register(TPM_DID_VID, vec![0x00]);
        driver
            .bus
            .set_wait_states(TPM_DID_VID, MAX_WAIT_CYCLES + 100);

        let mut buf = [0u8; 4];
        assert_eq!(
            driver.read_register(TPM_DID_VID, &mut buf).unwrap_err(),
            TpmError::Timeout
        );
    }

    // ── Command engine tests ─────────────────────────────────────────

    /// Helper: configure MockSpiBus for a successful command execution.
    /// Sets up TPM_ACCESS (valid + active), TPM_STS (commandReady,
    /// burstCount=64, dataAvail), and a canned response on DATA_FIFO.
    fn mock_command_flow(bus: &mut MockSpiBus, response: &[u8]) {
        // TPM_ACCESS: valid + active
        bus.on_register(TPM_ACCESS, vec![0x90]);
        // TPM_STS reads for execute_command. We need enough entries for:
        // 1: commandReady poll, 2: burstCount for write, 3: dataAvail poll,
        // 4+: burstCount for response reads (may need multiple if response > 64).
        // Queue generous entries — the last one is sticky.
        bus.on_register(TPM_STS, vec![0x40, 0x00, 0x00, 0x00]); // commandReady
        bus.on_register(TPM_STS, vec![0x40, 0x40, 0x00, 0x00]); // burstCount=64
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]); // dataAvail+burst
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]); // extra for read
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]); // extra
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]); // extra
                                                                // FIFO response
        bus.on_fifo(TPM_DATA_FIFO, response.to_vec());
    }

    #[test]
    fn execute_command_returns_response() {
        let mut driver = make_driver();
        // A minimal TPM response: 10-byte header with success RC
        let response_bytes = [
            0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x0A, // size: 10
            0x00, 0x00, 0x00, 0x00, // RC: success
        ];
        mock_command_flow(&mut driver.bus, &response_bytes);

        // A minimal command: 10-byte header
        let command = [
            0x80, 0x01, // tag
            0x00, 0x00, 0x00, 0x0A, // size: 10
            0x00, 0x00, 0x01, 0x44, // TPM2_Startup
        ];
        let mut resp = [0u8; 64];
        let len = driver.execute_command(&command, &mut resp).unwrap();
        assert_eq!(len, 10);
        assert_eq!(&resp[..10], &response_bytes);
    }

    #[test]
    fn execute_command_failed_rc() {
        let mut driver = make_driver();
        let response_bytes = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
            0x00, // RC: TPM_RC_INITIALIZE
        ];
        mock_command_flow(&mut driver.bus, &response_bytes);

        let command = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x44];
        let mut resp = [0u8; 64];
        let err = driver.execute_command(&command, &mut resp).unwrap_err();
        assert_eq!(err, TpmError::CommandFailed { rc: 0x100 });
    }

    #[test]
    fn execute_command_locality_unavailable() {
        let mut driver = make_driver();
        // TPM_ACCESS without valid bit
        driver.bus.on_register(TPM_ACCESS, vec![0x00]);

        let command = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x44];
        let mut resp = [0u8; 64];
        let err = driver.execute_command(&command, &mut resp).unwrap_err();
        assert_eq!(err, TpmError::LocalityUnavailable);
    }

    // ── Init tests ───────────────────────────────────────────────────

    /// Helper: configure mock for a successful init sequence.
    fn mock_init_flow(bus: &mut MockSpiBus) {
        // DID_VID probe
        bus.on_register(TPM_DID_VID, vec![0x15, 0xD1, 0x00, 0x1A]);

        // Startup: command flow (4 STS reads — writes don't advance cursor)
        bus.on_register(TPM_ACCESS, vec![0x90]);
        bus.on_register(TPM_STS, vec![0x40, 0x00, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x40, 0x40, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]);
        bus.on_fifo(
            TPM_DATA_FIFO,
            vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00],
        );

        // SelfTest: command flow
        bus.on_register(TPM_ACCESS, vec![0x90]);
        bus.on_register(TPM_STS, vec![0x40, 0x00, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x40, 0x40, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]);
        bus.on_fifo(
            TPM_DATA_FIFO,
            vec![
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, // success
            ],
        );
    }

    #[test]
    fn init_succeeds_and_transitions_to_ready() {
        let mut bus = MockSpiBus::new();
        mock_init_flow(&mut bus);
        let driver = TpmDriver::init(bus).unwrap();
        assert_eq!(driver.state(), TpmState::Ready);
    }

    #[test]
    fn init_accepts_tpm_rc_initialize() {
        let mut bus = MockSpiBus::new();
        bus.on_register(TPM_DID_VID, vec![0x15, 0xD1, 0x00, 0x1A]);

        // Startup returns TPM_RC_INITIALIZE
        bus.on_register(TPM_ACCESS, vec![0x90]);
        bus.on_register(TPM_STS, vec![0x40, 0x00, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x40, 0x40, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]);
        bus.on_fifo(
            TPM_DATA_FIFO,
            vec![
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x00, // RC = 0x100
            ],
        );

        // SelfTest succeeds
        bus.on_register(TPM_ACCESS, vec![0x90]);
        bus.on_register(TPM_STS, vec![0x40, 0x00, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x40, 0x40, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]);
        bus.on_register(TPM_STS, vec![0x10, 0x40, 0x00, 0x00]);
        bus.on_fifo(
            TPM_DATA_FIFO,
            vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00],
        );

        let driver = TpmDriver::init(bus).unwrap();
        assert_eq!(driver.state(), TpmState::Ready);
    }

    #[test]
    fn init_locality_unavailable() {
        let mut bus = MockSpiBus::new();
        bus.on_register(TPM_DID_VID, vec![0x15, 0xD1, 0x00, 0x1A]);
        bus.on_register(TPM_ACCESS, vec![0x00]); // no valid bit

        let err = TpmDriver::init(bus).unwrap_err();
        assert_eq!(err, TpmError::LocalityUnavailable);
    }

    // ── Key derivation tests ──────────────────────────────────────────

    /// Fake 32-byte PCR digest (all 0xAA).
    const FAKE_PCR_DIGEST: [u8; 32] = [0xAA; 32];

    /// Fake 32-byte HMAC output (deterministic for testing).
    const FAKE_HMAC_OUTPUT: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];

    /// Build the mock CreatePrimary response.
    /// tag=0x8002, size, RC=0, handle=0x80000001, then padding.
    fn create_primary_response() -> Vec<u8> {
        let mut resp = vec![0u8; 64];
        // tag: TPM_ST_SESSIONS
        resp[0] = 0x80;
        resp[1] = 0x02;
        // size: 64
        resp[2] = 0x00;
        resp[3] = 0x00;
        resp[4] = 0x00;
        resp[5] = 0x40;
        // RC: success
        resp[6] = 0x00;
        resp[7] = 0x00;
        resp[8] = 0x00;
        resp[9] = 0x00;
        // object handle: 0x80000001
        resp[10] = 0x80;
        resp[11] = 0x00;
        resp[12] = 0x00;
        resp[13] = 0x01;
        resp
    }

    /// Build the mock PCR_Read response for 1 PCR (PCR 0).
    /// tag=0x8001, RC=0, pcrUpdateCounter, selectionOut, pcrValues with 1 digest.
    fn pcr_read_response() -> Vec<u8> {
        // Layout:
        //   header: tag(2) + size(4) + RC(4) = 10
        //   pcrUpdateCounter: 4                         (offset 10)
        //   pcrSelectionOut: count(4) + hash(2) + sizeOfSelect(1) + select(3) = 10  (offset 14)
        //   pcrValues: count(4) + size(2) + digest(32) = 38  (offset 24)
        // Total = 10 + 4 + 10 + 38 = 62
        let total_size: u32 = 62;
        let mut resp = vec![0u8; total_size as usize];
        // tag: TPM_ST_NO_SESSIONS
        resp[0] = 0x80;
        resp[1] = 0x01;
        // size
        resp[2] = (total_size >> 24) as u8;
        resp[3] = (total_size >> 16) as u8;
        resp[4] = (total_size >> 8) as u8;
        resp[5] = total_size as u8;
        // RC: success
        // (already 0)
        // pcrUpdateCounter = 1
        resp[13] = 0x01;
        // pcrSelectionOut: count = 1
        resp[17] = 0x01;
        // hash: TPM_ALG_SHA256 = 0x000B
        resp[18] = 0x00;
        resp[19] = 0x0B;
        // sizeOfSelect = 3
        resp[20] = 0x03;
        // select: PCR 0 = bit 0 of byte 0
        resp[21] = 0x01;
        resp[22] = 0x00;
        resp[23] = 0x00;
        // pcrValues: count = 1
        resp[27] = 0x01;
        // digest: size = 32
        resp[28] = 0x00;
        resp[29] = 0x20;
        // digest bytes
        resp[30..62].copy_from_slice(&FAKE_PCR_DIGEST);
        resp
    }

    /// Build the mock HMAC response.
    /// tag=0x8002, RC=0, parameterSize(4)=34, outHMAC: size(2)+digest(32),
    /// then trailing auth.
    fn hmac_response() -> Vec<u8> {
        // Layout:
        //   header: tag(2) + size(4) + RC(4) = 10
        //   parameterSize(4) = 34           (offset 10)
        //   outHMAC: size(2) + digest(32)   (offset 14)
        //   trailing auth: nonce(2) + attrs(1) + hmac(2) = 5  (offset 48)
        // Total = 10 + 4 + 34 + 5 = 53
        let total_size: u32 = 53;
        let mut resp = vec![0u8; total_size as usize];
        // tag: TPM_ST_SESSIONS
        resp[0] = 0x80;
        resp[1] = 0x02;
        // size
        resp[2] = (total_size >> 24) as u8;
        resp[3] = (total_size >> 16) as u8;
        resp[4] = (total_size >> 8) as u8;
        resp[5] = total_size as u8;
        // RC: success (already 0)
        // parameterSize = 34 (0x22)
        resp[13] = 0x22;
        // outHMAC: size = 32
        resp[14] = 0x00;
        resp[15] = 0x20;
        // HMAC digest
        resp[16..48].copy_from_slice(&FAKE_HMAC_OUTPUT);
        // trailing auth: nonce size=0, attrs=continueSession, hmac size=0
        resp[48] = 0x00;
        resp[49] = 0x00;
        resp[50] = 0x01;
        resp[51] = 0x00;
        resp[52] = 0x00;
        resp
    }

    /// Build the mock FlushContext response.
    fn flush_context_response() -> Vec<u8> {
        vec![
            0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x0A, // size: 10
            0x00, 0x00, 0x00, 0x00, // RC: success
        ]
    }

    /// Helper: set up mock bus for a full derive_hardware_key workflow
    /// (4 command executions: CreatePrimary, PCR_Read, HMAC, FlushContext).
    fn mock_derive_flow(bus: &mut MockSpiBus) {
        // CreatePrimary
        mock_command_flow(bus, &create_primary_response());
        // PCR_Read
        mock_command_flow(bus, &pcr_read_response());
        // HMAC
        mock_command_flow(bus, &hmac_response());
        // FlushContext
        mock_command_flow(bus, &flush_context_response());
    }

    #[test]
    fn derive_hardware_key_requires_ready_state() {
        let mut driver = make_driver();
        assert_eq!(driver.state(), TpmState::Uninitialized);

        let err = driver.derive_hardware_key(&[0], b"salt").unwrap_err();
        assert_eq!(err, TpmError::InvalidState);
    }

    #[test]
    fn derive_hardware_key_returns_32_bytes() {
        let mut bus = MockSpiBus::new();
        mock_init_flow(&mut bus);
        mock_derive_flow(&mut bus);

        let mut driver = TpmDriver::init(bus).unwrap();
        assert_eq!(driver.state(), TpmState::Ready);

        let key = driver.derive_hardware_key(&[0], b"test-salt").unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(key, FAKE_HMAC_OUTPUT);
        // Verify still in Ready state (can call again)
        assert_eq!(driver.state(), TpmState::Ready);
    }

    #[test]
    fn derive_hardware_key_deterministic() {
        // First call
        let mut bus1 = MockSpiBus::new();
        mock_init_flow(&mut bus1);
        mock_derive_flow(&mut bus1);
        let mut driver1 = TpmDriver::init(bus1).unwrap();
        let key1 = driver1.derive_hardware_key(&[0], b"salt").unwrap();

        // Second call with identical mocks
        let mut bus2 = MockSpiBus::new();
        mock_init_flow(&mut bus2);
        mock_derive_flow(&mut bus2);
        let mut driver2 = TpmDriver::init(bus2).unwrap();
        let key2 = driver2.derive_hardware_key(&[0], b"salt").unwrap();

        assert_eq!(key1, key2);
    }

    // ── Integration test ─────────────────────────────────────────────

    #[test]
    fn full_tpm_lifecycle() {
        // Configure mock with ALL responses (init + derive) before calling init().
        // init() consumes the bus, so the full sequence must be pre-loaded.
        let mut bus = MockSpiBus::new();
        mock_init_flow(&mut bus);
        mock_derive_flow(&mut bus);

        // 1. init() succeeds → Ready state
        let mut driver = TpmDriver::init(bus).unwrap();
        assert_eq!(driver.state(), TpmState::Ready);

        // 2. derive_hardware_key([0], b"harmony-os") returns 32 bytes
        let key = driver.derive_hardware_key(&[0], b"harmony-os").unwrap();
        assert_eq!(key.len(), 32);

        // 3. Key is non-zero
        assert!(key.iter().any(|&b| b != 0));
    }
}
