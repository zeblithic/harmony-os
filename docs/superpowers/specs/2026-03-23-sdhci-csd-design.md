# SDHCI: Parse CSD Register for Real Card Capacity

**Bead:** harmony-os-hcz
**Date:** 2026-03-23
**Status:** Draft

## Problem

The SDHCI driver hardcodes `capacity_blocks = 0` after card initialization.
The SD server reports file size 0, and callers cannot bounds-check LBAs.
The CSD (Card-Specific Data) register contains the actual card capacity but
is never read.

## Solution

Add CMD9 (SEND_CSD) to the card init sequence after CMD7. Parse the 128-bit
R2 response to extract card capacity. Support both CSD v2.0 (SDHC/SDXC) and
CSD v1.0 (SDSC) formats.

## Design Decisions

### CMD9 after CMD7, before CMD16

CMD9 requires the card to be in standby or transfer state. After CMD7 selects
the card, it's in transfer state — CMD9 works here. The card must be
addressed by its RCA (bits [31:16] of the argument).

### SDHCI response register shift

The SDHCI controller shifts the 128-bit R2 response right by 8 bits when
storing it in RESPONSE_0-3. CSD bit positions must account for this 8-bit
shift when extracting fields from the register values.

### CSD v2.0 for SDHC/SDXC (primary path)

CSD v2.0 uses a simple capacity formula: `capacity_blocks = (C_SIZE + 1) * 1024`.
`C_SIZE` is in CSD bits [69:48] (22 bits). After the 8-bit SDHCI shift,
this maps to bits [61:40] across RESPONSE_1 and RESPONSE_0.

### CSD v1.0 for SDSC (fallback)

CSD v1.0 uses: `capacity_blocks = (C_SIZE + 1) * (1 << (C_SIZE_MULT + 2)) * (1 << READ_BL_LEN) / 512`.
Fields: `C_SIZE` [73:62], `C_SIZE_MULT` [49:47], `READ_BL_LEN` [83:80].
After SDHCI shift: adjusted by -8 bits.

### CSD version from bits [127:126]

`0b00` = v1.0 (SDSC), `0b01` = v2.0 (SDHC/SDXC). After SDHCI shift, these
are bits [119:118] → in RESPONSE_3.

## Architecture

### New Constants

```rust
const CMD9_SEND_CSD: u8 = 9;
```

### CMD9 in init_card()

After CMD7 (select card) and before CMD16 (set block length):

```rust
// CMD9: SEND_CSD — read Card-Specific Data register.
// Argument: RCA in [31:16], R2 (Long) response.
let csd_resp = self.send_command(
    bank, CMD9_SEND_CSD, (rca as u32) << 16,
    CMD_RSP_136 | CMD_CRC_CHK, 0,
)?;
let capacity_blocks = match csd_resp {
    Response::Long(words) => parse_csd_capacity(words, is_sdhc),
    _ => 0,
};
```

### parse_csd_capacity Function

```rust
fn parse_csd_capacity(resp: [u32; 4], is_sdhc: bool) -> u32 {
    // SDHCI shifts R2 response right by 8 bits.
    // CSD version in bits [127:126] → after shift: RESPONSE_3 bits [23:22].
    let csd_version = (resp[3] >> 22) & 0x3;

    if is_sdhc && csd_version == 1 {
        // CSD v2.0: C_SIZE in CSD bits [69:48] → after shift: bits [61:40].
        // Spans RESPONSE_1 [29:8] and top bits of RESPONSE_0.
        let c_size = ((resp[1] & 0x3F_FF_FF00) >> 8) as u32;
        // Actually: need to extract 22 bits carefully.
        // RESPONSE_1 bits [29:8] = CSD bits [69:48] after shift.
        let c_size_hi = (resp[1] >> 8) & 0x3F_FFFF; // 22 bits
        (c_size_hi + 1) * 1024
    } else if csd_version == 0 {
        // CSD v1.0: C_SIZE [73:62], C_SIZE_MULT [49:47], READ_BL_LEN [83:80]
        // After 8-bit shift: C_SIZE [65:54], C_SIZE_MULT [41:39], READ_BL_LEN [75:72]
        let read_bl_len = ((resp[2] >> 8) & 0xF) as u32;
        let c_size = (((resp[2] & 0x3) << 10) | ((resp[1] >> 22) & 0x3FF)) as u32;
        let c_size_mult = ((resp[1] >> 7) & 0x7) as u32;
        let block_len = 1u32 << read_bl_len;
        let mult = 1u32 << (c_size_mult + 2);
        let total_bytes = (c_size + 1) as u64 * mult as u64 * block_len as u64;
        (total_bytes / 512) as u32
    } else {
        0 // Unknown CSD version
    }
}
```

## File Changes

| File | Change |
|------|--------|
| `crates/harmony-unikernel/src/drivers/sdhci.rs` | Add CMD9 constant, send CMD9 in init_card, parse_csd_capacity function |
| `crates/harmony-microkernel/src/sd_server.rs` | Update test mocks to include CMD9 response |

## What is NOT in Scope

- No DMA mode (PIO only)
- No partition table parsing
- No filesystem support
- No eMMC extensions
- No CSD write (CMD27)

## Testing

- `parse_csd_v2_capacity` — known C_SIZE → expected block count
- `parse_csd_v1_capacity` — known v1.0 fields → expected block count
- `init_card_sends_cmd9` — verify CMD9 sent with correct RCA argument
- `init_card_parses_capacity` — full init with mocked CMD9 response → non-zero capacity_blocks
- Update existing init/test helpers to mock the CMD9 R2 response
- SD server stat test verifies non-zero file size
