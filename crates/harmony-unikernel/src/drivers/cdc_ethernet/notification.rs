// SPDX-License-Identifier: GPL-2.0-or-later

//! CDC notification parser for the interrupt IN endpoint.
//!
//! Parses `NETWORK_CONNECTION` and `CONNECTION_SPEED_CHANGE` notifications
//! as defined in USB CDC specification section 6.3.

// ── CDC notification constants ───────────────────────────────────

/// CDC notification: network connection state changed.
const NOTIF_NETWORK_CONNECTION: u8 = 0x00;

/// CDC notification: connection speed changed.
const NOTIF_CONNECTION_SPEED_CHANGE: u8 = 0x2A;

/// bmRequestType for CDC notifications (class, interface, device-to-host).
const CDC_NOTIF_REQUEST_TYPE: u8 = 0xA1;

// ── Error type ───────────────────────────────────────────────────

/// Errors produced by CDC class driver operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdcError {
    /// A descriptor was shorter than the minimum required length.
    DescriptorTooShort,
    /// No CDC Communication interface was found in the configuration.
    NoCdcInterface,
    /// A required endpoint (interrupt IN or bulk IN/OUT) was missing.
    MissingEndpoint,
    /// A required functional descriptor (e.g. ECM or NCM) was missing.
    MissingFunctionalDescriptor,
    /// The iMACAddress string descriptor was absent or non-UTF-16 encoded.
    InvalidMacString,
    /// The NTB (NCM Transfer Block) header was malformed or had bad signature.
    MalformedNtb,
    /// An Ethernet frame exceeded the maximum allowed size.
    FrameTooLarge,
    /// The driver is not yet ready (e.g. link is down).
    NotReady,
    /// The notification packet was shorter than the 8-byte header.
    NotificationTooShort,
}

// ── Notification type ────────────────────────────────────────────

/// A parsed CDC interrupt IN notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdcNotification {
    /// Network connection state changed (NETWORK_CONNECTION, 0x00).
    NetworkConnection {
        /// `true` if the network is now connected, `false` if disconnected.
        connected: bool,
    },
    /// Link speed changed (CONNECTION_SPEED_CHANGE, 0x2A).
    ConnectionSpeedChange {
        /// Downstream bit rate in bits per second.
        downstream: u32,
        /// Upstream bit rate in bits per second.
        upstream: u32,
    },
    /// An unrecognised notification type — ignored by the driver.
    Unknown {
        /// The `bNotificationCode` byte from the header.
        request: u8,
    },
}

// ── Parser ───────────────────────────────────────────────────────

/// Parse a raw CDC notification from the interrupt IN endpoint.
///
/// The CDC notification header is 8 bytes:
/// ```text
/// Offset  Field               Size
///      0  bmRequestType        1   must be 0xA1
///      1  bNotificationCode    1
///      2  wValue               2  (little-endian)
///      4  wIndex               2  (little-endian, interface number)
///      6  wLength              2  (little-endian, payload length)
///      8  payload             wLength bytes
/// ```
///
/// # Errors
///
/// Returns [`CdcError::NotificationTooShort`] if `data` is shorter than
/// 8 bytes or shorter than `8 + wLength`.
pub fn parse_notification(data: &[u8]) -> Result<CdcNotification, CdcError> {
    if data.len() < 8 {
        return Err(CdcError::NotificationTooShort);
    }

    let request_code = data[1];
    let w_value = u16::from_le_bytes([data[2], data[3]]);
    let w_length = u16::from_le_bytes([data[6], data[7]]);
    let payload_len = w_length as usize;

    if data.len() < 8 + payload_len {
        return Err(CdcError::NotificationTooShort);
    }

    let payload = &data[8..8 + payload_len];

    match request_code {
        NOTIF_NETWORK_CONNECTION => Ok(CdcNotification::NetworkConnection {
            connected: w_value != 0,
        }),
        NOTIF_CONNECTION_SPEED_CHANGE => {
            // Payload: DLBitRate (4 bytes LE) || ULBitRate (4 bytes LE)
            if payload.len() < 8 {
                return Err(CdcError::NotificationTooShort);
            }
            let downstream = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let upstream = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
            Ok(CdcNotification::ConnectionSpeedChange {
                downstream,
                upstream,
            })
        }
        other => Ok(CdcNotification::Unknown { request: other }),
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a NETWORK_CONNECTION notification header.
    fn network_connection_notif(connected: bool) -> [u8; 8] {
        let w_value: u16 = if connected { 1 } else { 0 };
        [
            CDC_NOTIF_REQUEST_TYPE,
            NOTIF_NETWORK_CONNECTION,
            (w_value & 0xFF) as u8,
            (w_value >> 8) as u8,
            0x00, // wIndex low
            0x00, // wIndex high
            0x00, // wLength low
            0x00, // wLength high
        ]
    }

    /// Build a CONNECTION_SPEED_CHANGE notification with 8-byte payload.
    fn speed_change_notif(downstream: u32, upstream: u32) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0] = CDC_NOTIF_REQUEST_TYPE;
        buf[1] = NOTIF_CONNECTION_SPEED_CHANGE;
        // wValue = 0, wIndex = 0
        buf[6] = 8; // wLength = 8
        buf[7] = 0;
        buf[8..12].copy_from_slice(&downstream.to_le_bytes());
        buf[12..16].copy_from_slice(&upstream.to_le_bytes());
        buf
    }

    #[test]
    fn parse_network_connection_connected() {
        let notif = network_connection_notif(true);
        assert_eq!(
            parse_notification(&notif),
            Ok(CdcNotification::NetworkConnection { connected: true })
        );
    }

    #[test]
    fn parse_network_connection_disconnected() {
        let notif = network_connection_notif(false);
        assert_eq!(
            parse_notification(&notif),
            Ok(CdcNotification::NetworkConnection { connected: false })
        );
    }

    #[test]
    fn parse_speed_change() {
        let notif = speed_change_notif(100_000_000, 100_000_000);
        assert_eq!(
            parse_notification(&notif),
            Ok(CdcNotification::ConnectionSpeedChange {
                downstream: 100_000_000,
                upstream: 100_000_000,
            })
        );
    }

    #[test]
    fn parse_speed_change_asymmetric() {
        let notif = speed_change_notif(100_000_000, 10_000_000);
        assert_eq!(
            parse_notification(&notif),
            Ok(CdcNotification::ConnectionSpeedChange {
                downstream: 100_000_000,
                upstream: 10_000_000,
            })
        );
    }

    #[test]
    fn parse_speed_change_payload_too_short() {
        // Header says wLength=4 but spec requires 8 bytes of payload.
        let mut buf = [0u8; 12];
        buf[0] = CDC_NOTIF_REQUEST_TYPE;
        buf[1] = NOTIF_CONNECTION_SPEED_CHANGE;
        buf[6] = 4; // wLength = 4 (too short — need 8)
        // Only 4 bytes of payload present.
        assert_eq!(
            parse_notification(&buf),
            Err(CdcError::NotificationTooShort)
        );
    }

    #[test]
    fn parse_unknown_notification() {
        let buf = [
            CDC_NOTIF_REQUEST_TYPE,
            0xFF, // unknown bNotificationCode
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        assert_eq!(
            parse_notification(&buf),
            Ok(CdcNotification::Unknown { request: 0xFF })
        );
    }

    #[test]
    fn parse_too_short() {
        // Only 7 bytes — shorter than the 8-byte header.
        let buf = [0xA1, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_notification(&buf), Err(CdcError::NotificationTooShort));
    }
}
