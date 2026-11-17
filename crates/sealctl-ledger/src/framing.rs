//! Ledger APDU framing, shared by USB HID and Bluetooth LE.
//!
//! Every frame is: `[channel u16 BE (HID only)] 0x05 seq:u16 BE [len:u16 BE on seq 0] payload…`.
//! HID frames are padded to the 64-byte report size; BLE frames are at most `mtu` bytes.

use thiserror::Error;

pub const TAG_APDU: u8 = 0x05;
pub const HID_CHANNEL: u16 = 0x0101;
pub const HID_PACKET_SIZE: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FramingError {
    #[error("frame too short")]
    Short,
    #[error("unexpected channel {0:#06x}")]
    Channel(u16),
    #[error("unexpected tag {0:#04x}")]
    Tag(u8),
    #[error("unexpected sequence {got}, expected {expected}")]
    Sequence { got: u16, expected: u16 },
    #[error("APDU too long ({0} bytes)")]
    TooLong(usize),
    #[error("packet size {0} too small")]
    PacketSize(usize),
}

/// Split an APDU into frames of at most `packet_size` bytes.
/// With `channel = Some(..)` (HID) every frame is zero-padded to `packet_size`.
pub fn encode(apdu: &[u8], packet_size: usize, channel: Option<u16>) -> Result<Vec<Vec<u8>>, FramingError> {
    if apdu.len() > u16::MAX as usize {
        return Err(FramingError::TooLong(apdu.len()));
    }
    let header = |seq: u16| {
        let mut h = Vec::with_capacity(7);
        if let Some(ch) = channel {
            h.extend_from_slice(&ch.to_be_bytes());
        }
        h.push(TAG_APDU);
        h.extend_from_slice(&seq.to_be_bytes());
        if seq == 0 {
            h.extend_from_slice(&(apdu.len() as u16).to_be_bytes());
        }
        h
    };
    if packet_size <= header(0).len() {
        return Err(FramingError::PacketSize(packet_size));
    }

    let mut frames = Vec::new();
    let mut offset = 0;
    let mut seq: u16 = 0;
    while offset < apdu.len() || seq == 0 {
        let mut frame = header(seq);
        let take = (packet_size - frame.len()).min(apdu.len() - offset);
        frame.extend_from_slice(&apdu[offset..offset + take]);
        if channel.is_some() {
            frame.resize(packet_size, 0);
        }
        frames.push(frame);
        offset += take;
        seq = seq.wrapping_add(1);
    }
    Ok(frames)
}

/// Reassembles a response from incoming frames.
#[derive(Debug)]
pub struct Decoder {
    channel: Option<u16>,
    expected_seq: u16,
    total: Option<usize>,
    data: Vec<u8>,
}

impl Decoder {
    pub fn new(channel: Option<u16>) -> Self {
        Self {
            channel,
            expected_seq: 0,
            total: None,
            data: Vec::new(),
        }
    }

    /// Feed one frame. Returns `Ok(Some(response))` once the whole response arrived.
    /// Frames with a foreign tag (e.g. BLE MTU replies) are ignored.
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, FramingError> {
        let mut f = frame;
        if let Some(ch) = self.channel {
            if f.len() < 2 {
                return Err(FramingError::Short);
            }
            let got = u16::from_be_bytes([f[0], f[1]]);
            if got != ch {
                return Err(FramingError::Channel(got));
            }
            f = &f[2..];
        }
        if f.len() < 3 {
            return Err(FramingError::Short);
        }
        if f[0] != TAG_APDU {
            if self.channel.is_none() {
                return Ok(None);
            }
            return Err(FramingError::Tag(f[0]));
        }
        let seq = u16::from_be_bytes([f[1], f[2]]);
        if seq != self.expected_seq {
            return Err(FramingError::Sequence {
                got: seq,
                expected: self.expected_seq,
            });
        }
        let mut payload = &f[3..];
        if seq == 0 {
            if payload.len() < 2 {
                return Err(FramingError::Short);
            }
            self.total = Some(u16::from_be_bytes([payload[0], payload[1]]) as usize);
            payload = &payload[2..];
        }
        // a reply is at most 64 KiB, far below 65 536 frames: refuse to wrap the counter
        self.expected_seq = self.expected_seq.checked_add(1).ok_or(FramingError::Short)?;
        let total = self.total.unwrap_or(0);
        let need = total.saturating_sub(self.data.len());
        self.data.extend_from_slice(&payload[..payload.len().min(need)]);
        if self.data.len() >= total {
            return Ok(Some(std::mem::take(&mut self.data)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(apdu: &[u8], size: usize, channel: Option<u16>) {
        let frames = encode(apdu, size, channel).unwrap();
        for f in &frames {
            assert!(f.len() <= size);
            if channel.is_some() {
                assert_eq!(f.len(), size);
            }
        }
        let mut d = Decoder::new(channel);
        let mut out = None;
        for f in &frames {
            out = d.push(f).unwrap();
        }
        assert_eq!(out.unwrap(), apdu);
    }

    #[test]
    fn hid_roundtrip_various_lengths() {
        for len in [0, 1, 4, 57, 58, 59, 120, 255, 600] {
            let apdu: Vec<u8> = (0..len).map(|i| i as u8).collect();
            roundtrip(&apdu, HID_PACKET_SIZE, Some(HID_CHANNEL));
        }
    }

    #[test]
    fn ble_roundtrip_various_mtus() {
        for mtu in [20, 23, 153, 512] {
            for len in [5, 15, 16, 17, 100, 300] {
                let apdu: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
                roundtrip(&apdu, mtu, None);
            }
        }
    }

    #[test]
    fn select_openpgp_hid_frame_layout() {
        let apdu = [0x00, 0xa4, 0x04, 0x00, 0x06, 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
        let f = &encode(&apdu, 64, Some(HID_CHANNEL)).unwrap()[0];
        assert_eq!(&f[..7], &[0x01, 0x01, 0x05, 0x00, 0x00, 0x00, 0x0b]);
        assert_eq!(&f[7..18], &apdu);
    }

    #[test]
    fn rejects_bad_sequence() {
        let mut d = Decoder::new(None);
        assert_eq!(
            d.push(&[0x05, 0x00, 0x01, 0x00]),
            Err(FramingError::Sequence { got: 1, expected: 0 })
        );
    }

    #[test]
    fn ignores_foreign_ble_tags() {
        let mut d = Decoder::new(None);
        assert_eq!(d.push(&[0x08, 0, 0, 0, 0, 153]), Ok(None));
    }
}
