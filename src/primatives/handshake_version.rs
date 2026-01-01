use crate::{
    error::ReadError,
    from_reader_helper,
    primatives::varint::{CONTINUE_MASK_U32, SEGMENT_MASK},
};

/// The type of "handshake" that was sent to the server.
/// Represents minecraft versions >1.6, 1.6, 1.4-1.5, and <=1.3 respectively.
pub enum HandshakeVersion {
    Standard(usize),
    Legacy1_6(usize),
    Pre1_6,
    Pre1_3,
}

from_reader_helper!(HandshakeVersion {
    let first_byte = read!(u8);
    if first_byte == 0xFE {
        if let Some(next_byte) = try_read_byte!() {
            if next_byte != 0x01 {
                return Err(ReadError::MalformedLegacyPing);
            }

            if let Some(channel_byte) = try_read_byte!() {
                if channel_byte != 0xFA {
                    return Err(ReadError::MalformedLegacyPing);
                }

                let channel_length = read_bytes!(2);
                if i16::from_be_bytes(channel_length) != 0x0B {
                    return Err(ReadError::MalformedLegacyPing);
                }

                let channel = read_bytes!(22);
                if channel
                    != [
                        // the string MC|PingHost encoded as a UTF-16BE string
                        0x00, 0x4D, 0x00, 0x43, 0x00, 0x7C, 0x00, 0x50, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x67,
                        0x00, 0x48, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x74,
                    ]
                {
                    return Err(ReadError::MalformedLegacyPing);
                }

                let data_length = read_bytes!(2);
                let bound = i16::from_be_bytes(data_length);

                if bound < 0 {
                    return Err(ReadError::NegativeLength {
                        name: "legacy_ping_bound",
                    });
                }

                Ok(HandshakeVersion::Legacy1_6(bound as usize))
            } else {
                Ok(HandshakeVersion::Pre1_6)
            }
        } else {
            Ok(HandshakeVersion::Pre1_3)
        }
    } else {
        // >1.6; this is a VarInt that has a maximum of 3 bytes (24 bits).
        let mut value = first_byte as u32;
        if (value & CONTINUE_MASK_U32) != 0 {
            let mut ok = false;
            for offset in (7..24).step_by(7) {
                let curr: u32 = read!(u8).into();
                value |= (curr & SEGMENT_MASK) << offset;
                if (curr & CONTINUE_MASK_U32) == 0 {
                    ok = true;
                    break;
                }
            }

            if !ok {
                return Err(ReadError::OverSized {
                    name: "handshake_varint",
                    maximum: 3,
                    was: 4,
                });
            }
        }

        let value = value as i32;
        if value < 0 {
            return Err(ReadError::NegativeLength { name: "handshake_varint" });
        }

        Ok(HandshakeVersion::Standard(value as usize))
    }
});
