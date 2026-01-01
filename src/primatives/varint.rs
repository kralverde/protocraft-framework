use crate::{
    error::{ReadError, WriteError},
    from_reader_helper, to_writer_helper,
    traits::Serializable,
};

pub struct VarInt(i32);

impl From<i32> for VarInt {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

#[allow(clippy::from_over_into)]
impl Into<i32> for VarInt {
    fn into(self) -> i32 {
        self.0
    }
}

pub(crate) const SEGMENT_MASK: u32 = 0x7f;
pub(crate) const CONTINUE_MASK_U32: u32 = 0x80;
const CONTINUE_MASK_U8: u8 = 0x80;

from_reader_helper!(VarInt {
    let mut value = 0;
    for offset in (0..32).step_by(7) {
        let curr: u32 = read!(u8).into();
        value |= (curr & SEGMENT_MASK) << offset;
        if (curr & CONTINUE_MASK_U32) == 0 {
            return Ok(VarInt(value as i32));
        }
    }

    Err(ReadError::OverSized {
        name: "varint",
        maximum: 5,
        was: 6,
    })
});

impl Serializable for VarInt {
    #[inline]
    fn size(&self) -> usize {
        let absolute = self.0 as u32;
        let chunks_of_seven_bits = absolute.checked_ilog2().unwrap_or(0) / 7 + 1;
        chunks_of_seven_bits as usize
    }
}

to_writer_helper!(VarInt, this {
    let mut buf = [0u8; 5];
    for (index, byte) in buf.iter_mut().enumerate() {
        let remaining = (this.0 as u32) >> (index * 7);
        if (remaining & !SEGMENT_MASK) == 0 {
            *byte = remaining as u8;
            write_bytes!(&buf[..=index]);
            return Ok(());
        }
        let masked = remaining & SEGMENT_MASK;
        *byte = (masked as u8) | CONTINUE_MASK_U8;
    }

    // This should not be possible to reach
    Err(WriteError::MalformedVarInt)
});
