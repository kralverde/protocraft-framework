#[cfg(feature = "async")]
use crate::traits::asynchronous::{AsyncBoundedReader, AsyncFromReader};
use crate::{
    error::{ReadError, WriteError},
    traits::{BoundedReader, FromReader, Serializable, ToWriter, Writer},
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

const SEGMENT_MASK: u32 = 0x7f;
const CONTINUE_MASK_U32: u32 = 0x80;
const CONTINUE_MASK_U8: u8 = 0x80;

impl FromReader for VarInt {
    fn from_reader<R>(reader: &mut R) -> Result<Self, ReadError<R::Error>>
    where
        R: BoundedReader,
    {
        let mut value = 0;
        for offset in (0..32).step_by(7) {
            let curr: u32 = u8::from_reader(reader)?.into();
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
    }
}

#[cfg(feature = "async")]
impl AsyncFromReader for VarInt {
    async fn async_from_reader<R>(reader: &mut R) -> Result<Self, ReadError<R::Error>>
    where
        R: AsyncBoundedReader,
    {
        let mut value = 0;
        for offset in (0..32).step_by(7) {
            let curr: u32 = u8::async_from_reader(reader).await?.into();
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
    }
}

impl Serializable for VarInt {
    #[inline]
    fn size(&self) -> usize {
        let absolute = self.0 as u32;
        let chunks_of_seven_bits = absolute.checked_ilog2().unwrap_or(0) / 7 + 1;
        chunks_of_seven_bits as usize
    }
}

impl ToWriter for VarInt {
    fn to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
    where
        W: Writer,
    {
        let mut buf = [0u8; 5];
        for (index, byte) in buf.iter_mut().enumerate() {
            let remaining = (self.0 as u32) >> (index * 7);
            if (remaining & !SEGMENT_MASK) == 0 {
                *byte = remaining as u8;
                writer
                    .write(&buf[..=index])
                    .map_err(WriteError::StreamError)?;
                return Ok(());
            }
            let masked = remaining & SEGMENT_MASK;
            *byte = (masked as u8) | CONTINUE_MASK_U8;
        }

        // This should not be possible to reach
        Err(WriteError::MalformedVarInt)
    }
}
