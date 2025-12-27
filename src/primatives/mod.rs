pub mod varint;

macro_rules! build_primative {
    ($type:ty, $bytes:literal) => {
        impl $crate::traits::FromReader for $type {
            fn from_reader<R>(reader: &mut R) -> Result<Self, $crate::error::ReadError<R::Error>>
            where
                R: $crate::traits::BoundedReader,
            {
                let mut buf = [0u8; $bytes];
                reader
                    .read_exact(&mut buf)
                    .map_err($crate::error::ReadError::StreamError)?;
                let result = <$type>::from_be_bytes(buf);
                Ok(result)
            }
        }

        impl $crate::traits::Serializable for $type {
            #[inline]
            fn size(&self) -> usize {
                $bytes
            }
        }

        impl $crate::traits::ToWriter for $type {
            fn to_writer<W>(
                &self,
                writer: &mut W,
            ) -> Result<(), $crate::error::WriteError<W::Error>>
            where
                W: $crate::traits::Writer,
            {
                let bytes = self.to_be_bytes();
                writer
                    .write(&bytes)
                    .map_err($crate::error::WriteError::StreamError)?;
                Ok(())
            }
        }

        #[cfg(feature = "async")]
        impl $crate::traits::asynchronous::AsyncFromReader for $type {
            async fn async_from_reader<R>(
                reader: &mut R,
            ) -> Result<Self, $crate::error::ReadError<R::Error>>
            where
                R: $crate::traits::asynchronous::AsyncBoundedReader,
            {
                let mut buf = [0u8; $bytes];
                reader
                    .async_read_exact(&mut buf)
                    .await
                    .map_err($crate::error::ReadError::StreamError)?;
                let result = <$type>::from_be_bytes(buf);
                Ok(result)
            }
        }
    };
}

build_primative!(u8, 1);
build_primative!(i8, 1);
build_primative!(u16, 2);
build_primative!(i16, 2);
build_primative!(u32, 4);
build_primative!(i32, 4);
build_primative!(u64, 8);
build_primative!(i64, 8);
build_primative!(u128, 16);
build_primative!(i128, 16);
build_primative!(f32, 4);
build_primative!(f64, 8);
