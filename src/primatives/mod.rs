pub mod varint;

#[macro_export]
macro_rules! from_reader_helper {
    ($type:ident$(<$($generic:ident$(:$bound:path)?),+>)? {$($func:tt)+}) => {
        impl$(<$($generic$(:$bound)?),+>)? $crate::traits::FromReader for $type$(<$($generic),+>)? {
            fn from_reader<R>(reader: &mut R) -> Result<Self, $crate::error::ReadError<R::Error>>
            where
                R: $crate::traits::BoundedReader,
            {
                #[allow(unused_macros)]
                macro_rules! read_bytes {
                    ($buf:expr) => {
                        reader
                            .read_exact($buf)
                            .map_err($crate::error::ReadError::StreamError)?;
                    }
                }

                #[allow(unused_macros)]
                macro_rules! read {
                    ($read_ty:ty) => {
                        <$read_ty as $crate::traits::FromReader>::from_reader(reader)?
                    }
                }

                $($func)+
            }
        }

        #[cfg(feature = "async")]
        impl$(<$($generic$(:$bound)?),+>)? $crate::traits::asynchronous::AsyncFromReader for $type$(<$($generic),+>)? {
            async fn async_from_reader<R>(
                reader: &mut R,
            ) -> Result<Self, $crate::error::ReadError<R::Error>>
            where
                R: $crate::traits::asynchronous::AsyncBoundedReader,
            {
                #[allow(unused_macros)]
                macro_rules! read_bytes {
                    ($buf:expr) => {
                        reader
                            .async_read_exact($buf).await
                            .map_err($crate::error::ReadError::StreamError)?;
                    }
                }

                #[allow(unused_macros)]
                macro_rules! read {
                    ($read_ty:ty) => {
                        <$read_ty as $crate::traits::asynchronous::AsyncFromReader>::async_from_reader(reader).await?
                    }
                }

                $($func)+
            }
        }
    };
}

#[macro_export]
macro_rules! to_writer_helper {
    ($type:ident$(<$($generic:ident$(:$bound:path)?),+>)?, $this:ident {$($func:tt)+}) => {
        impl$(<$($generic$(:$bound)?),+>)? $crate::traits::ToWriter for $type$(<$($generic),+>)? {
            fn to_writer<W>(
                &self,
                writer: &mut W,
            ) -> Result<(), $crate::error::WriteError<W::Error>>
            where
                W: $crate::traits::Writer,
            {
                #[allow(unused_macros)]
                macro_rules! write_bytes {
                    ($bytes:expr) => {
                        writer
                            .write($bytes)
                            .map_err($crate::error::WriteError::StreamError)?;
                    }
                }

                #[allow(unused_macros)]
                macro_rules! write {
                    ($write_type:ty, $value:expr) => (<$write_type as $crate::traits::ToWriter>::to_writer($value, writer)?)
                }

                let $this = self;
                $($func)+
            }
        }

        #[cfg(feature = "async")]
        impl$(<$($generic$(:$bound)?),+>)? $crate::traits::asynchronous::AsyncToWriter for $type$(<$($generic),+>)? {
            async fn async_to_writer<W>(
                &self,
                writer: &mut W,
            ) -> Result<(), $crate::error::WriteError<W::Error>>
            where
                W: $crate::traits::asynchronous::AsyncWriter,
            {
                #[allow(unused_macros)]
                macro_rules! write_bytes {
                    ($bytes:expr) => {
                        writer
                            .async_write($bytes).await
                            .map_err($crate::error::WriteError::StreamError)?;
                    }
                }

                #[allow(unused_macros)]
                macro_rules! write {
                    ($write_type:ty, $value:expr) => (<$write_type as $crate::traits::asynchronous::AsyncToWriter>::async_to_writer($value, writer).await?)
                }

                let $this = self;
                $($func)+
            }
        }
    };
}

macro_rules! build_primative {
    ($type:ident, $bytes:literal) => {
        $crate::from_reader_helper!($type {
            let mut buf = [0u8; $bytes];
            read_bytes!(&mut buf);
            let result = <$type>::from_be_bytes(buf);
            Ok(result)
        });

        impl $crate::traits::Serializable for $type {
            #[inline]
            fn size(&self) -> usize {
                $bytes
            }
        }

        $crate::to_writer_helper!($type, this {
            let bytes = this.to_be_bytes();
            write_bytes!(&bytes);
            Ok(())
        });
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
