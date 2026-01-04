#[cfg(feature = "async")]
use crate::traits::asynchronous::{AsyncFromReader, AsyncReader, AsyncToWriter, AsyncWriter};
use crate::{
    error::{ReadError, WriteError},
    traits::{FromReader, Reader, Serializable, ToWriter, Writer},
};

pub mod handshake_version;
pub mod varint;

#[macro_export]
macro_rules! from_reader_helper {
    ($type:ident$(<$($generic:ident$(:$bound:path)?),+>)? {$($func:tt)+}) => {
        impl$(<$($generic$(:$bound)?),+>)? $crate::traits::FromReader for $type$(<$($generic),+>)? {
            fn from_reader<R>(reader: &mut R) -> Result<Self, $crate::error::ReadError<R::Error>>
            where
                R: $crate::traits::Reader,
            {
                #[allow(unused_macros)]
                macro_rules! read_bytes {
                    ($count:literal) => {{
                        let mut buf = [0u8; $count];
                        reader.read_exact(&mut buf).map_err($crate::error::ReadError::StreamError)?;
                        buf
                    }}
                }

                #[allow(unused_macros)]
                macro_rules! read {
                    ($read_ty:ty) => {
                        <$read_ty as $crate::traits::FromReader>::from_reader(reader)?
                    }
                }

                #[allow(unused_macros)]
                macro_rules! try_read_byte {
                    () => (reader.try_read_byte().map_err($crate::error::ReadError::StreamError)?)
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
                R: $crate::traits::asynchronous::AsyncReader,
            {
                #[allow(unused_macros)]
                macro_rules! read_bytes {
                    ($count:literal) => {{
                        let mut buf = [0u8; $count];
                        reader.async_read_exact(&mut buf).await.map_err($crate::error::ReadError::StreamError)?;
                        buf
                    }}
                }

                #[allow(unused_macros)]
                macro_rules! read {
                    ($read_ty:ty) => {
                        <$read_ty as $crate::traits::asynchronous::AsyncFromReader>::async_from_reader(reader).await?
                    }
                }

                #[allow(unused_macros)]
                macro_rules! try_read_byte {
                    () => (reader.async_try_read_byte().await.map_err($crate::error::ReadError::StreamError)?)
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
            let buf = read_bytes!($bytes);
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

impl Serializable for bool {
    #[inline]
    fn size(&self) -> usize {
        1
    }
}

from_reader_helper!(bool {
    let byte = read!(u8);
    Ok(byte != 0)
});

to_writer_helper!(bool, this {
    let byte = if *this {0x01} else {0x00};
    write!(u8, &byte);
    Ok(())
});

impl<T> Serializable for Option<T>
where
    T: Serializable,
{
    #[inline]
    fn size(&self) -> usize {
        match self {
            Some(val) => 1 + val.size(),
            None => 1,
        }
    }
}

impl<T> FromReader for Option<T>
where
    T: FromReader,
{
    fn from_reader<R>(reader: &mut R) -> Result<Self, ReadError<R::Error>>
    where
        R: Reader,
    {
        Ok(if bool::from_reader(reader)? {
            Some(T::from_reader(reader)?)
        } else {
            None
        })
    }
}

#[cfg(feature = "async")]
impl<T> AsyncFromReader for Option<T>
where
    T: AsyncFromReader,
{
    async fn async_from_reader<R>(reader: &mut R) -> Result<Self, ReadError<R::Error>>
    where
        R: AsyncReader,
    {
        Ok(if bool::async_from_reader(reader).await? {
            Some(T::async_from_reader(reader).await?)
        } else {
            None
        })
    }
}

impl<T> ToWriter for Option<T>
where
    T: ToWriter,
{
    fn to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
    where
        W: Writer,
    {
        match self {
            Some(val) => {
                true.to_writer(writer)?;
                val.to_writer(writer)?;
            }
            None => false.to_writer(writer)?,
        }

        Ok(())
    }
}

#[cfg(feature = "async")]
impl<T> AsyncToWriter for Option<T>
where
    T: AsyncToWriter,
{
    async fn async_to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
    where
        W: AsyncWriter,
    {
        match self {
            Some(val) => {
                true.async_to_writer(writer).await?;
                val.async_to_writer(writer).await?;
            }
            None => false.async_to_writer(writer).await?,
        }

        Ok(())
    }
}
