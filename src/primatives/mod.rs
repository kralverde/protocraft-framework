pub mod array;
mod bool;
pub mod handshake_version;
mod option;
mod str;
mod tuple;
pub mod varint;

#[doc(hidden)]
#[macro_export]
macro_rules! _from_reader_helper_internal {
    (sync $type:path: bounds: ($($($bound:tt)+)?), {$($func:tt)+}) => {
        impl$(<$($bound)+>)? $crate::traits::FromReader for $type {
            fn from_reader<R>(reader: &mut R) -> Result<Self, $crate::error::ReadError<R::Error>>
            where
                R: $crate::traits::Reader
            {
                #[allow(unused_macros)]
                macro_rules! read_bytes {
                    ($count:literal) => {{
                        let mut buf = [0u8; $count];
                        reader.read_exact(&mut buf).map_err($crate::error::ReadError::StreamError)?;
                        buf
                    }};
                    ($count:ident) => {{
                        let mut buf = [0u8; $count];
                        reader.read_exact(&mut buf).map_err($crate::error::ReadError::StreamError)?;
                        buf
                    }};
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
    };
    (async $type:path: bounds: ($($($bound:tt)+)?), {$($func:tt)+}) => {
        impl$(<$($bound)+>)? $crate::traits::asynchronous::AsyncFromReader for $type {
            async fn async_from_reader<R>(
                reader: &mut R,
            ) -> Result<Self, $crate::error::ReadError<R::Error>>
            where
                R: $crate::traits::asynchronous::AsyncReader
            {
                #[allow(unused_macros)]
                macro_rules! read_bytes {
                    ($count:literal) => {{
                        let mut buf = [0u8; $count];
                        reader.async_read_exact(&mut buf).await.map_err($crate::error::ReadError::StreamError)?;
                        buf
                    }};
                    ($count:ident) => {{
                        let mut buf = [0u8; $count];
                        reader.async_read_exact(&mut buf).await.map_err($crate::error::ReadError::StreamError)?;
                        buf
                    }};
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
macro_rules! from_reader_helper {
    ($type:path $(where ($($bounds:tt)+))? {$($func:tt)+}) => {
        $crate::_from_reader_helper_internal!(sync $type: bounds: ($($($bounds)+)?), {$($func)+});

        #[cfg(feature = "async")]
        $crate::_from_reader_helper_internal!(async $type: bounds: ($($($bounds)+)?), {$($func)+});
    };
    ($type:path $(where ($($bounds:tt)+))?, wrapped <$($generic:ident),+> {$($func:tt)+}) => {
        $crate::_from_reader_helper_internal!(sync $type: bounds: ($($generic: $crate::traits::FromReader),+ $(,$($bounds)+)?), {$($func)+});

        #[cfg(feature = "async")]
        $crate::_from_reader_helper_internal!(async $type: bounds: ($($generic: $crate::traits::asynchronous::AsyncFromReader),+ $(,$($bounds)+)?), {$($func)+});
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! _to_writer_helper_internal {
    (sync $type:path: bounds: ($($($bound:tt)+)?), $this:ident {$($func:tt)+}) => {
        impl$(<$($bound)+>)? $crate::traits::ToWriter for $type {
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
                    ($write_type:ty, $value:expr) => (<$write_type as $crate::traits::ToWriter>::to_writer(&$value, writer)?)
                }

                let $this = self;
                $($func)+
            }
        }
    };
    (async $type:path: bounds: ($($($bound:tt)+)?), $this:ident {$($func:tt)+}) => {
        impl$(<$($bound)+>)? $crate::traits::asynchronous::AsyncToWriter for $type {
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
                    ($write_type:ty, $value:expr) => (<$write_type as $crate::traits::asynchronous::AsyncToWriter>::async_to_writer(&$value, writer).await?)
                }

                let $this = self;
                $($func)+
            }
        }
    }
}

#[macro_export]
macro_rules! to_writer_helper {
    ($type:path $(where ($($bounds:tt)+))?, ($this:ident){$($func:tt)+}) => {
        $crate::_to_writer_helper_internal!(sync $type: bounds: ($($($bounds)+)?), $this {$($func)*});

        #[cfg(feature = "async")]
        $crate::_to_writer_helper_internal!(async $type: bounds: ($($($bounds)+)?), $this {$($func)*});
    };
    ($type:path $(where ($($bounds:tt)+))?, wrapped <$($generic:ident),+>, ($this:ident){$($func:tt)+}) => {
        $crate::_to_writer_helper_internal!(sync $type: bounds: ($($generic: $crate::traits::ToWriter),+ $(,$($bounds)+)?), $this {$($func)+});

        #[cfg(feature = "async")]
        $crate::_to_writer_helper_internal!(async $type: bounds: ($($generic: $crate::traits::asynchronous::AsyncToWriter),+ $(,$($bounds)+)?), $this {$($func)+});
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

        $crate::to_writer_helper!($type, (this){
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
