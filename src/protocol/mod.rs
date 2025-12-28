use core::marker::PhantomData;

use crate::{
    error::{ReadError, WriteError},
    primatives::varint::VarInt,
    to_writer_helper,
    traits::{
        BoundableDecompressableReader, BoundableReader, BoundedReader, CompressableWriter,
        CompressionWriter, DecompressableReader, HandshakeProtocolState, HasNextProtocolState,
        Serializable, ToWriter, WriteStreamProvider, Writer,
    },
};

pub mod versions;

pub const MAX_PACKET_SIZE: usize = 0x1FFFFF;

pub struct LegacyPingResponse<S: AsRef<str>> {
    server_version: S,
    motd: S,
    player_count: S,
    max_players: S,
    payload_length: usize,
}

fn utf16_code_units<S: AsRef<str>>(string: S) -> usize {
    let string = string.as_ref();
    string.encode_utf16().count()
}

impl<S: AsRef<str>> LegacyPingResponse<S> {
    pub fn new(server_version: S, motd: S, player_count: S, max_players: S) -> Option<Self> {
        let payload_length = 11
            + (utf16_code_units(&server_version)
                + utf16_code_units(&motd)
                + utf16_code_units(&player_count)
                + utf16_code_units(&max_players));

        if payload_length > i16::MAX as usize {
            None
        } else {
            Some(Self {
                server_version,
                motd,
                player_count,
                max_players,
                payload_length,
            })
        }
    }
}

impl<S: AsRef<str>> Serializable for LegacyPingResponse<S> {
    fn size(&self) -> usize {
        3 + self.payload_length * 2
    }
}

macro_rules! write_legacy_string {
    ($string:expr) => {
        for codeunit in $string.encode_utf16() {
            write!(u16, &codeunit);
        }
        write!(u16, &0);
    };
}

to_writer_helper!(LegacyPingResponse<S: AsRef<str>>, this {
    write!(u8, &0xFF);
    // SAFETY: This is validated in the constructor
    write!(i16, &(this.payload_length as i16));
    write_legacy_string!("§1");
    write_legacy_string!("127");
    write_legacy_string!(this.server_version.as_ref());
    write_legacy_string!(this.motd.as_ref());
    write_legacy_string!(this.player_count.as_ref());
    write_legacy_string!(this.max_players.as_ref());
    Ok(())
});

pub enum Handshake {
    Standard,
    Legacy,
}

pub struct ProtocolHandler<P, S> {
    provider: P,
    _x: PhantomData<S>,
}

impl<P, S> ProtocolHandler<P, S> {
    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }
}

impl<P, S: HandshakeProtocolState> ProtocolHandler<P, S> {
    pub fn into_status_state(self) -> ProtocolHandler<P, S::StatusState> {
        ProtocolHandler {
            provider: self.provider,
            _x: PhantomData {},
        }
    }

    pub fn into_login_state(self) -> ProtocolHandler<P, S::LoginState> {
        ProtocolHandler {
            provider: self.provider,
            _x: PhantomData {},
        }
    }
}

impl<P, S: HasNextProtocolState> ProtocolHandler<P, S> {
    pub fn into_next_state(self) -> ProtocolHandler<P, S::NextState> {
        ProtocolHandler {
            provider: self.provider,
            _x: PhantomData {},
        }
    }
}

impl<P: WriteStreamProvider, S: HandshakeProtocolState> ProtocolHandler<P, S> {
    pub fn write_legacy_ping_response<String>(
        &mut self,
        response: &LegacyPingResponse<String>,
    ) -> Result<(), WriteError<<P::BaseWriter<'_> as Writer>::Error>>
    where
        String: AsRef<str>,
    {
        let mut writer = self.provider.write_stream();
        response.to_writer(&mut writer)
    }
}

#[cfg(feature = "async")]
impl<P: crate::traits::asynchronous::AsyncWriteStreamProvider, S: HandshakeProtocolState>
    ProtocolHandler<P, S>
{
    pub async fn async_write_legacy_ping_response<String>(
        &mut self,
        response: &LegacyPingResponse<String>,
    ) -> Result<
        (),
        WriteError<<P::AsyncBaseWriter<'_> as crate::traits::asynchronous::AsyncWriter>::Error>,
    >
    where
        String: AsRef<str>,
    {
        use crate::traits::asynchronous::AsyncToWriter;
        let mut writer = self.provider.async_write_stream();
        response.async_to_writer(&mut writer).await
    }
}

macro_rules! read_handshake_helper {
    ({$($func:tt)+}) => {
        impl<P: $crate::traits::ReadStreamProvider, S: $crate::traits::HandshakeProtocolState> ProtocolHandler<P, S> {
            pub fn read_handshake<H>(
                &mut self,
            ) -> Result<H::Result, ReadError<<P::BaseReader<'_> as $crate::traits::Reader>::Error>>
            where
                H: $crate::traits::ProtocolStateHandler<PacketDesignator = S::PacketDesignator>,
            {
                macro_rules! read_stream {
                    () => (self.provider.read_stream())
                }

                macro_rules! with_bound {
                    ($bound:expr, $r_in: ident => $r_out:ident $bound_func:tt) => {{
                        let mut $r_out = $r_in.with_bound($bound);
                        $bound_func
                    }};
                }

                macro_rules! handle_packet {
                    ($designator:expr, $reader:ident) => (H::handle_packet($designator, &mut $reader))
                }

                macro_rules! read {
                    ($type:ty, $reader:ident) => (<$type as $crate::traits::FromReader>::from_reader(&mut $reader)?)
                }

                macro_rules! discard_remaining {
                    ($reader:ident) => {{
                        let remaining = $reader.remaining();
                        $reader.discard(remaining).map_err(ReadError::StreamError)?;
                    }}
                }

                $($func)+
            }
        }

        #[cfg(feature = "async")]
        impl<P: $crate::traits::asynchronous::AsyncReadStreamProvider, S: $crate::traits::HandshakeProtocolState> ProtocolHandler<P, S> {
            pub async fn async_read_handshake<H>(
                &mut self,
            ) -> Result<H::Result, ReadError<<P::AsyncBaseReader<'_> as $crate::traits::asynchronous::AsyncReader>::Error>>
            where
                H: $crate::traits::asynchronous::AsyncProtocolStateHandler<PacketDesignator = S::PacketDesignator>,
            {
                macro_rules! read_stream {
                    () => (self.provider.async_read_stream())
                }

                macro_rules! with_bound {
                    ($bound:expr, $r_in: ident => $r_out:ident $bound_func:tt) => {
                    {
                        #[allow(unused)]
                        use $crate::traits::asynchronous::{AsyncBoundableReader, AsyncBoundableDecompressableReader, AsyncWrappedReader};
                        let mut $r_out = $r_in.with_bound($bound);
                        let result = $bound_func;
                        $r_in = $r_out.into_parent();
                        result
                    }};
                }

                macro_rules! handle_packet {
                    ($designator:expr, $reader:ident) => (H::async_handle_packet($designator, &mut $reader).await)
                }

                macro_rules! read {
                    ($type:ty, $reader:ident) => (<$type as $crate::traits::asynchronous::AsyncFromReader>::async_from_reader(&mut $reader).await?)
                }

                macro_rules! discard_remaining {
                    ($reader:ident) => {{
                        use $crate::traits::asynchronous::AsyncBoundedReader;
                        let remaining = $reader.async_remaining().await;
                        $reader.async_discard(remaining).await.map_err(ReadError::StreamError)?;
                    }}
                }

                $($func)+
            }
        }
    };
}

read_handshake_helper!({
    let mut reader = read_stream!();

    // 3-Byte VarInts are the maximum allowed for packet lengths
    let packet_length: i32 = with_bound!(3, reader => varint_reader {
        read!(VarInt, varint_reader).into()
    });

    if packet_length < 0 {
        return Err(ReadError::NegativeLength {
            name: "packet_length",
        });
    }

    // VarInt interpretation of legacy ping handshake prefix
    if packet_length == 0xFE {
        // Bound the stream to sane default (the 1.7+ maximum packet size)
        let result = with_bound!(MAX_PACKET_SIZE, reader => legacy_reader {
            handle_packet!(Handshake::Legacy, legacy_reader)
            // TODO: Figure out a way to properly bound this so end-users don't need to worry about
            // properly handling the packet, will eventually need to do this for legacy packets
            // anyway
        });
        let _ = reader;
        result
    } else {
        // SAFETY: We validated that `packet_length` >= 0.
        let result = with_bound!(packet_length as usize, reader => packet_reader {
            let packet_id: i32 = read!(VarInt, packet_reader).into();
            if let Some(designator) = S::designator_from_id(packet_id) {
                let result = handle_packet!(designator, packet_reader);
                discard_remaining!(packet_reader);
                result
            } else {
                Err(ReadError::UnknownPacket {
                    state: S::STATE_NAME,
                    id: packet_id,
                })
            }
        });
        let _ = reader;
        result
    }
});

macro_rules! read_packet_helper {
    ({$($func:tt)+}) => {
        impl<P: $crate::traits::ReadStreamProvider, S: $crate::traits::ProtocolState> ProtocolHandler<P, S> {
            pub fn read_packet<H>(
                &mut self,
            ) -> Result<H::Result, ReadError<<P::BaseReader<'_> as $crate::traits::Reader>::Error>>
            where
                H: $crate::traits::ProtocolStateHandler<PacketDesignator = S::PacketDesignator>,
            {
                macro_rules! threshold {
                    () => (self.provider.compression_threshold())
                }

                macro_rules! read_stream {
                    () => (self.provider.read_stream())
                }

                macro_rules! with_bound {
                    ($bound:expr, $r_in: ident => $r_out:ident $bound_func:tt) => {{
                        let mut $r_out = $r_in.with_bound($bound);
                        $bound_func
                    }};
                }

                macro_rules! with_decompression {
                    ($r_in:ident => $r_out:ident $decomp_func:tt) => {{
                        let mut $r_out = $r_in.with_decompression();
                        $decomp_func
                    }};
                }

                macro_rules! handle_packet {
                    ($designator:expr, $reader:ident) => (H::handle_packet($designator, &mut $reader))
                }

                macro_rules! read {
                    ($type:ty, $reader:ident) => (<$type as $crate::traits::FromReader>::from_reader(&mut $reader)?)
                }

                macro_rules! discard_remaining {
                    ($reader:ident) => {{
                        let remaining = $reader.remaining();
                        $reader.discard(remaining).map_err(ReadError::StreamError)?;
                    }};
                }

                $($func)+
            }
        }

        #[cfg(feature = "async")]
        impl<P: $crate::traits::asynchronous::AsyncReadStreamProvider, S: $crate::traits::ProtocolState> ProtocolHandler<P, S> {
            pub async fn async_read_packet<H>(
                &mut self,
            ) -> Result<H::Result, ReadError<<P::AsyncBaseReader<'_> as $crate::traits::asynchronous::AsyncReader>::Error>>
            where
                H: $crate::traits::asynchronous::AsyncProtocolStateHandler<PacketDesignator = S::PacketDesignator>,
            {
                macro_rules! threshold {
                    () => (self.provider.compression_threshold())
                }

                macro_rules! read_stream {
                    () => (self.provider.async_read_stream())
                }

                macro_rules! with_bound {
                    ($bound:expr, $r_in: ident => $r_out:ident $bound_func:tt) => {
                    {
                        #[allow(unused)]
                        use $crate::traits::asynchronous::{AsyncBoundableReader, AsyncBoundableDecompressableReader, AsyncWrappedReader};
                        let mut $r_out = $r_in.with_bound($bound);
                        let result = $bound_func;
                        $r_in = $r_out.into_parent();
                        result
                    }};
                }

                macro_rules! with_decompression {
                    ($r_in: ident => $r_out: ident $decomp_func:tt) => {{
                        #[allow(unused)]
                        use $crate::traits::asynchronous::{AsyncDecompressableReader, AsyncBoundableDecompressableReader, AsyncWrappedReader};
                        let mut $r_out = $r_in.with_decompression();
                        let result = $decomp_func;
                        $r_in = $r_out.into_parent();
                        result
                    }};
                }

                macro_rules! handle_packet {
                    ($designator:expr, $reader:ident) => (H::async_handle_packet($designator, &mut $reader).await)
                }

                macro_rules! read {
                    ($type:ty, $reader:ident) => (<$type as $crate::traits::asynchronous::AsyncFromReader>::async_from_reader(&mut $reader).await?)
                }

                macro_rules! discard_remaining {
                    ($reader:ident) => {{
                        use $crate::traits::asynchronous::AsyncBoundedReader;
                        let remaining = $reader.async_remaining().await;
                        $reader.async_discard(remaining).await.map_err(ReadError::StreamError)?;
                    }}
                }

                $($func)+
            }
        }
    };
}

read_packet_helper!({
    let compression_threshold = threshold!();
    let mut reader = read_stream!();

    // 3-Byte VarInts are the maximum allowed for packet lengths
    let packet_length: i32 = with_bound!(3, reader => varint_reader {
        read!(VarInt, varint_reader).into()
    });

    if packet_length < 0 {
        return Err(ReadError::NegativeLength {
            name: "packet_length",
        });
    }

    macro_rules! handle_helper {
        ($stream:ident) => {{
            let packet_id: i32 = read!(VarInt, $stream).into();
            if let Some(designator) = S::designator_from_id(packet_id) {
                let result = handle_packet!(designator, $stream);
                discard_remaining!($stream);
                result
            } else {
                Err(ReadError::UnknownPacket {
                    state: S::STATE_NAME,
                    id: packet_id,
                })
            }
        }};
    }

    // SAFETY: We validated that `packet_length` >= 0.
    let result = with_bound!(packet_length as usize, reader => packet_reader {
        match compression_threshold {
            Some(_) => {
                let data_length: i32 = read!(VarInt, packet_reader).into();
                if data_length < 0 {
                    return Err(ReadError::NegativeLength {
                        name: "uncompressed_size",
                    });
                }

                if data_length == 0 {
                    // Length of 0 means an uncompressed packet
                    handle_helper!(packet_reader)
                } else {
                    with_decompression!(packet_reader => d_r {
                        // SAFETY: We validated that `data_length` >= 0.
                        with_bound!(data_length as usize, d_r => decompression_reader {
                            handle_helper!(decompression_reader)
                        })
                    })
                }
            }
            None => handle_helper!(packet_reader),
        }
    });
    let _ = reader;
    result
});

macro_rules! write_packet_internal_helper {
    (($id:ident, $packet:ident: $packet_type:ident) {$($func:tt)+}) => {
        impl<P: $crate::traits::WriteStreamProvider, S: $crate::traits::ProtocolState>
            ProtocolHandler<P, S>
        {
            #[allow(unused)]
            fn write_packet_internal<PACKET>(
                &mut self,
                id: i32,
                packet: &$packet_type,
            ) -> Result<(), WriteError<<P::BaseWriter<'_> as $crate::traits::Writer>::Error>>
            where
                $packet_type: $crate::traits::ToWriter,
            {
                macro_rules! threshold {
                    () => (self.provider.compression_threshold())
                }

                macro_rules! level {
                    () => (self.provider.compression_level())
                }

                macro_rules! writer {
                    () => (self.provider.write_stream())
                }

                macro_rules! compression_writer {
                    ($level:expr) => {
                        <P::BaseWriter<'_> as CompressableWriter>::compression_writer(
                            $level,
                        )
                    }
                }

                macro_rules! write {
                    ($type:ty, $value:ident=> $writer:ident) => (<$type as $crate::traits::ToWriter>::to_writer(&$value, &mut $writer)?)
                }

                macro_rules! write_bytes {
                    ($bytes:expr => $writer:ident) => ($writer.write($bytes).map_err(WriteError::StreamError)?)
                }

                macro_rules! flush {
                    ($writer:ident) => ($writer.flush().map_err(WriteError::StreamError)?)
                }

                macro_rules! compressor_to_bytes {
                    ($compressor:ident) => {
                        $compressor
                            .into_bytes()
                            .map_err(WriteError::StreamError)?
                    }
                }

                let $id = id;
                let $packet = packet;
                $($func)+
            }
        }

        #[cfg(feature = "async")]
        impl<P: $crate::traits::asynchronous::AsyncWriteStreamProvider, S: $crate::traits::ProtocolState>
            ProtocolHandler<P, S>
        {
            #[allow(unused)]
            async fn async_write_packet_internal<PACKET>(
                &mut self,
                id: i32,
                packet: &$packet_type,
            ) -> Result<(), WriteError<<P::AsyncBaseWriter<'_> as $crate::traits::asynchronous::AsyncWriter>::Error>>
            where
                $packet_type: $crate::traits::asynchronous::AsyncToWriter,
            {
                macro_rules! threshold {
                    () => (self.provider.compression_threshold())
                }

                macro_rules! level {
                    () => (self.provider.compression_level())
                }

                macro_rules! writer {
                    () => (self.provider.async_write_stream())
                }

                macro_rules! compression_writer {
                    ($level:expr) => {
                        <P::AsyncBaseWriter<'_> as $crate::traits::asynchronous::AsyncCompressableWriter>::async_compression_writer(
                            $level,
                        )
                    }
                }

                macro_rules! write {
                    ($type:ty, $value:ident=> $writer:ident) => (<$type as $crate::traits::asynchronous::AsyncToWriter>::async_to_writer(&$value, &mut $writer).await?)
                }

                macro_rules! write_bytes {
                    ($bytes:expr => $writer:ident) => {{
                        use $crate::traits::asynchronous::AsyncWriter;
                        $writer.async_write($bytes).await.map_err(WriteError::StreamError)?
                    }}
                }

                macro_rules! flush {
                    ($writer:ident) => {{
                        use $crate::traits::asynchronous::AsyncWriter;
                        $writer.async_flush().await.map_err(WriteError::StreamError)?
                    }}
                }

                macro_rules! compressor_to_bytes {
                    ($compressor:ident) => {{
                        use $crate::traits::asynchronous::AsyncCompressionWriter;
                        $compressor
                            .async_into_bytes().await
                            .map_err(WriteError::StreamError)?
                    }}
                }

                let $id = id;
                let $packet = packet;
                $($func)+
            }
        }
    };
}

write_packet_internal_helper!((id, packet: PACKET) {
    let compression_threshold = threshold!();
    let compression_level = level!();
    let mut writer = writer!();

    let id_varint = VarInt::from(id);
    let id_size = id_varint.size();
    let packet_size = packet.size();
    let total_size = id_size + packet_size;

    match compression_threshold {
        Some(threshold) => {
            if total_size < threshold {
                let total_size = total_size + 1;
                if total_size > MAX_PACKET_SIZE {
                    return Err(WriteError::OverSized {
                        name: "compression_below_size",
                        maximum: MAX_PACKET_SIZE,
                        was: total_size,
                    });
                }

                // SAFETY: `MAX_PACKET_SIZE` is less than `i32::MAX`.
                let total_varint = VarInt::from(total_size as i32);
                write!(VarInt, total_varint => writer);
                // Uncompressed size of 0 denotes no compression.
                let zero = VarInt::from(0);
                write!(VarInt, zero => writer);
                write!(VarInt, id_varint => writer);
                write!(PACKET, packet => writer);
            } else {
                let mut compression_writer = compression_writer!(compression_level);
                write!(VarInt, id_varint => compression_writer);
                write!(PACKET, packet => compression_writer);
                flush!(compression_writer);

                let compressed_data = compressor_to_bytes!(compression_writer);
                let compressed_slice = compressed_data.as_ref();

                let Ok(total_size): Result<i32, _> = total_size.try_into() else {
                    return Err(WriteError::OverSized {
                        name: "uncompressed_varint",
                        maximum: i32::MAX as usize,
                        was: total_size,
                    });
                };

                let uncompressed_varint = VarInt::from(total_size);
                let total_size = uncompressed_varint.size() + compressed_slice.len();

                if total_size > MAX_PACKET_SIZE {
                    return Err(WriteError::OverSized {
                        name: "no_compression_size",
                        maximum: MAX_PACKET_SIZE,
                        was: total_size,
                    });
                }

                // SAFETY: `MAX_PACKET_SIZE` is less than `i32::MAX`.
                let total_varint = VarInt::from(total_size as i32);
                write!(VarInt, total_varint => writer);
                write!(VarInt, uncompressed_varint => writer);
                write_bytes!(compressed_slice => writer);
            }
        }
        None => {
            if total_size > MAX_PACKET_SIZE {
                return Err(WriteError::OverSized {
                    name: "no_compression_size",
                    maximum: MAX_PACKET_SIZE,
                    was: total_size,
                });
            }

            // SAFETY: `MAX_PACKET_SIZE` is less than `i32::MAX`.
            let total_varint = VarInt::from(total_size as i32);
            write!(VarInt, total_varint => writer);
            write!(VarInt, id_varint => writer);
            write!(PACKET, packet => writer);
        }
    }

    flush!(writer);
    Ok(())
});
