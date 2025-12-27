use core::marker::PhantomData;

use crate::{
    error::{ReadError, WriteError},
    primatives::varint::VarInt,
    traits::{
        BoundableDecompressableReader, BoundableReader, BoundedReader, CompressableWriter,
        CompressionWriter, DecompressableReader, FromReader, HandshakeProtocolState,
        HasNextProtocolState, ProtocolState, ProtocolStateHandler, ReadStreamProvider, Reader,
        Serializable, ToWriter, WriteStreamProvider, Writer,
    },
};

pub mod versions;

pub const MAX_PACKET_SIZE: usize = 0x1FFFFF;

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

impl<P: ReadStreamProvider, S: HandshakeProtocolState> ProtocolHandler<P, S> {
    pub fn read_handshake<H>(
        &mut self,
    ) -> Result<H::Result, ReadError<<P::BaseReader<'_> as Reader>::Error>>
    where
        H: ProtocolStateHandler<PacketDesignator = S::PacketDesignator>,
    {
        let mut reader = self.provider.read_stream();
        let packet_length: i32 = {
            // 3-Byte VarInts are the maximum allowed for packet lengths
            let mut reader = reader.with_bound(3);
            VarInt::from_reader(&mut reader)?.into()
        };

        if packet_length < 0 {
            return Err(ReadError::NegativeLength {
                name: "packet_length",
            });
        }

        if packet_length == 0xFE {
            // VarInt interpretation of legacy ping handshake prefix

            // Bound the stream to sane default (the 1.7+ maximum packet size)
            let mut reader = reader.with_bound(MAX_PACKET_SIZE);
            H::handle_packet(Handshake::Legacy, &mut reader)
            // TODO: Figure out a way to properly bound this so end-users don't need to worry about
            // properly handling the packet, will eventually need to do this for legacy packets
            // anyway
        } else {
            // SAFETY: We validated that `packet_length` >= 0.
            let mut reader = reader.with_bound(packet_length as usize);
            let packet_id: i32 = VarInt::from_reader(&mut reader)?.into();
            if let Some(designator) = S::designator_from_id(packet_id) {
                let result = H::handle_packet(designator, &mut reader);
                reader
                    .discard(reader.remaining())
                    .map_err(ReadError::StreamError)?;
                result
            } else {
                Err(ReadError::UnknownPacket {
                    state: S::STATE_NAME,
                    id: packet_id,
                })
            }
        }
    }
}

impl<P: ReadStreamProvider, S: ProtocolState> ProtocolHandler<P, S> {
    pub fn read_packet<H>(
        &mut self,
    ) -> Result<H::Result, ReadError<<P::BaseReader<'_> as Reader>::Error>>
    where
        H: ProtocolStateHandler<PacketDesignator = S::PacketDesignator>,
    {
        let compression_threshold = self.provider.compression_threshold();
        let mut reader = self.provider.read_stream();
        let packet_length: i32 = {
            // 3-Byte VarInts are the maximum allowed for packet lengths
            let mut reader = reader.with_bound(3);
            VarInt::from_reader(&mut reader)?.into()
        };

        if packet_length < 0 {
            return Err(ReadError::NegativeLength {
                name: "packet_length",
            });
        }

        // SAFETY: We validated that `packet_length` >= 0.
        let mut reader = reader.with_bound(packet_length as usize);

        macro_rules! handle_helper {
            ($stream:expr) => {{
                let packet_id: i32 = VarInt::from_reader(&mut $stream)?.into();
                if let Some(designator) = S::designator_from_id(packet_id) {
                    let result = H::handle_packet(designator, &mut $stream);
                    $stream
                        .discard($stream.remaining())
                        .map_err(ReadError::StreamError)?;
                    result
                } else {
                    Err(ReadError::UnknownPacket {
                        state: S::STATE_NAME,
                        id: packet_id,
                    })
                }
            }};
        }

        match compression_threshold {
            Some(_) => {
                let data_length: i32 = VarInt::from_reader(&mut reader)?.into();
                if data_length < 0 {
                    return Err(ReadError::NegativeLength {
                        name: "uncompressed_size",
                    });
                }

                if data_length == 0 {
                    // Length of 0 means an uncompressed packet
                    handle_helper!(reader)
                } else {
                    let mut reader = reader.with_decompression();
                    // SAFETY: We validated that `data_length` >= 0.
                    let mut reader = reader.with_bound(data_length as usize);
                    handle_helper!(reader)
                }
            }
            None => handle_helper!(reader),
        }
    }
}

impl<P: WriteStreamProvider, S: ProtocolState> ProtocolHandler<P, S> {
    fn write_packet_internal<PACKET>(
        &mut self,
        id: i32,
        packet: &PACKET,
    ) -> Result<(), WriteError<<P::BaseWriter<'_> as Writer>::Error>>
    where
        PACKET: ToWriter,
    {
        let compression_threshold = self.provider.compression_threshold();
        let compression_level = self.provider.compression_level();
        let mut writer = self.provider.write_stream();

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
                    total_varint.to_writer(&mut writer)?;
                    // Uncompressed size of 0 denotes no compression.
                    VarInt::from(0).to_writer(&mut writer)?;
                    id_varint.to_writer(&mut writer)?;
                    packet.to_writer(&mut writer)?;
                } else {
                    let mut compression_writer =
                        <P::BaseWriter<'_> as CompressableWriter>::compression_writer(
                            compression_level,
                        );
                    id_varint.to_writer(&mut compression_writer)?;
                    packet.to_writer(&mut compression_writer)?;
                    compression_writer
                        .flush()
                        .map_err(WriteError::StreamError)?;
                    let compressed_data = compression_writer
                        .into_bytes()
                        .map_err(WriteError::StreamError)?;
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
                    total_varint.to_writer(&mut writer)?;
                    uncompressed_varint.to_writer(&mut writer)?;
                    writer
                        .write(compressed_slice)
                        .map_err(WriteError::StreamError)?;
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
                total_varint.to_writer(&mut writer)?;
                id_varint.to_writer(&mut writer)?;
                packet.to_writer(&mut writer)?;
            }
        }

        writer.flush().map_err(WriteError::StreamError)?;
        Ok(())
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use crate::{
        error::ReadError,
        primatives::varint::VarInt,
        protocol::{Handshake, MAX_PACKET_SIZE, ProtocolHandler},
        traits::{
            HandshakeProtocolState,
            asynchronous::{
                AsyncBoundableDecompressableReader, AsyncBoundedReader, AsyncFromReader,
                AsyncProtocolStateHandler, AsyncReadStreamProvider, AsyncReader,
                AsyncWrappedReader,
            },
        },
    };

    impl<P: AsyncReadStreamProvider, S: HandshakeProtocolState> ProtocolHandler<P, S> {
        pub async fn async_read_handshake<H>(
            &mut self,
        ) -> Result<H::Result, ReadError<<P::AsyncBaseReader<'_> as AsyncReader>::Error>>
        where
            H: AsyncProtocolStateHandler<PacketDesignator = S::PacketDesignator>,
        {
            let mut reader = self.provider.async_read_stream().await;
            let packet_length: i32 = {
                // 3-Byte VarInts are the maximum allowed for packet lengths
                let mut local_reader = reader.async_with_bound(3).await;
                let result = VarInt::async_from_reader(&mut local_reader).await?.into();
                reader = local_reader.into_parent();
                result
            };

            if packet_length < 0 {
                return Err(ReadError::NegativeLength {
                    name: "packet_length",
                });
            }

            if packet_length == 0xFE {
                // VarInt interpretation of legacy ping handshake prefix

                // Bound the stream to sane default (the 1.7+ maximum packet size)
                let mut local_reader = reader.async_with_bound(MAX_PACKET_SIZE).await;
                H::async_handle_packet(Handshake::Legacy, &mut local_reader).await
                // TODO: Figure out a way to properly bound this so end-users don't need to worry about
                // properly handling the packet, will eventually need to do this for legacy packets
                // anyway
            } else {
                // SAFETY: We validated that `packet_length` >= 0.
                let mut reader = reader.async_with_bound(packet_length as usize).await;
                let packet_id: i32 = VarInt::async_from_reader(&mut reader).await?.into();
                if let Some(designator) = S::designator_from_id(packet_id) {
                    let result = H::async_handle_packet(designator, &mut reader).await?;
                    reader
                        .async_discard(reader.async_remaining().await)
                        .await
                        .map_err(ReadError::StreamError)?;
                    Ok(result)
                } else {
                    Err(ReadError::UnknownPacket {
                        state: S::STATE_NAME,
                        id: packet_id,
                    })
                }
            }
        }
    }
}
