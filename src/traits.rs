use crate::{
    error::{ReadError, WriteError},
    protocol::Handshake,
};

pub trait Reader {
    type Error;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}

pub trait BoundedReader: Reader {
    fn remaining(&self) -> usize;

    fn discard(&mut self, amount: usize) -> Result<(), Self::Error>;
}

pub trait BoundableDecompressableReader: Reader {
    type BoundedReader<'a>: BoundedReader<Error = Self::Error>
        + DecompressableReader<Error = Self::Error>
    where
        Self: 'a;
    fn with_bound(&mut self, bound: usize) -> Self::BoundedReader<'_>;
}

pub trait DecompressableReader: Reader {
    type DecompressReader<'a>: BoundableReader<Error = Self::Error>
    where
        Self: 'a;
    fn with_decompression(&mut self) -> Self::DecompressReader<'_>;
}

pub trait BoundableReader: Reader {
    type BoundedReader<'a>: BoundedReader<Error = Self::Error>
    where
        Self: 'a;
    fn with_bound(&mut self, bound: usize) -> Self::BoundedReader<'_>;
}

pub trait FromReader: Sized {
    fn from_reader<R>(reader: &mut R) -> Result<Self, ReadError<R::Error>>
    where
        R: BoundedReader;
}

pub trait Writer {
    type Error;

    fn write(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    fn flush(&mut self) -> Result<(), Self::Error>;
}

pub trait CompressableWriter: Writer {
    type Level;
    type CompressionWriter: CompressionWriter<Error = Self::Error>;

    fn compression_writer(level: Self::Level) -> Self::CompressionWriter;
}

pub trait CompressionWriter: Writer {
    type Bytes: AsRef<[u8]>;

    fn into_bytes(self) -> Result<Self::Bytes, Self::Error>;
}

pub trait Serializable {
    fn size(&self) -> usize;
}

pub trait ToWriter: Serializable {
    fn to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
    where
        W: Writer;
}

pub trait ProtocolState {
    const STATE_NAME: &'static str;
    type PacketDesignator;

    fn designator_from_id(id: i32) -> Option<Self::PacketDesignator>;
}

pub trait HasNextProtocolState: ProtocolState {
    type NextState: ProtocolState;
}

pub trait HandshakeProtocolState: ProtocolState<PacketDesignator = Handshake> {
    type StatusState: ProtocolState;
    type LoginState: ProtocolState;
}

pub trait ProtocolStateHandler {
    type PacketDesignator;
    type Result;

    fn handle_packet<R>(
        designator: Self::PacketDesignator,
        reader: &mut R,
    ) -> Result<Self::Result, ReadError<R::Error>>
    where
        R: BoundedReader;
}

pub trait StreamProvider {
    type CompressionLevel;

    fn compression_threshold(&self) -> Option<usize>;

    fn compression_level(&self) -> Self::CompressionLevel;
}

pub trait ReadStreamProvider: StreamProvider {
    // Reader type graph:
    // `Base Reader` -> `Bounded` -> `Decompress`(?) -> `Bounded`(?)
    // All readers need the same error type.
    type BaseReader<'a>: BoundableDecompressableReader
    where
        Self: 'a;

    fn read_stream(&mut self) -> Self::BaseReader<'_>;
}

pub trait WriteStreamProvider: StreamProvider {
    type BaseWriter<'a>: CompressableWriter<Level = Self::CompressionLevel>
    where
        Self: 'a;

    fn write_stream(&mut self) -> Self::BaseWriter<'_>;
}

#[allow(async_fn_in_trait)]
#[cfg(feature = "async")]
pub mod asynchronous {
    use crate::{
        error::{ReadError, WriteError},
        traits::{Serializable, StreamProvider},
    };

    pub trait AsyncReader {
        type Error;

        async fn async_read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
    }

    pub trait AsyncBoundedReader: AsyncReader {
        async fn async_remaining(&self) -> usize;

        async fn async_discard(&mut self, amount: usize) -> Result<(), Self::Error>;
    }

    pub trait AsyncBoundableDecompressableReader: AsyncReader {
        type AsyncBoundedReader<'a>: AsyncBoundedReader<Error = Self::Error>
            + AsyncDecompressableReader<Error = Self::Error>
        where
            Self: 'a;

        async fn async_with_bound(&mut self, bound: usize) -> Self::AsyncBoundedReader<'_>;
    }

    pub trait AsyncDecompressableReader: AsyncReader {
        type AsyncDecompressReader<'a>: AsyncBoundableReader<Error = Self::Error>
        where
            Self: 'a;

        async fn async_with_decompression(&mut self) -> Self::AsyncDecompressReader<'_>;
    }

    pub trait AsyncBoundableReader: AsyncReader {
        type AsyncBoundedReader<'a>: AsyncBoundedReader<Error = Self::Error>
        where
            Self: 'a;

        async fn async_with_bound(&mut self, bound: usize) -> Self::AsyncBoundedReader<'_>;
    }

    pub trait AsyncFromReader: Sized {
        async fn async_from_reader<R>(reader: R) -> Result<(R, Self), ReadError<R::Error>>
        where
            R: AsyncBoundedReader;
    }

    pub trait AsyncWriter {
        type Error;

        async fn async_write(&mut self, data: &[u8]) -> Result<(), Self::Error>;

        async fn async_flush(&mut self) -> Result<(), Self::Error>;
    }

    pub trait AsyncCompressableWriter: AsyncWriter {
        type Level;
        type AsyncCompressionWriter: AsyncCompressionWriter<Error = Self::Error>;

        async fn async_compression_writer(level: Self::Level) -> Self::AsyncCompressionWriter;
    }

    pub trait AsyncCompressionWriter: AsyncWriter {
        type Bytes: AsRef<[u8]>;

        async fn async_into_bytes(self) -> Result<Self::Bytes, Self::Error>;
    }

    pub trait AsyncToWriter {
        async fn async_size(&self) -> usize;

        async fn async_to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
        where
            W: AsyncWriter;
    }

    pub trait AsyncProtocolStateHandler {
        type PacketDesignator;
        type Result;

        async fn async_handle_packet<R>(
            designator: Self::PacketDesignator,
            reader: R,
        ) -> Result<(R, Self::Result), ReadError<R::Error>>
        where
            R: AsyncBoundedReader;
    }

    pub trait AsyncWritablePayload: Serializable {
        async fn async_to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
        where
            W: AsyncWriter;
    }

    pub trait AsyncReadStreamProvider: StreamProvider {
        // Reader type graph:
        // `Base Reader` -> `Bounded` -> `Decompress`(?) -> `Bounded`(?)
        // All readers need the same error type.
        type AsyncBaseReader<'a>: AsyncBoundableDecompressableReader
        where
            Self: 'a;

        async fn async_read_stream(&mut self) -> Self::AsyncBaseReader<'_>;
    }

    pub trait AsyncWriteStreamProvider: StreamProvider {
        type AsyncBaseWriter<'a>: AsyncCompressableWriter<Level = Self::CompressionLevel>
        where
            Self: 'a;

        async fn async_write_stream(&mut self) -> Self::AsyncBaseWriter<'_>;
    }
}
