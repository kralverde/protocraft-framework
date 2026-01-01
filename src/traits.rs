use crate::{
    error::{ReadError, WriteError},
    protocol::Handshake,
};

pub trait SetBlocking {
    /// Makes the underlying reader blocking or non-blocking. Only used for
    /// `Reader::try_read_byte`.
    fn set_blocking(&mut self, _blocking: bool) {}
}

/// A trait that describes how bytes are retrieved from a stream. Analogous to `std::io::Read`.
pub trait Reader: SetBlocking {
    /// Returned when `Self::read_exact` cannot fill the buffer `buf` completely.
    type Error;

    /// Fills the buffer `buf` completely, returning an error if it cannot be done.
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Attempts to read a byte from the stream *without blocking*. Returns `Some(u8)` if a byte could be read, `None`
    /// if the stream would block, or `Err` for any other errors. Only used during the handshake
    /// state to determine what version of handshake the client is using.
    fn try_read_byte(&mut self) -> Result<Option<u8>, Self::Error>;

    /// Discards exactly `amount` bytes from the stream, returning an error if it cannot be done.
    fn discard(&mut self, amount: usize) -> Result<(), Self::Error>;
}

/// An extension of `Reader`. This trait is limited in the number of bytes that it can read.
/// Analogous to `std::io::Take`.
pub trait BoundedReader: Reader {
    /// The number of bytes that can be read from this `Reader`. If the result of this function is
    /// less than the size of the buffer passed into `Self::read_exact`, an error will be returned
    /// from `Self::read_exact`.
    fn remaining(&self) -> usize;
}

/// A `Reader` who's `BoundedReader` is also a `DecompressableReader`. See `BoundableReader`
/// and `DecompressableReader` for more information.
pub trait BoundableDecompressableReader: Reader {
    type BoundedReader<'a>: BoundedReader<Error = Self::Error>
        + DecompressableReader<Error = Self::Error>
    where
        Self: 'a;
    fn with_bound(&mut self, bound: usize) -> Self::BoundedReader<'_>;
}

/// A `Reader` that can be converted into a `Self::DecompressReader`. This `Reader` takes the
/// underlying byte stream and performs ZLib decompression, returning the decompressed bytes as a
/// stream.
pub trait DecompressableReader: Reader {
    type DecompressReader<'a>: BoundableReader<Error = Self::Error>
    where
        Self: 'a;
    fn with_decompression(&mut self) -> Self::DecompressReader<'_>;
}

/// A `Reader` that can be bound to read no more than `bound` bytes. Analogous to
/// `std::io::Read::take`.
pub trait BoundableReader: Reader {
    type BoundedReader<'a>: BoundedReader<Error = Self::Error>
    where
        Self: 'a;
    fn with_bound(&mut self, bound: usize) -> Self::BoundedReader<'_>;
}

/// A trait defining how a type is constructed from a `BoundedReader`.
pub trait FromReader: Sized {
    fn from_reader<R>(reader: &mut R) -> Result<Self, ReadError<R::Error>>
    where
        R: Reader;
}

/// A trait that describes how bytes are written to a stream. Analogous to `std::io::Write`.
pub trait Writer {
    /// Returned when `Self::write` cannot write the data completely to the stream.
    type Error;

    /// Completely writes `data` to the stream, returning an error if it cannot be done.
    fn write(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Flushes the stream, ensuring the bytes are actually written. Analagous to
    /// `std::io::Write::flush`.
    fn flush(&mut self) -> Result<(), Self::Error>;
}

/// A `Writer` that receives the exact same calls to `Self::write` prior to a `CompressionWriter`.
/// `Self::finish` will be called and its returned `Self::Payload` will be used to initialize
/// a `CompressionWriter`. If a `no-alloc` environment is used, this can be useful to compress the
/// data into a sink to calculate the compressed size in order to serialize the compressed length
/// before actually serializing the compressed data.
pub trait PreCompressionWriter: Writer {
    type Payload;

    /// Returns the length of the compressed data and a payload to initialize a
    /// `CompressionWriter`.
    fn finish(self) -> Result<(usize, Self::Payload), Self::Error>;
}

/// A `Writer` that performs ZLib compression on the data passed into `Self::Write` before
/// serializing to the stream.
pub trait CompressionWriter: Writer {
    type Payload;

    /// A payload received from the preceeding `PreCompressionWriter`.
    fn initialize(&mut self, payload: Self::Payload) -> Result<(), Self::Error>;
}

/// A `Writer` that can be converted into a `CompressionWriter`.
pub trait CompressableWriter: Writer {
    /// The level of compression to use.
    type Level;

    /// A type used to communicate between the `PreCompressionWriter` and the `CompressionWriter`.
    type Payload;

    type PreCompressionWriter: PreCompressionWriter<Error = Self::Error, Payload = Self::Payload>;

    type CompressionWriter<'a>: CompressionWriter<Error = Self::Error, Payload = Self::Payload>
    where
        Self: 'a;

    /// A `PreCompressionWriter` is used to determine the size of the compressed data that is
    /// compressed with `CompressionWriter`. It should make no writes to the underlying `Writer`.
    fn pre_compression_writer(level: &Self::Level) -> Self::PreCompressionWriter;

    /// A `CompressionWriter` performs ZLib compression on input bytes and writes the compressed
    /// bytes to the underlying writer.
    fn with_compression(&mut self, level: &Self::Level) -> Self::CompressionWriter<'_>;
}

pub trait Serializable {
    /// The number of bytes that represent this type when serialized.
    fn size(&self) -> usize;
}

pub trait ToWriter {
    fn to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
    where
        W: Writer;
}

/// A specific Client or Server state for a certain protocol version.
pub trait ProtocolState {
    const STATE_NAME: &'static str;
    /// A type representing the packets avaliable in this state.
    type PacketDesignator;

    /// If the `id` is known for this state, returns `Some(Self::PacketDesignator)` for the `id`.
    /// Otherwise returns `None`.
    fn designator_from_id(id: i32) -> Option<Self::PacketDesignator>;
}

/// A `ProtocolState` with a next state.
pub trait HasNextProtocolState: ProtocolState {
    type NextState: ProtocolState;
}

/// The starting protocol state since Minecraft version 1.7
pub trait HandshakeProtocolState: ProtocolState<PacketDesignator = Handshake> {
    type StatusState: ProtocolState;
    type LoginState: ProtocolState;
}

/// API for handling the data of a packet given the packet type.
pub trait ProtocolStateHandler {
    /// See `ProtocolState::PacketDesignator`.
    type PacketDesignator;
    type Result;

    /// Given a `Self::PacketDesignator` to define what type of packet this is, return
    /// a `Self::Result`. The `reader` can safely be unused; the remaining bytes will automatically
    /// be discarded.
    fn handle_packet<R>(
        designator: Self::PacketDesignator,
        reader: &mut R,
    ) -> Result<Self::Result, ReadError<R::Error>>
    where
        R: BoundedReader;
}

pub trait StreamProvider {
    type CompressionLevel;

    fn set_compression_threshold(&mut self, threshold: Option<usize>);

    fn compression_threshold(&self) -> Option<usize>;

    fn compression_level(&self) -> Self::CompressionLevel;
}

pub trait EncryptableStreamProvider: StreamProvider {
    /// Called once to make the reader and writer decrypt and encrypt respectively.
    /// See `https://minecraft.wiki/w/Java_Edition_protocol/Encryption#Symmetric_Encryption` for
    /// more information.
    fn with_encryption(&mut self, key: [u8; 16]);
}

pub trait ReadStreamProvider: StreamProvider {
    type Error;

    // Reader type graph:
    // `Base Reader` -> `Bounded` -> `Decompress`(?) -> `Bounded`(?)
    // All readers need the same error type.
    type BaseReader<'a>: BoundableDecompressableReader<Error = Self::Error>
    where
        Self: 'a;

    fn read_stream(&mut self) -> Self::BaseReader<'_>;
}

pub trait WriteStreamProvider: StreamProvider {
    type Error;

    type BaseWriter<'a>: CompressableWriter<Level = Self::CompressionLevel, Error = Self::Error>
    where
        Self: 'a;

    fn write_stream(&mut self) -> Self::BaseWriter<'_>;
}

#[allow(async_fn_in_trait)]
#[cfg(feature = "async")]
pub mod asynchronous {

    use crate::{
        error::{ReadError, WriteError},
        traits::StreamProvider,
    };

    /// Async equivalent of `Reader`
    pub trait AsyncReader {
        type Error;

        async fn async_read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;

        async fn async_try_read_byte(&mut self) -> Result<Option<u8>, Self::Error>;

        async fn async_discard(&mut self, amount: usize) -> Result<(), Self::Error>;
    }

    /// Async equivalent of `BoundedReader`
    pub trait AsyncBoundedReader: AsyncReader {
        async fn async_remaining(&self) -> usize;
    }

    /// Async equivalent of `BoundableDecompressableReader`
    pub trait AsyncBoundableDecompressableReader: AsyncReader + Sized {
        type AsyncBoundedReader: AsyncBoundedReader<Error = Self::Error>
            + AsyncDecompressableReader<Error = Self::Error>
            + Into<Self>;

        fn with_bound(self, bound: usize) -> Self::AsyncBoundedReader;
    }

    /// Async equivalent of `DecompressableReader`
    pub trait AsyncDecompressableReader: AsyncReader + Sized {
        type AsyncDecompressReader: AsyncBoundableReader<Error = Self::Error> + Into<Self>;

        fn with_decompression(self) -> Self::AsyncDecompressReader;
    }

    /// Async equivalent of `BoundableReader`
    pub trait AsyncBoundableReader: AsyncReader + Sized {
        type AsyncBoundedReader: AsyncBoundedReader<Error = Self::Error> + Into<Self>;

        fn with_bound(self, bound: usize) -> Self::AsyncBoundedReader;
    }

    /// Async equivalent of `FromReader`
    pub trait AsyncFromReader: Sized {
        async fn async_from_reader<R>(reader: &mut R) -> Result<Self, ReadError<R::Error>>
        where
            R: AsyncReader;
    }

    /// Async equivalent of `Writer`
    pub trait AsyncWriter {
        type Error;

        async fn async_write(&mut self, data: &[u8]) -> Result<(), Self::Error>;

        async fn async_flush(&mut self) -> Result<(), Self::Error>;
    }

    /// Async equivalent of `PreCompressionWriter`
    pub trait AsyncPreCompressionWriter: AsyncWriter {
        type Payload;

        /// Returns the compressed data, the payload, and the parent writer that
        /// created this `AsyncPreCompressionWriter`.
        async fn async_finish(self) -> Result<(usize, Self::Payload), Self::Error>;
    }

    /// Async equivalent of `CompressionWriter`
    pub trait AsyncCompressionWriter: AsyncWriter {
        type Payload;

        async fn async_initialize(&mut self, payload: Self::Payload) -> Result<(), Self::Error>;
    }

    /// Async equivalent of `CompressableWriter`
    pub trait AsyncCompressableWriter: AsyncWriter + Sized {
        type Level;
        type Payload: 'static;

        type AsyncPreCompressionWriter: AsyncPreCompressionWriter<
            Error = Self::Error,
            Payload = Self::Payload,
        >;

        type AsyncCompressionWriter: AsyncCompressionWriter<Error = Self::Error, Payload = Self::Payload>
            + Into<Self>;

        fn async_pre_compression_writer(level: &Self::Level) -> Self::AsyncPreCompressionWriter;

        fn with_async_compression(self, level: &Self::Level) -> Self::AsyncCompressionWriter;
    }

    /// Async equivalent of `ToWriter`
    pub trait AsyncToWriter {
        async fn async_to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
        where
            W: AsyncWriter;
    }

    /// Async equivalent of `ProtocolStateHandler`
    pub trait AsyncProtocolStateHandler {
        type PacketDesignator;
        type Result;

        async fn async_handle_packet<R>(
            designator: Self::PacketDesignator,
            reader: &mut R,
        ) -> Result<Self::Result, ReadError<R::Error>>
        where
            R: AsyncBoundedReader;
    }

    pub trait AsyncReadStreamProvider: StreamProvider {
        type Error;

        // Reader type graph:
        // `Base Reader` -> `Bounded` -> `Decompress`(?) -> `Bounded`(?)
        // All readers need the same error type.
        type AsyncBaseReader<'a>: AsyncBoundableDecompressableReader<Error = Self::Error>
        where
            Self: 'a;

        fn async_read_stream(&mut self) -> Self::AsyncBaseReader<'_>;
    }

    pub trait AsyncWriteStreamProvider: StreamProvider {
        type Error;

        type AsyncBaseWriter<'a>: AsyncCompressableWriter<
            Level = Self::CompressionLevel,
            Error = Self::Error,
        >
        where
            Self: 'a;

        fn async_write_stream(&mut self) -> Self::AsyncBaseWriter<'_>;
    }
}
