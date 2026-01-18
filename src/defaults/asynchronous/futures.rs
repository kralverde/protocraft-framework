extern crate std;

use core::{
    pin::Pin,
    task::{Context, Poll},
};

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, inout::InOutBuf};
use futures_io::{AsyncBufRead, AsyncRead, AsyncWrite};
use futures_util::{
    AsyncReadExt, AsyncWriteExt,
    io::{BufReader, Take},
};
use miniz_oxide::{
    DataFormat, MZFlush,
    deflate::{
        core::{CompressorOxide, deflate_flags},
        stream::deflate,
    },
    inflate::stream::{InflateState, MinReset, inflate},
};

use crate::{
    asynchronous::FuturesIo,
    defaults::Compression,
    traits::{
        EncryptableStreamProvider, StreamProvider,
        asynchronous::{
            AsyncBoundableDecompressableReader, AsyncBoundableReader, AsyncBoundedReader,
            AsyncCompressableWriter, AsyncCompressionWriter, AsyncDecompressableReader,
            AsyncPreCompressionWriter, AsyncReadStreamProvider, AsyncWriteStreamProvider,
            AsyncWriter,
        },
    },
};

// TODO: This code can be cleaned up, but it works :p

pub struct FuturesReader<'a, R> {
    state: &'a mut InflateState,
    reader: R,
}

impl<R> AsyncRead for FuturesReader<'_, R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<futures_io::Result<usize>> {
        let reader = &mut self.get_mut().reader;
        let reader = std::pin::pin!(reader);

        reader.poll_read(cx, buf)
    }
}

pub struct AsyncDecompressionReader<'a, R> {
    state: &'a mut InflateState,
    reader: R,
}

impl<R> AsyncRead for AsyncDecompressionReader<'_, R>
where
    R: AsyncBufRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<futures_io::Result<usize>> {
        let this = self.get_mut();
        let reader = &mut this.reader;
        let state = &mut this.state;

        let mut reader = std::pin::pin!(reader);
        let result = reader.as_mut().poll_fill_buf(cx)?;
        let Poll::Ready(internal_buf) = result else {
            return Poll::Pending;
        };

        let result = inflate(state, internal_buf, buf, MZFlush::None);
        let _ = result.status.map_err(|err| {
            futures_io::Error::other(std::format!("Decompression error: {:?}", err))
        })?;
        reader.consume(result.bytes_consumed);

        Poll::Ready(Ok(result.bytes_written))
    }
}

impl<'a, R> AsyncBoundableReader for FuturesIo<AsyncDecompressionReader<'a, R>>
where
    R: AsyncBufRead + Unpin,
{
    type AsyncBoundedReader = FuturesIo<Take<AsyncDecompressionReader<'a, R>>>;

    fn with_bound(self, bound: usize) -> Self::AsyncBoundedReader {
        FuturesIo(self.0.take(bound as u64))
    }
}

impl<R> AsyncBoundedReader for FuturesIo<Take<AsyncDecompressionReader<'_, R>>>
where
    R: AsyncBufRead + Unpin,
{
    async fn async_remaining(&self) -> usize {
        self.0.limit() as usize
    }
}

impl<'a, R> From<FuturesIo<Take<AsyncDecompressionReader<'a, R>>>>
    for FuturesIo<AsyncDecompressionReader<'a, R>>
where
    R: AsyncBufRead + Unpin,
{
    fn from(value: FuturesIo<Take<AsyncDecompressionReader<'a, R>>>) -> Self {
        FuturesIo(value.0.into_inner())
    }
}

pub struct AsyncDecryptionReader<R> {
    decryptor: cfb8::Decryptor<aes::Aes128>,
    reader: R,
}

impl<R> AsyncRead for AsyncDecryptionReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<futures_io::Result<usize>> {
        let reader = &mut self.as_mut().reader;
        let reader = std::pin::pin!(reader);

        let result = reader.poll_read(cx, buf);
        if let Poll::Ready(Ok(count)) = result {
            // We only want to decrypt what was just read
            let io_buf: InOutBuf<u8> = (&mut buf[..count]).into();
            let (chunks, tail) = io_buf.into_chunks();
            // SAFETY: Our chunk size is 1 byte. There will never be a tail.
            assert!(tail.is_empty());
            self.decryptor.decrypt_blocks_inout_mut(chunks);
        }

        result
    }
}

pub enum AsyncBufferedWriterState {
    Fill,
    Write(usize),
}

pub struct AsyncEncryptionWriter<W> {
    encryptor: cfb8::Encryptor<aes::Aes128>,
    writer: W,
    buffer: std::vec::Vec<u8>,
    state: AsyncBufferedWriterState,
}

impl<W> AsyncWrite for AsyncEncryptionWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, futures_io::Error>> {
        let this = self.get_mut();

        loop {
            match &mut this.state {
                AsyncBufferedWriterState::Fill => {
                    let capacity = this.buffer.capacity().saturating_sub(this.buffer.len());
                    if capacity > 0 {
                        let amount_to_write = capacity.min(buf.len());
                        this.buffer.extend_from_slice(&buf[..amount_to_write]);
                        return Poll::Ready(Ok(amount_to_write));
                    }

                    let io_buf: InOutBuf<u8> = (this.buffer.as_mut_slice()).into();
                    let (chunks, tail) = io_buf.into_chunks();
                    // SAFETY: Our chunk size is 1 byte. There will never be a tail.
                    assert!(tail.is_empty());
                    this.encryptor.encrypt_blocks_inout_mut(chunks);
                    this.state = AsyncBufferedWriterState::Write(0);
                }
                AsyncBufferedWriterState::Write(offset) => {
                    let fut = this.writer.write(&this.buffer[*offset..]);
                    let fut = std::pin::pin!(fut);
                    let amount_written = core::task::ready!(fut.poll(cx))?;
                    *offset += amount_written;
                    if *offset == this.buffer.len() {
                        this.buffer.clear();
                        this.state = AsyncBufferedWriterState::Fill;
                    }
                }
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), futures_io::Error>> {
        let this = self.get_mut();

        loop {
            match &mut this.state {
                AsyncBufferedWriterState::Fill => {
                    let io_buf: InOutBuf<u8> = (this.buffer.as_mut_slice()).into();
                    let (chunks, tail) = io_buf.into_chunks();
                    // SAFETY: Our chunk size is 1 byte. There will never be a tail.
                    assert!(tail.is_empty());
                    this.encryptor.encrypt_blocks_inout_mut(chunks);
                    this.state = AsyncBufferedWriterState::Write(0);
                }
                AsyncBufferedWriterState::Write(offset) => {
                    let fut = this.writer.write(&this.buffer[*offset..]);
                    let fut = std::pin::pin!(fut);
                    let amount_written = core::task::ready!(fut.poll(cx))?;
                    *offset += amount_written;
                    if *offset == this.buffer.len() {
                        this.buffer.clear();
                        this.state = AsyncBufferedWriterState::Fill;

                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), futures_io::Error>> {
        let writer = &mut self.get_mut().writer;
        let writer = std::pin::pin!(writer);
        writer.poll_close(cx)
    }
}

pub enum AsyncDefaultReader<R> {
    Standard(R),
    Decrypt(std::boxed::Box<AsyncDecryptionReader<R>>),
    Poisoned,
}

impl<R> AsyncDefaultReader<R> {
    fn with_encryption(&mut self, key: &[u8; 16]) {
        match std::mem::replace(self, Self::Poisoned) {
            Self::Standard(reader) => {
                let decryption_reader = AsyncDecryptionReader {
                    decryptor: cfb8::Decryptor::new(key.into(), key.into()),
                    reader,
                };
                *self = Self::Decrypt(std::boxed::Box::new(decryption_reader));
            }
            Self::Decrypt(_) => panic!("We are already decrypting!"),
            Self::Poisoned => unreachable!(),
        }
    }
}

impl<R> AsyncRead for AsyncDefaultReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<futures_io::Result<usize>> {
        match &mut *self {
            Self::Standard(reader) => {
                let reader = std::pin::pin!(reader);
                reader.poll_read(cx, buf)
            }
            Self::Decrypt(reader) => {
                let reader = std::pin::pin!(reader);
                reader.poll_read(cx, buf)
            }
            Self::Poisoned => unreachable!(),
        }
    }
}

pub struct AsyncBufferedWriter<W> {
    writer: W,
    buffer: std::vec::Vec<u8>,
    state: AsyncBufferedWriterState,
}

impl<W> AsyncWrite for AsyncBufferedWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<futures_io::Result<usize>> {
        let this = self.get_mut();

        loop {
            match &mut this.state {
                AsyncBufferedWriterState::Fill => {
                    let capacity = this.buffer.capacity().saturating_sub(this.buffer.len());
                    if capacity > 0 {
                        let amount_to_write = capacity.min(buf.len());
                        this.buffer.extend_from_slice(&buf[..amount_to_write]);
                        return Poll::Ready(Ok(amount_to_write));
                    }

                    this.state = AsyncBufferedWriterState::Write(0);
                }
                AsyncBufferedWriterState::Write(offset) => {
                    let fut = this.writer.write(&this.buffer[*offset..]);
                    let fut = std::pin::pin!(fut);
                    let amount_written = core::task::ready!(fut.poll(cx))?;
                    *offset += amount_written;
                    if *offset == this.buffer.len() {
                        this.buffer.clear();
                        this.state = AsyncBufferedWriterState::Fill;
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<futures_io::Result<()>> {
        let this = self.get_mut();

        loop {
            match &mut this.state {
                AsyncBufferedWriterState::Fill => {
                    this.state = AsyncBufferedWriterState::Write(0);
                }
                AsyncBufferedWriterState::Write(offset) => {
                    let fut = this.writer.write(&this.buffer[*offset..]);
                    let fut = std::pin::pin!(fut);
                    let amount_written = core::task::ready!(fut.poll(cx))?;
                    *offset += amount_written;
                    if *offset == this.buffer.len() {
                        this.buffer.clear();
                        this.state = AsyncBufferedWriterState::Fill;

                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<futures_io::Result<()>> {
        let writer = &mut self.get_mut().writer;
        let writer = std::pin::pin!(writer);
        writer.poll_close(cx)
    }
}

pub enum AsyncDefaultWriter<W> {
    Standard(std::boxed::Box<AsyncBufferedWriter<W>>),
    Encrypt(std::boxed::Box<AsyncEncryptionWriter<W>>),
    Poisoned,
}

impl<W> AsyncDefaultWriter<W> {
    fn with_encryption(&mut self, key: &[u8; 16]) {
        match std::mem::replace(self, Self::Poisoned) {
            Self::Standard(buf_write) => {
                let writer = buf_write.writer;
                let mut buffer = buf_write.buffer;
                buffer.clear();

                let encryption_writer = AsyncEncryptionWriter {
                    encryptor: cfb8::Encryptor::new(key.into(), key.into()),
                    writer,
                    buffer,
                    state: AsyncBufferedWriterState::Fill,
                };
                *self = Self::Encrypt(std::boxed::Box::new(encryption_writer));
            }
            Self::Encrypt(_) => panic!("We are already encrypting!"),
            Self::Poisoned => unreachable!(),
        }
    }
}

impl<W> AsyncWrite for AsyncDefaultWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, futures_io::Error>> {
        match &mut *self {
            Self::Standard(writer) => {
                let writer = std::pin::pin!(writer);
                writer.poll_write(cx, buf)
            }
            Self::Encrypt(writer) => {
                let writer = std::pin::pin!(writer);
                writer.poll_write(cx, buf)
            }
            Self::Poisoned => {
                unreachable!()
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), futures_io::Error>> {
        match &mut *self {
            Self::Standard(writer) => {
                let writer = std::pin::pin!(writer);
                writer.poll_flush(cx)
            }
            Self::Encrypt(writer) => {
                let writer = std::pin::pin!(writer);
                writer.poll_flush(cx)
            }
            Self::Poisoned => {
                unreachable!()
            }
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), futures_io::Error>> {
        match &mut *self {
            Self::Standard(writer) => {
                let writer = std::pin::pin!(writer);
                writer.poll_close(cx)
            }
            Self::Encrypt(writer) => {
                let writer = std::pin::pin!(writer);
                writer.poll_close(cx)
            }
            Self::Poisoned => {
                unreachable!()
            }
        }
    }
}

impl<'a, R> From<FuturesIo<FuturesReader<'a, Take<R>>>> for FuturesIo<FuturesReader<'a, R>>
where
    R: AsyncRead + Unpin,
{
    fn from(value: FuturesIo<FuturesReader<'a, Take<R>>>) -> Self {
        FuturesIo(FuturesReader {
            state: value.0.state,
            reader: value.0.reader.into_inner(),
        })
    }
}

impl<'a, R> AsyncBoundableDecompressableReader for FuturesIo<FuturesReader<'a, R>>
where
    R: AsyncBufRead + Unpin,
{
    type AsyncBoundedReader = FuturesIo<FuturesReader<'a, Take<R>>>;

    fn with_bound(self, bound: usize) -> Self::AsyncBoundedReader {
        FuturesIo(FuturesReader {
            state: self.0.state,
            reader: self.0.reader.take(bound as u64),
        })
    }
}

impl<'a, R> AsyncBoundableReader for FuturesIo<FuturesReader<'a, R>>
where
    R: AsyncRead + Unpin,
{
    type AsyncBoundedReader = FuturesIo<FuturesReader<'a, Take<R>>>;

    fn with_bound(self, bound: usize) -> Self::AsyncBoundedReader {
        FuturesIo(FuturesReader {
            state: self.0.state,
            reader: self.0.reader.take(bound as u64),
        })
    }
}

impl<R> AsyncBoundedReader for FuturesIo<FuturesReader<'_, Take<R>>>
where
    R: AsyncRead + Unpin,
{
    async fn async_remaining(&self) -> usize {
        self.0.reader.limit() as usize
    }
}

impl<'a, R> AsyncDecompressableReader for FuturesIo<FuturesReader<'a, R>>
where
    R: AsyncBufRead + Unpin,
{
    type AsyncDecompressReader = FuturesIo<AsyncDecompressionReader<'a, R>>;

    fn with_decompression(self) -> Self::AsyncDecompressReader {
        let state = self.0.state;
        state.reset_as(MinReset);
        FuturesIo(AsyncDecompressionReader {
            state,
            reader: self.0.reader,
        })
    }
}

impl<'a, R> From<FuturesIo<AsyncDecompressionReader<'a, R>>> for FuturesIo<FuturesReader<'a, R>> {
    fn from(value: FuturesIo<AsyncDecompressionReader<'a, R>>) -> Self {
        FuturesIo(FuturesReader {
            state: value.0.state,
            reader: value.0.reader,
        })
    }
}

pub struct FuturesWriter<'a, W> {
    state: &'a mut CompressorOxide,
    writer: W,
}

impl<W> AsyncWrite for FuturesWriter<'_, W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, futures_io::Error>> {
        let writer = &mut self.get_mut().writer;
        let writer = std::pin::pin!(writer);
        writer.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), futures_io::Error>> {
        let writer = &mut self.get_mut().writer;
        let writer = std::pin::pin!(writer);
        writer.poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), futures_io::Error>> {
        let writer = &mut self.get_mut().writer;
        let writer = std::pin::pin!(writer);
        writer.poll_close(cx)
    }
}

pub struct AsyncCachedPreCompressionWriter<'a, W> {
    state: &'a mut CompressorOxide,
    buffer: std::vec::Vec<u8>,
    cached_writer: W,
}

impl<W> AsyncWriter for AsyncCachedPreCompressionWriter<'_, W> {
    type Error = futures_io::Error;

    async fn async_write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let mut offset = 0;
        let mut buf = [0u8; 512];
        loop {
            let result = deflate(self.state, &data[offset..], &mut buf, MZFlush::Sync);
            let _ = result.status.map_err(|err| {
                futures_io::Error::other(std::format!("Compression error: {:?}", err))
            })?;

            self.buffer.extend_from_slice(&buf[..result.bytes_written]);
            offset += result.bytes_consumed;
            if offset == data.len() {
                break;
            }
        }
        Ok(())
    }

    async fn async_flush(&mut self) -> Result<(), Self::Error> {
        // Handled in `Self::async_finish`
        Ok(())
    }
}

impl<'a, W> AsyncPreCompressionWriter for AsyncCachedPreCompressionWriter<'a, W> {
    type Payload = std::vec::Vec<u8>;
    type Parent = FuturesIo<FuturesWriter<'a, W>>;

    async fn async_finish(self) -> Result<(usize, Self::Payload, Self::Parent), Self::Error> {
        let buffer = self.buffer;
        Ok((
            buffer.len(),
            buffer,
            FuturesIo(FuturesWriter {
                state: self.state,
                writer: self.cached_writer,
            }),
        ))
    }
}

pub struct AsyncCachedCompressionWriter<W>(W);
impl<W> AsyncWrite for AsyncCachedCompressionWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, futures_io::Error>> {
        // Handled in `AsyncCompressionWriter::async_initialize`
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), futures_io::Error>> {
        let writer = &mut self.get_mut().0;
        let writer = std::pin::pin!(writer);
        writer.poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), futures_io::Error>> {
        let writer = &mut self.get_mut().0;
        let writer = std::pin::pin!(writer);
        writer.poll_close(cx)
    }
}

impl<W> AsyncCompressionWriter for FuturesIo<FuturesWriter<'_, AsyncCachedCompressionWriter<W>>>
where
    W: AsyncWrite + Unpin,
{
    type Payload = std::vec::Vec<u8>;

    async fn async_initialize(&mut self, payload: Self::Payload) -> Result<(), Self::Error> {
        // Explicitly invoke the real writer; AsyncCachedCompressionWriter is a Sink.
        self.0.writer.0.write_all(&payload).await?;
        Ok(())
    }
}

impl<'a, W> From<FuturesIo<FuturesWriter<'a, AsyncCachedCompressionWriter<W>>>>
    for FuturesIo<FuturesWriter<'a, W>>
{
    fn from(value: FuturesIo<FuturesWriter<'a, AsyncCachedCompressionWriter<W>>>) -> Self {
        FuturesIo(FuturesWriter {
            state: value.0.state,
            writer: value.0.writer.0,
        })
    }
}

impl<'a, W> AsyncCompressableWriter for FuturesIo<FuturesWriter<'a, W>>
where
    W: AsyncWrite + Unpin,
{
    type Payload = std::vec::Vec<u8>;
    type Level = Compression;

    type AsyncPreCompressionWriter = AsyncCachedPreCompressionWriter<'a, W>;
    type AsyncCompressionWriter = FuturesIo<FuturesWriter<'a, AsyncCachedCompressionWriter<W>>>;

    fn async_pre_compression_writer(self, _level: &Self::Level) -> Self::AsyncPreCompressionWriter {
        let compressor = self.0.state;
        //compressor.set_compression_level(*level);
        compressor.reset();
        AsyncCachedPreCompressionWriter {
            state: compressor,
            buffer: std::vec::Vec::new(),
            cached_writer: self.0.writer,
        }
    }

    fn with_async_compression(self, _level: &Self::Level) -> Self::AsyncCompressionWriter {
        FuturesIo(FuturesWriter {
            state: self.0.state,
            writer: AsyncCachedCompressionWriter(self.0.writer),
        })
    }
}

/// The default stream provider for FuturesIo.
pub struct AsyncDefaultStreamProvider<R, W> {
    reader: BufReader<AsyncDefaultReader<R>>,
    writer: AsyncDefaultWriter<W>,
    compression_threshold: Option<usize>,
    compression_level: Compression,
    compression_state: std::boxed::Box<CompressorOxide>,
    decompression_state: std::boxed::Box<InflateState>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite> AsyncDefaultStreamProvider<R, W> {
    /// Constructs a new `DefaultStreamProvider`.
    /// `reader`: the stream of incoming data
    /// `writer`: the stream of outgoing data
    /// `compression_level`: see `Compression`
    /// `buffer_size`: how many bytes to buffer. This size is used for both the `reader` and
    /// `writer`, so the total buffer size is `buffer_size * 2`.
    pub fn new(reader: R, writer: W, compression_level: Compression, buffer_size: usize) -> Self {
        let mut compression_state =
            std::boxed::Box::new(CompressorOxide::new(deflate_flags::TDEFL_WRITE_ZLIB_HEADER));
        compression_state.set_compression_level_raw(compression_level.into());

        Self {
            reader: BufReader::with_capacity(buffer_size, AsyncDefaultReader::Standard(reader)),
            writer: AsyncDefaultWriter::Standard(std::boxed::Box::new(AsyncBufferedWriter {
                writer,
                buffer: std::vec::Vec::with_capacity(buffer_size),
                state: AsyncBufferedWriterState::Fill,
            })),
            compression_threshold: None,
            compression_level,
            decompression_state: InflateState::new_boxed(DataFormat::Zlib),
            compression_state,
        }
    }
}

impl<R, W> StreamProvider for AsyncDefaultStreamProvider<R, W> {
    type CompressionLevel = Compression;

    fn set_compression_threshold(&mut self, threshold: Option<usize>) {
        self.compression_threshold = threshold;
    }

    fn compression_threshold(&self) -> Option<usize> {
        self.compression_threshold
    }

    fn compression_level(&self) -> Self::CompressionLevel {
        self.compression_level
    }
}

impl<R: AsyncRead + Unpin, W> EncryptableStreamProvider for AsyncDefaultStreamProvider<R, W> {
    fn with_encryption(&mut self, key: [u8; 16]) {
        self.reader.get_mut().with_encryption(&key);
        self.writer.with_encryption(&key);
    }
}

impl<R: AsyncRead + Unpin, W> AsyncReadStreamProvider for AsyncDefaultStreamProvider<R, W> {
    type Error = futures_io::Error;

    type AsyncBaseReader<'a>
        = FuturesIo<FuturesReader<'a, &'a mut BufReader<AsyncDefaultReader<R>>>>
    where
        Self: 'a;

    fn async_read_stream(&mut self) -> Self::AsyncBaseReader<'_> {
        FuturesIo(FuturesReader {
            state: &mut self.decompression_state,
            reader: &mut self.reader,
        })
    }
}

impl<R, W: AsyncWrite + Unpin> AsyncWriteStreamProvider for AsyncDefaultStreamProvider<R, W> {
    type Error = futures_io::Error;

    type AsyncBaseWriter<'a>
        = FuturesIo<FuturesWriter<'a, &'a mut AsyncDefaultWriter<W>>>
    where
        Self: 'a;

    fn async_write_stream(&mut self) -> Self::AsyncBaseWriter<'_> {
        FuturesIo(FuturesWriter {
            state: &mut self.compression_state,
            writer: &mut self.writer,
        })
    }
}
