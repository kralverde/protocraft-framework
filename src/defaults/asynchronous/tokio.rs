extern crate std;

use core::{
    pin::Pin,
    task::{Context, Poll},
};

use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit, generic_array::GenericArray, inout::InOutBuf,
};
use miniz_oxide::{
    MZFlush,
    deflate::{
        CompressionLevel,
        core::{CompressorOxide, deflate_flags},
        stream::deflate,
    },
    inflate::stream::{InflateState, inflate},
};
use tokio::io::{
    AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter,
    ReadBuf, Take,
};

use crate::{
    asynchronous::TokioIo,
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
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let reader = &mut this.reader;
        let state = &mut this.state;

        tokio::pin!(reader);
        let result = reader.as_mut().poll_fill_buf(cx)?;
        let Poll::Ready(internal_buf) = result else {
            return Poll::Pending;
        };

        let result = inflate(
            state,
            internal_buf,
            buf.initialize_unfilled(),
            MZFlush::None,
        );
        let _ = result.status.map_err(|err| {
            tokio::io::Error::other(std::format!("Decompression error: {:?}", err))
        })?;
        reader.consume(result.bytes_consumed);

        Poll::Ready(Ok(()))
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
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let reader_ref = &mut self.as_mut().reader;
        tokio::pin!(reader_ref);

        let original_fill = buf.filled().len();
        let result = reader_ref.poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            let new_fill = buf.filled().len();

            // We only want to decrypt what was just read
            let io_buf: InOutBuf<u8> = (&mut buf.filled_mut()[original_fill..new_fill]).into();
            let (chunks, tail) = io_buf.into_chunks();
            // SAFETY: Our chunk size is 1 byte. There will never be a tail.
            assert!(tail.is_empty());
            self.decryptor.decrypt_blocks_inout_mut(chunks);
        }

        result
    }
}

pub struct AsyncEncryptionWriter<W> {
    encryptor: cfb8::Encryptor<aes::Aes128>,
    writer: W,
    last_byte: Option<u8>,
}

impl<W> AsyncEncryptionWriter<W> {
    fn deconstruct(&mut self) -> (&mut cfb8::Encryptor<aes::Aes128>, &mut W, &mut Option<u8>) {
        (&mut self.encryptor, &mut self.writer, &mut self.last_byte)
    }
}

impl<W> AsyncWrite for AsyncEncryptionWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        // Lots of small writes; we'll want to recommend using a `AsyncBufWriter`
        let mut total_written = 0;

        let (encryptor, writer, last_byte) = self.deconstruct();
        tokio::pin!(writer);

        if let Some(byte) = last_byte {
            let result = writer.as_mut().poll_write(cx, &[*byte]);
            let Poll::Ready(Ok(amount_written)) = result else {
                return result;
            };

            *last_byte = None;
            total_written += amount_written;
        }

        for byte in buf {
            let mut chunk = GenericArray::from([*byte]);
            encryptor.encrypt_block_inout_mut((&mut chunk).into());
            let result = writer.as_mut().poll_write(cx, &chunk);
            match result {
                Poll::Ready(result) => match result {
                    Ok(amount_written) => {
                        total_written += amount_written;
                    }
                    Err(err) => {
                        return Poll::Ready(Err(err));
                    }
                },
                Poll::Pending => {
                    *last_byte = Some(chunk[0]);
                    return Poll::Ready(Ok(total_written));
                }
            }
        }

        Poll::Ready(Ok(total_written))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), tokio::io::Error>> {
        let writer = &mut self.as_mut().writer;
        tokio::pin!(writer);
        writer.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), tokio::io::Error>> {
        let writer = &mut self.as_mut().writer;
        tokio::pin!(writer);
        writer.poll_shutdown(cx)
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
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        match &mut *self {
            Self::Standard(reader) => {
                tokio::pin!(reader);
                reader.poll_read(cx, buf)
            }
            Self::Decrypt(reader) => {
                tokio::pin!(reader);
                reader.poll_read(cx, buf)
            }
            Self::Poisoned => unreachable!(),
        }
    }
}

pub enum AsyncDefaultWriter<W> {
    Standard(W),
    Encrypt(std::boxed::Box<AsyncEncryptionWriter<W>>),
    Poisoned,
}

impl<W> AsyncDefaultWriter<W> {
    fn with_encryption(&mut self, key: &[u8; 16]) {
        match std::mem::replace(self, Self::Poisoned) {
            Self::Standard(writer) => {
                let encryption_writer = AsyncEncryptionWriter {
                    encryptor: cfb8::Encryptor::new(key.into(), key.into()),
                    writer,
                    last_byte: None,
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
    ) -> Poll<Result<usize, tokio::io::Error>> {
        match &mut *self {
            Self::Standard(writer) => {
                tokio::pin!(writer);
                writer.poll_write(cx, buf)
            }
            Self::Encrypt(writer) => {
                tokio::pin!(writer);
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
    ) -> Poll<Result<(), tokio::io::Error>> {
        match &mut *self {
            Self::Standard(writer) => {
                tokio::pin!(writer);
                writer.poll_flush(cx)
            }
            Self::Encrypt(writer) => {
                tokio::pin!(writer);
                writer.poll_flush(cx)
            }
            Self::Poisoned => {
                unreachable!()
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), tokio::io::Error>> {
        match &mut *self {
            Self::Standard(writer) => {
                tokio::pin!(writer);
                writer.poll_shutdown(cx)
            }
            Self::Encrypt(writer) => {
                tokio::pin!(writer);
                writer.poll_shutdown(cx)
            }
            Self::Poisoned => {
                unreachable!()
            }
        }
    }
}

impl<R> From<TokioIo<Take<R>>> for TokioIo<R>
where
    R: AsyncRead + Unpin,
{
    fn from(value: TokioIo<Take<R>>) -> Self {
        TokioIo(value.0.into_inner())
    }
}

impl<R> AsyncBoundableDecompressableReader for TokioIo<R>
where
    R: AsyncBufRead + Unpin,
{
    type AsyncBoundedReader = TokioIo<Take<R>>;

    fn with_bound(self, bound: usize) -> Self::AsyncBoundedReader {
        TokioIo(self.0.take(bound as u64))
    }
}

impl<R> AsyncBoundableReader for TokioIo<R>
where
    R: AsyncRead + Unpin,
{
    type AsyncBoundedReader = TokioIo<Take<R>>;

    fn with_bound(self, bound: usize) -> Self::AsyncBoundedReader {
        TokioIo(self.0.take(bound as u64))
    }
}

impl<R> AsyncBoundedReader for TokioIo<Take<R>>
where
    R: AsyncRead + Unpin,
{
    async fn async_remaining(&self) -> usize {
        self.0.limit() as usize
    }
}

impl<R> AsyncDecompressableReader for TokioIo<R>
where
    R: AsyncBufRead + Unpin,
{
    type AsyncDecompressReader = TokioIo<AsyncDecompressionReader<'static, R>>;

    fn with_decompression(self) -> Self::AsyncDecompressReader {
        todo!()
    }
}

impl<R> From<TokioIo<AsyncDecompressionReader<'static, R>>> for TokioIo<R> {
    fn from(value: TokioIo<AsyncDecompressionReader<'static, R>>) -> Self {
        todo!()
    }
}

pub struct AsyncCachedPreCompressionWriter {
    state: &'static mut CompressorOxide,
    buffer: std::vec::Vec<u8>,
}

impl AsyncWriter for AsyncCachedPreCompressionWriter {
    type Error = tokio::io::Error;

    async fn async_write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let mut offset = 0;
        let mut buf = [0u8; 4096];
        loop {
            let result = deflate(self.state, &data[offset..], &mut buf, MZFlush::Sync);
            let _ = result.status.map_err(|err| {
                tokio::io::Error::other(std::format!("Compression error: {:?}", err))
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

impl AsyncPreCompressionWriter for AsyncCachedPreCompressionWriter {
    type Payload = std::vec::Vec<u8>;

    async fn async_finish(self) -> Result<(usize, Self::Payload), Self::Error> {
        let buffer = self.buffer;
        Ok((buffer.len(), buffer))
    }
}

pub struct CachedCompressionWriter<W>(W);

impl<W> AsyncWriter for CachedCompressionWriter<W>
where
    W: AsyncWrite + Unpin,
{
    type Error = tokio::io::Error;

    async fn async_write(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
        // Handled in `Self::initialize`
        Ok(())
    }

    async fn async_flush(&mut self) -> Result<(), Self::Error> {
        self.0.flush().await?;
        Ok(())
    }
}

impl<W> AsyncCompressionWriter for CachedCompressionWriter<W>
where
    W: AsyncWrite + Unpin,
{
    type Payload = std::vec::Vec<u8>;

    async fn async_initialize(&mut self, payload: Self::Payload) -> Result<(), Self::Error> {
        self.0.write_all(&payload).await?;
        Ok(())
    }
}

impl<W> From<CachedCompressionWriter<W>> for TokioIo<W> {
    fn from(value: CachedCompressionWriter<W>) -> Self {
        TokioIo(value.0)
    }
}

impl<W> AsyncCompressableWriter for TokioIo<W>
where
    W: AsyncWrite + Unpin,
{
    type Payload = std::vec::Vec<u8>;
    type Level = CompressionLevel;

    type AsyncPreCompressionWriter = AsyncCachedPreCompressionWriter;
    type AsyncCompressionWriter = CachedCompressionWriter<W>;

    fn async_pre_compression_writer(_level: &Self::Level) -> Self::AsyncPreCompressionWriter {
        todo!()
    }

    fn with_async_compression(self, _level: &Self::Level) -> Self::AsyncCompressionWriter {
        CachedCompressionWriter(self.0)
    }
}

pub struct AsyncDefaultStreamProvider<R, W> {
    reader: BufReader<AsyncDefaultReader<R>>,
    writer: AsyncDefaultWriter<BufWriter<W>>,
    compression_threshold: Option<usize>,
    compression_level: CompressionLevel,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite> AsyncDefaultStreamProvider<R, W> {
    pub fn new(
        reader: R,
        writer: W,
        compression_level: CompressionLevel,
        buffer_size: usize,
    ) -> Self {
        let mut compression_state =
            std::boxed::Box::new(CompressorOxide::new(deflate_flags::TDEFL_WRITE_ZLIB_HEADER));
        compression_state.set_compression_level(compression_level);

        Self {
            reader: BufReader::with_capacity(buffer_size, AsyncDefaultReader::Standard(reader)),
            writer: AsyncDefaultWriter::Standard(BufWriter::with_capacity(buffer_size, writer)),
            compression_threshold: None,
            compression_level,
        }
    }
}

impl<R, W> StreamProvider for AsyncDefaultStreamProvider<R, W> {
    type CompressionLevel = CompressionLevel;

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
    type Error = tokio::io::Error;

    type AsyncBaseReader<'a>
        = TokioIo<&'a mut BufReader<AsyncDefaultReader<R>>>
    where
        Self: 'a;

    fn async_read_stream(&mut self) -> Self::AsyncBaseReader<'_> {
        TokioIo(&mut self.reader)
    }
}

impl<R, W: AsyncWrite + Unpin> AsyncWriteStreamProvider for AsyncDefaultStreamProvider<R, W> {
    type Error = tokio::io::Error;

    type AsyncBaseWriter<'a>
        = TokioIo<&'a mut AsyncDefaultWriter<BufWriter<W>>>
    where
        Self: 'a;

    fn async_write_stream(&mut self) -> Self::AsyncBaseWriter<'_> {
        TokioIo(&mut self.writer)
    }
}
