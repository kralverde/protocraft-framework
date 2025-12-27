extern crate std;

use core::{
    pin::Pin,
    task::{Context, Poll},
};

use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit, generic_array::GenericArray, inout::InOutBuf,
};
use tokio::io::{
    AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, ReadBuf,
};

use crate::traits::{
    StreamProvider,
    asynchronous::{
        AsyncBoundableDecompressableReader, AsyncBoundableReader, AsyncBoundedReader,
        AsyncCompressableWriter, AsyncCompressionWriter, AsyncDecompressableReader,
        AsyncReadStreamProvider, AsyncWrappedReader, AsyncWriteStreamProvider,
    },
};

use async_compression as ac;

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

impl<R> AsyncWrappedReader<R> for tokio::io::Take<R>
where
    R: AsyncRead + Unpin,
{
    fn into_parent(self) -> R {
        self.into_inner()
    }
}

impl<R> AsyncBoundableDecompressableReader for R
where
    R: AsyncBufRead + Unpin,
{
    type AsyncBoundedReader = tokio::io::Take<R>;

    fn with_bound(self, bound: usize) -> Self::AsyncBoundedReader {
        self.take(bound as u64)
    }
}

impl<R> AsyncBoundableReader for R
where
    R: AsyncRead + Unpin,
{
    type AsyncBoundedReader = tokio::io::Take<R>;

    fn with_bound(self, bound: usize) -> Self::AsyncBoundedReader {
        self.take(bound as u64)
    }
}

impl<R> AsyncBoundedReader for tokio::io::Take<R>
where
    R: AsyncRead + Unpin,
{
    async fn async_remaining(&self) -> usize {
        self.limit() as usize
    }

    async fn async_discard(&mut self, amount: usize) -> Result<(), Self::Error> {
        if amount != 0 {
            let mut reader = self.take(amount as u64);
            let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await?;
        }
        Ok(())
    }
}

impl<R> AsyncWrappedReader<R> for ac::tokio::bufread::ZlibDecoder<R>
where
    R: AsyncBufRead + Unpin,
{
    fn into_parent(self) -> R {
        self.into_inner()
    }
}

impl<R> AsyncDecompressableReader for R
where
    R: AsyncBufRead + Unpin,
{
    type AsyncDecompressReader = ac::tokio::bufread::ZlibDecoder<R>;

    fn with_decompression(self) -> Self::AsyncDecompressReader {
        ac::tokio::bufread::ZlibDecoder::new(self)
    }
}

impl AsyncCompressionWriter for ac::tokio::write::ZlibEncoder<std::vec::Vec<u8>> {
    type Bytes = std::vec::Vec<u8>;

    async fn async_into_bytes(mut self) -> Result<Self::Bytes, Self::Error> {
        self.flush().await?;
        Ok(self.into_inner())
    }
}

impl<W> AsyncCompressableWriter for W
where
    W: AsyncWrite + Unpin,
{
    type Level = ac::Level;
    type AsyncCompressionWriter = ac::tokio::write::ZlibEncoder<std::vec::Vec<u8>>;

    fn async_compression_writer(level: Self::Level) -> Self::AsyncCompressionWriter {
        ac::tokio::write::ZlibEncoder::with_quality(std::vec::Vec::new(), level)
    }
}

pub struct AsyncDefaultStreamProvider<R, W> {
    reader: BufReader<AsyncDefaultReader<R>>,
    writer: AsyncDefaultWriter<BufWriter<W>>,
    compression_threshold: Option<usize>,
    compression_level: ac::Level,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite> AsyncDefaultStreamProvider<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::with_capacity(4096, AsyncDefaultReader::Standard(reader)),
            writer: AsyncDefaultWriter::Standard(BufWriter::with_capacity(4096, writer)),
            compression_threshold: None,
            compression_level: ac::Level::Default,
        }
    }

    // TODO: Add warning about stale data in the buffer here
    pub fn with_encryption(&mut self, key: [u8; 16]) {
        self.reader.get_mut().with_encryption(&key);
        self.writer.with_encryption(&key);
    }
}

impl<R, W> StreamProvider for AsyncDefaultStreamProvider<R, W> {
    type CompressionLevel = ac::Level;

    fn compression_threshold(&self) -> Option<usize> {
        self.compression_threshold
    }

    fn compression_level(&self) -> Self::CompressionLevel {
        self.compression_level
    }
}

impl<R: AsyncRead + Unpin, W> AsyncReadStreamProvider for AsyncDefaultStreamProvider<R, W> {
    type AsyncBaseReader<'a>
        = &'a mut BufReader<AsyncDefaultReader<R>>
    where
        Self: 'a;

    fn async_read_stream(&mut self) -> Self::AsyncBaseReader<'_> {
        &mut self.reader
    }
}

impl<R, W: AsyncWrite + Unpin> AsyncWriteStreamProvider for AsyncDefaultStreamProvider<R, W> {
    type AsyncBaseWriter<'a>
        = &'a mut AsyncDefaultWriter<BufWriter<W>>
    where
        Self: 'a;

    fn async_write_stream(&mut self) -> Self::AsyncBaseWriter<'_> {
        &mut self.writer
    }
}
