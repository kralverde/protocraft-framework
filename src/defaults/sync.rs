extern crate std;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, inout::InOutBuf};
use miniz_oxide::{
    DataFormat, MZFlush, MZStatus,
    deflate::{
        core::{CompressorOxide, deflate_flags},
        stream::deflate,
    },
    inflate::stream::{InflateState, MinReset, inflate},
};

use crate::{
    defaults::Compression,
    traits::{
        BoundableDecompressableReader, BoundableReader, BoundedReader, CompressableWriter,
        CompressionWriter, DecompressableReader, EncryptableStreamProvider, PreCompressionWriter,
        ReadStreamProvider, SetBlocking, StreamProvider, WriteStreamProvider, Writer,
    },
};

pub struct DecompressionReader<'a, R> {
    state: &'a mut InflateState,
    reader: R,
}

impl<R> std::io::Read for DecompressionReader<'_, R>
where
    R: std::io::BufRead,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let internal_buf = self.reader.fill_buf()?;
        let result = inflate(self.state, internal_buf, buf, MZFlush::None);
        let _ = result
            .status
            .map_err(|err| std::io::Error::other(std::format!("Decompression error: {:?}", err)))?;
        self.reader.consume(result.bytes_consumed);
        Ok(result.bytes_written)
    }
}

impl<R> SetBlocking for DecompressionReader<'_, R>
where
    R: SetBlocking<BlockingError = std::io::Error>,
{
    type BlockingError = std::io::Error;

    fn set_blocking(&mut self, blocking: bool) -> Result<(), Self::BlockingError> {
        self.reader.set_blocking(blocking)
    }
}

pub struct DecryptionReader<R> {
    decryptor: cfb8::Decryptor<aes::Aes128>,
    reader: R,
}

impl<R> BoundableReader for DecompressionReader<'_, R>
where
    R: std::io::BufRead + SetBlocking<BlockingError = std::io::Error>,
{
    type BoundedReader<'a>
        = std::io::Take<&'a mut Self>
    where
        Self: 'a;

    fn with_bound(&mut self, bound: usize) -> Self::BoundedReader<'_> {
        <&mut DecompressionReader<'_, R> as std::io::Read>::take(self, bound as u64)
    }
}

impl<R> BoundedReader for std::io::Take<R>
where
    R: std::io::Read + SetBlocking<BlockingError = std::io::Error>,
{
    fn remaining(&self) -> usize {
        self.limit() as usize
    }
}

impl<R> std::io::Read for DecryptionReader<R>
where
    R: std::io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let amount_read = self.reader.read(buf)?;
        if amount_read == 0 {
            Ok(0)
        } else {
            let io_buf: InOutBuf<u8> = (&mut buf[..amount_read]).into();
            let (chunks, tail) = io_buf.into_chunks();
            // SAFETY: Our chunk size is 1 byte. There will never be a tail.
            assert!(tail.is_empty());
            self.decryptor.decrypt_blocks_inout_mut(chunks);
            Ok(amount_read)
        }
    }
}

pub struct EncryptionWriter<W> {
    encryptor: cfb8::Encryptor<aes::Aes128>,
    writer: W,
    buffer: std::vec::Vec<u8>,
}

impl<W> std::io::Write for EncryptionWriter<W>
where
    W: std::io::Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut capacity = self.buffer.capacity() - self.buffer.len();
        if capacity == 0 {
            let io_buf: InOutBuf<u8> = (self.buffer.as_mut_slice()).into();
            let (chunks, tail) = io_buf.into_chunks();
            // SAFETY: Our chunk size is 1 byte. There will never be a tail.
            assert!(tail.is_empty());
            self.encryptor.encrypt_blocks_inout_mut(chunks);
            self.writer.write_all(&self.buffer)?;
            self.buffer.clear();

            capacity = self.buffer.capacity();
        }

        let amount_to_write = capacity.min(buf.len());
        self.buffer.extend_from_slice(&buf[..amount_to_write]);
        Ok(amount_to_write)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buffer.is_empty() {
            let io_buf: InOutBuf<u8> = (self.buffer.as_mut_slice()).into();
            let (chunks, tail) = io_buf.into_chunks();
            // SAFETY: Our chunk size is 1 byte. There will never be a tail.
            assert!(tail.is_empty());
            self.encryptor.encrypt_blocks_inout_mut(chunks);
            self.writer.write_all(&self.buffer)?;
            self.buffer.clear();
        }

        self.writer.flush()
    }
}

pub struct DecompressionStateWrappedReader<'a, R> {
    decompression_state: &'a mut InflateState,
    reader: R,
}

impl<R> std::io::Read for DecompressionStateWrappedReader<'_, R>
where
    R: std::io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R> SetBlocking for DecompressionStateWrappedReader<'_, R>
where
    R: SetBlocking<BlockingError = std::io::Error>,
{
    type BlockingError = std::io::Error;

    fn set_blocking(&mut self, blocking: bool) -> Result<(), Self::BlockingError> {
        self.reader.set_blocking(blocking)
    }
}

impl<R> BoundableDecompressableReader for DecompressionStateWrappedReader<'_, R>
where
    R: std::io::BufRead + SetBlocking<BlockingError = std::io::Error>,
{
    type BoundedReader<'a>
        = DecompressionStateWrappedReader<'a, std::io::Take<&'a mut R>>
    where
        Self: 'a;

    fn with_bound(&mut self, bound: usize) -> Self::BoundedReader<'_> {
        DecompressionStateWrappedReader {
            decompression_state: self.decompression_state,
            reader: <&mut R as std::io::Read>::take(&mut self.reader, bound as u64),
        }
    }
}

impl<R> BoundableReader for DecompressionStateWrappedReader<'_, R>
where
    R: std::io::Read + SetBlocking<BlockingError = std::io::Error>,
{
    type BoundedReader<'a>
        = DecompressionStateWrappedReader<'a, std::io::Take<&'a mut R>>
    where
        Self: 'a;

    fn with_bound(&mut self, bound: usize) -> Self::BoundedReader<'_> {
        DecompressionStateWrappedReader {
            decompression_state: self.decompression_state,
            reader: <&mut R as std::io::Read>::take(&mut self.reader, bound as u64),
        }
    }
}

impl<R> BoundedReader for DecompressionStateWrappedReader<'_, std::io::Take<R>>
where
    R: std::io::Read + SetBlocking<BlockingError = std::io::Error>,
{
    fn remaining(&self) -> usize {
        self.reader.limit() as usize
    }
}

impl<R> DecompressableReader for DecompressionStateWrappedReader<'_, R>
where
    R: std::io::BufRead + SetBlocking<BlockingError = std::io::Error>,
{
    type DecompressReader<'a>
        = DecompressionReader<'a, &'a mut R>
    where
        Self: 'a;

    fn with_decompression(&mut self) -> Self::DecompressReader<'_> {
        let state = &mut self.decompression_state;
        state.reset_as(MinReset);
        DecompressionReader {
            state,
            reader: &mut self.reader,
        }
    }
}

pub enum DefaultReader<R> {
    Standard(R),
    Decrypt(std::boxed::Box<DecryptionReader<R>>),
    Poisoned,
}

impl<R> SetBlocking for DefaultReader<R>
where
    R: SetBlocking<BlockingError = std::io::Error>,
{
    type BlockingError = std::io::Error;
    fn set_blocking(&mut self, blocking: bool) -> Result<(), Self::BlockingError> {
        match self {
            Self::Standard(reader) => reader.set_blocking(blocking),
            Self::Decrypt(reader) => reader.reader.set_blocking(blocking),
            Self::Poisoned => unreachable!(),
        }
    }
}

impl<R> DefaultReader<R> {
    fn with_encryption(&mut self, key: &[u8; 16]) {
        match std::mem::replace(self, Self::Poisoned) {
            Self::Standard(reader) => {
                let decryption_reader = DecryptionReader {
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

impl<R> std::io::Read for DefaultReader<R>
where
    R: std::io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Standard(reader) => reader.read(buf),
            Self::Decrypt(reader) => reader.read(buf),
            Self::Poisoned => unreachable!(),
        }
    }
}

pub struct BufferedWriter<W> {
    writer: W,
    buffer: std::vec::Vec<u8>,
}

impl<W> std::io::Write for BufferedWriter<W>
where
    W: std::io::Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut capacity = self.buffer.capacity() - self.buffer.len();
        if capacity == 0 {
            self.writer.write_all(&self.buffer)?;
            self.buffer.clear();

            capacity = self.buffer.capacity();
        }

        let amount_to_write = capacity.min(buf.len());
        self.buffer.extend_from_slice(&buf[..amount_to_write]);
        Ok(amount_to_write)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buffer.is_empty() {
            self.writer.write_all(&self.buffer)?;
            self.buffer.clear();
        }

        self.writer.flush()
    }
}

pub enum DefaultWriterState<W> {
    Standard(std::boxed::Box<BufferedWriter<W>>),
    Encrypt(std::boxed::Box<EncryptionWriter<W>>),
    Poisoned,
}

pub struct DefaultWriter<W> {
    compression_state: std::boxed::Box<CompressorOxide>,
    writer: DefaultWriterState<W>,
}

impl<W> DefaultWriter<W> {
    fn with_encryption(&mut self, key: &[u8; 16]) {
        match std::mem::replace(&mut self.writer, DefaultWriterState::Poisoned) {
            DefaultWriterState::Standard(buf_write) => {
                let writer = buf_write.writer;
                let mut buffer = buf_write.buffer;
                buffer.clear();

                let encryption_writer = EncryptionWriter {
                    encryptor: cfb8::Encryptor::new(key.into(), key.into()),
                    writer,
                    buffer,
                };
                self.writer = DefaultWriterState::Encrypt(std::boxed::Box::new(encryption_writer));
            }
            DefaultWriterState::Encrypt(_) => panic!("We are already encrypting!"),
            DefaultWriterState::Poisoned => unreachable!(),
        }
    }
}

impl<W> std::io::Write for DefaultWriter<W>
where
    W: std::io::Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.writer {
            DefaultWriterState::Standard(writer) => {
                <std::boxed::Box<BufferedWriter<W>> as std::io::Write>::write(writer, buf)
            }
            DefaultWriterState::Encrypt(writer) => {
                <std::boxed::Box<EncryptionWriter<W>> as std::io::Write>::write(writer, buf)
            }
            DefaultWriterState::Poisoned => unreachable!(),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.writer {
            DefaultWriterState::Standard(writer) => {
                <std::boxed::Box<BufferedWriter<W>> as std::io::Write>::flush(writer)
            }
            DefaultWriterState::Encrypt(writer) => {
                <std::boxed::Box<EncryptionWriter<W>> as std::io::Write>::flush(writer)
            }
            DefaultWriterState::Poisoned => unreachable!(),
        }
    }
}

pub struct CachedPreCompressionWriter<'a> {
    state: &'a mut CompressorOxide,
    buffer: std::vec::Vec<u8>,
    written: usize,
}

impl Writer for CachedPreCompressionWriter<'_> {
    type Error = std::io::Error;

    fn write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let mut consumed = 0;
        self.buffer
            .resize(self.buffer.len() + 2.max(data.len() / 2), 0);
        loop {
            let result = deflate(
                self.state,
                &data[consumed..],
                &mut self.buffer[self.written..],
                MZFlush::None,
            );
            let _ = result.status.map_err(|err| {
                std::io::Error::other(std::format!("Write compression error: {:?}", err))
            })?;

            consumed += result.bytes_consumed;
            self.written += result.bytes_written;
            if consumed == data.len() {
                break;
            }

            let guess = 2.max((data.len().saturating_sub(consumed)) - 2);
            if self.buffer.len().saturating_sub(self.written) < guess {
                // We need more space, so resize the buffer
                self.buffer.resize(self.buffer.len() + guess, 0);
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        if self.buffer.len() == self.written {
            // We need more space, so resize the buffer
            self.buffer.resize(2.max(self.buffer.len() * 2), 0);
        }

        loop {
            let result = deflate(
                self.state,
                &[],
                &mut self.buffer[self.written..],
                MZFlush::Finish,
            );
            let status = result.status.map_err(|err| {
                std::io::Error::other(std::format!("Flush compression error: {:?}", err))
            })?;
            self.written += result.bytes_written;

            if matches!(status, MZStatus::StreamEnd) {
                self.buffer.truncate(self.written);
                break;
            }

            // We need more space, so resize the buffer
            self.buffer.resize(self.buffer.len() * 2, 0);
        }
        Ok(())
    }
}

impl PreCompressionWriter for CachedPreCompressionWriter<'_> {
    type Payload = std::vec::Vec<u8>;

    fn finish(self) -> Result<(usize, Self::Payload), Self::Error> {
        let payload = self.buffer;
        Ok((payload.len(), payload))
    }
}

pub struct CachedCompressionWriter<W>(W);

impl<W> Writer for CachedCompressionWriter<W>
where
    W: std::io::Write,
{
    type Error = std::io::Error;

    fn write(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
        // Handled in `Self::initialize`
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.0.flush()?;
        Ok(())
    }
}

impl<W> CompressionWriter for CachedCompressionWriter<W>
where
    W: std::io::Write,
{
    type Payload = std::vec::Vec<u8>;

    fn initialize(&mut self, payload: Self::Payload) -> Result<(), Self::Error> {
        self.0.write_all(&payload)?;
        Ok(())
    }
}

impl<W> CompressableWriter for &mut DefaultWriter<W>
where
    W: std::io::Write,
{
    type Payload = std::vec::Vec<u8>;
    type Level = Compression;

    type PreCompressionWriter<'a>
        = CachedPreCompressionWriter<'a>
    where
        Self: 'a;

    type CompressionWriter<'a>
        = CachedCompressionWriter<&'a mut DefaultWriter<W>>
    where
        Self: 'a;

    fn pre_compression_writer(&mut self, _level: &Self::Level) -> Self::PreCompressionWriter<'_> {
        let compressor = &mut self.compression_state;
        //compressor.set_compression_level(*level);
        compressor.reset();
        CachedPreCompressionWriter {
            state: compressor,
            buffer: std::vec::Vec::new(),
            written: 0,
        }
    }

    fn with_compression(&mut self, _level: &Self::Level) -> Self::CompressionWriter<'_> {
        CachedCompressionWriter(self)
    }
}

pub struct DefaultStreamProvider<R, W: std::io::Write> {
    reader: std::io::BufReader<DefaultReader<R>>,
    writer: DefaultWriter<W>,
    compression_threshold: Option<usize>,
    compression_level: Compression,
    decompression_state: std::boxed::Box<InflateState>,
}

impl<R: std::io::Read, W: std::io::Write> DefaultStreamProvider<R, W> {
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
            reader: std::io::BufReader::with_capacity(buffer_size, DefaultReader::Standard(reader)),
            writer: DefaultWriter {
                writer: DefaultWriterState::Standard(std::boxed::Box::new(BufferedWriter {
                    writer,
                    buffer: std::vec::Vec::with_capacity(buffer_size),
                })),
                compression_state,
            },
            compression_threshold: None,
            compression_level,
            decompression_state: InflateState::new_boxed(DataFormat::Zlib),
        }
    }
}

impl<R, W: std::io::Write> EncryptableStreamProvider for DefaultStreamProvider<R, W> {
    fn with_encryption(&mut self, key: [u8; 16]) {
        self.reader.get_mut().with_encryption(&key);
        self.writer.with_encryption(&key);
    }
}

impl<R, W: std::io::Write> StreamProvider for DefaultStreamProvider<R, W> {
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

impl<R: std::io::Read + SetBlocking<BlockingError = std::io::Error>, W: std::io::Write>
    ReadStreamProvider for DefaultStreamProvider<R, W>
{
    type Error = std::io::Error;
    type BaseReader<'a>
        = DecompressionStateWrappedReader<'a, &'a mut std::io::BufReader<DefaultReader<R>>>
    where
        Self: 'a;

    fn read_stream(&mut self) -> Self::BaseReader<'_> {
        DecompressionStateWrappedReader {
            decompression_state: &mut self.decompression_state,
            reader: &mut self.reader,
        }
    }
}

impl<R: std::io::Read, W: std::io::Write> WriteStreamProvider for DefaultStreamProvider<R, W> {
    type Error = std::io::Error;
    type BaseWriter<'a>
        = &'a mut DefaultWriter<W>
    where
        Self: 'a;

    fn write_stream(&mut self) -> Self::BaseWriter<'_> {
        &mut self.writer
    }
}
