extern crate std;

use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit, generic_array::GenericArray, inout::InOutBuf,
};
use miniz_oxide::{
    DataFormat, MZFlush,
    deflate::{
        CompressionLevel,
        core::{CompressorOxide, deflate_flags},
        stream::deflate,
    },
    inflate::stream::{InflateState, MinReset, inflate},
};

use crate::traits::{
    BoundableDecompressableReader, BoundableReader, BoundedReader, CompressableWriter,
    CompressionWriter, DecompressableReader, EncryptableStreamProvider, PreCompressionWriter,
    ReadStreamProvider, SetBlocking, StreamProvider, WriteStreamProvider, Writer,
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
    last_byte: Option<u8>,
}

impl<W> std::io::Write for EncryptionWriter<W>
where
    W: std::io::Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Lots of small writes; we'll want to recommend using a `BufWriter`
        let mut total_written = 0;

        if let Some(byte) = self.last_byte {
            let amount_written = self.writer.write(&[byte])?;
            if amount_written == 0 {
                return Ok(0);
            }

            self.last_byte = None;
            total_written += 1;
        }

        for byte in buf {
            let mut chunk = GenericArray::from([*byte]);
            self.encryptor.encrypt_block_inout_mut((&mut chunk).into());
            let amount_written = self.writer.write(&chunk)?;
            if amount_written == 0 {
                self.last_byte = Some(chunk[0]);
                return Ok(total_written);
            } else {
                total_written += amount_written;
            }
        }

        Ok(total_written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

pub struct DecompressionStateWrappedReader<'a, R> {
    decompression_state: &'a mut std::boxed::Box<InflateState>,
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
            state: self.decompression_state,
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

pub enum DefaultWriterType<W> {
    Standard(W),
    Encrypt(std::boxed::Box<EncryptionWriter<W>>),
    Poisoned,
}

pub struct DefaultWriter<W> {
    compression_state: std::boxed::Box<CompressorOxide>,
    writer: DefaultWriterType<W>,
}

impl<W> DefaultWriter<W> {
    fn with_encryption(&mut self, key: &[u8; 16]) {
        match std::mem::replace(&mut self.writer, DefaultWriterType::Poisoned) {
            DefaultWriterType::Standard(writer) => {
                let encryption_writer = EncryptionWriter {
                    encryptor: cfb8::Encryptor::new(key.into(), key.into()),
                    writer,
                    last_byte: None,
                };
                self.writer = DefaultWriterType::Encrypt(std::boxed::Box::new(encryption_writer));
            }
            DefaultWriterType::Encrypt(_) => panic!("We are already encrypting!"),
            DefaultWriterType::Poisoned => unreachable!(),
        }
    }
}

impl<W> std::io::Write for DefaultWriter<W>
where
    W: std::io::Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.writer {
            DefaultWriterType::Standard(writer) => writer.write(buf),
            DefaultWriterType::Encrypt(writer) => {
                <std::boxed::Box<EncryptionWriter<W>> as std::io::Write>::write(writer, buf)
            }
            DefaultWriterType::Poisoned => unreachable!(),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.writer {
            DefaultWriterType::Standard(writer) => writer.flush(),
            DefaultWriterType::Encrypt(writer) => {
                <std::boxed::Box<EncryptionWriter<W>> as std::io::Write>::flush(writer)
            }
            DefaultWriterType::Poisoned => unreachable!(),
        }
    }
}

pub struct CachedPreCompressionWriter<'a> {
    state: &'a mut CompressorOxide,
    buffer: std::vec::Vec<u8>,
}

impl Writer for CachedPreCompressionWriter<'_> {
    type Error = std::io::Error;

    fn write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let mut offset = 0;
        let mut buf = [0u8; 4096];
        loop {
            let result = deflate(self.state, &data[offset..], &mut buf, MZFlush::Sync);
            let _ = result.status.map_err(|err| {
                std::io::Error::other(std::format!("Compression error: {:?}", err))
            })?;

            self.buffer.extend_from_slice(&buf[..result.bytes_written]);
            offset += result.bytes_consumed;
            if offset == data.len() {
                break;
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // Handled in `Self::finish`
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
    type Level = CompressionLevel;

    type PreCompressionWriter<'a>
        = CachedPreCompressionWriter<'a>
    where
        Self: 'a;

    type CompressionWriter<'a>
        = CachedCompressionWriter<&'a mut DefaultWriter<W>>
    where
        Self: 'a;

    fn pre_compression_writer(&mut self, level: &Self::Level) -> Self::PreCompressionWriter<'_> {
        let compressor = &mut self.compression_state;
        compressor.set_compression_level(*level);
        compressor.reset();
        CachedPreCompressionWriter {
            state: compressor,
            buffer: std::vec::Vec::new(),
        }
    }

    fn with_compression(&mut self, _level: &Self::Level) -> Self::CompressionWriter<'_> {
        CachedCompressionWriter(self)
    }
}

pub struct DefaultStreamProvider<R, W: std::io::Write> {
    reader: std::io::BufReader<DefaultReader<R>>,
    writer: DefaultWriter<std::io::BufWriter<W>>,
    compression_threshold: Option<usize>,
    compression_level: CompressionLevel,
    decompression_state: std::boxed::Box<InflateState>,
}

impl<R: std::io::Read, W: std::io::Write> DefaultStreamProvider<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: std::io::BufReader::with_capacity(4096, DefaultReader::Standard(reader)),
            writer: DefaultWriter {
                writer: DefaultWriterType::Standard(std::io::BufWriter::with_capacity(
                    4096, writer,
                )),
                compression_state: std::boxed::Box::new(CompressorOxide::new(
                    deflate_flags::TDEFL_WRITE_ZLIB_HEADER,
                )),
            },
            compression_threshold: None,
            compression_level: CompressionLevel::DefaultCompression,
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
        = &'a mut DefaultWriter<std::io::BufWriter<W>>
    where
        Self: 'a;

    fn write_stream(&mut self) -> Self::BaseWriter<'_> {
        &mut self.writer
    }
}
