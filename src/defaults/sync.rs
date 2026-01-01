extern crate std;

use aes::cipher::{
    generic_array::GenericArray, inout::InOutBuf, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};

use crate::traits::{
    BoundableDecompressableReader, BoundableReader, BoundedReader, CompressableWriter,
    CompressionWriter, DecompressableReader, EncryptableStreamProvider, PreCompressionWriter,
    ReadStreamProvider, SetBlocking, StreamProvider, WriteStreamProvider, Writer,
};

pub struct DecryptionReader<R> {
    decryptor: cfb8::Decryptor<aes::Aes128>,
    reader: R,
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

pub enum DefaultReader<R> {
    Standard(R),
    Decrypt(std::boxed::Box<DecryptionReader<R>>),
    Poisoned,
}

impl<R> SetBlocking for DefaultReader<R>
where
    R: SetBlocking,
{
    fn set_blocking(&mut self, blocking: bool) {
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

pub enum DefaultWriter<W> {
    Standard(W),
    Encrypt(std::boxed::Box<EncryptionWriter<W>>),
    Poisoned,
}

impl<W> DefaultWriter<W> {
    fn with_encryption(&mut self, key: &[u8; 16]) {
        match std::mem::replace(self, Self::Poisoned) {
            Self::Standard(writer) => {
                let encryption_writer = EncryptionWriter {
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

impl<W> std::io::Write for DefaultWriter<W>
where
    W: std::io::Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Standard(writer) => writer.write(buf),
            Self::Encrypt(writer) => {
                <std::boxed::Box<EncryptionWriter<W>> as std::io::Write>::write(writer, buf)
            }
            Self::Poisoned => unreachable!(),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Standard(writer) => writer.flush(),
            Self::Encrypt(writer) => {
                <std::boxed::Box<EncryptionWriter<W>> as std::io::Write>::flush(writer)
            }
            Self::Poisoned => unreachable!(),
        }
    }
}

impl<R> SetBlocking for std::io::Take<R>
where
    R: std::io::Read + SetBlocking,
{
    fn set_blocking(&mut self, blocking: bool) {
        self.get_mut().set_blocking(blocking);
    }
}

impl<R> BoundableDecompressableReader for R
where
    R: std::io::BufRead + SetBlocking,
{
    type BoundedReader<'a>
        = std::io::Take<&'a mut R>
    where
        Self: 'a;

    fn with_bound(&mut self, bound: usize) -> Self::BoundedReader<'_> {
        <&mut R as std::io::Read>::take(self, bound as u64)
    }
}

impl<R> BoundableReader for R
where
    R: std::io::Read + SetBlocking,
{
    type BoundedReader<'a>
        = std::io::Take<&'a mut R>
    where
        Self: 'a;

    fn with_bound(&mut self, bound: usize) -> Self::BoundedReader<'_> {
        <&mut R as std::io::Read>::take(self, bound as u64)
    }
}

impl<R> BoundedReader for std::io::Take<R>
where
    R: std::io::Read + SetBlocking,
{
    fn remaining(&self) -> usize {
        self.limit() as usize
    }
}

impl<R> SetBlocking for flate2::bufread::ZlibDecoder<R>
where
    R: std::io::BufRead + SetBlocking,
{
    fn set_blocking(&mut self, blocking: bool) {
        self.get_mut().set_blocking(blocking);
    }
}

impl<R> DecompressableReader for R
where
    R: std::io::BufRead + SetBlocking,
{
    type DecompressReader<'a>
        = flate2::bufread::ZlibDecoder<&'a mut R>
    where
        Self: 'a;

    fn with_decompression(&mut self) -> Self::DecompressReader<'_> {
        flate2::bufread::ZlibDecoder::new(self)
    }
}

pub struct CachedPreCompressionWriter(flate2::write::ZlibEncoder<std::vec::Vec<u8>>);

impl Writer for CachedPreCompressionWriter {
    type Error = std::io::Error;

    fn write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.0.write(data)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // Handled in `Self::finish`
        Ok(())
    }
}

impl PreCompressionWriter for CachedPreCompressionWriter {
    type Payload = std::vec::Vec<u8>;

    fn finish(self) -> Result<(usize, Self::Payload), Self::Error> {
        let payload = self.0.flush_finish()?;
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

impl<W> CompressableWriter for W
where
    W: std::io::Write,
{
    type Payload = std::vec::Vec<u8>;
    type Level = flate2::Compression;

    type PreCompressionWriter = CachedPreCompressionWriter;

    type CompressionWriter<'a>
        = CachedCompressionWriter<&'a mut W>
    where
        Self: 'a;

    fn pre_compression_writer(level: &Self::Level) -> Self::PreCompressionWriter {
        CachedPreCompressionWriter(flate2::write::ZlibEncoder::new(
            std::vec::Vec::new(),
            *level,
        ))
    }

    fn with_compression(&mut self, _level: &Self::Level) -> Self::CompressionWriter<'_> {
        CachedCompressionWriter(self)
    }
}

pub struct DefaultStreamProvider<R, W: std::io::Write> {
    reader: std::io::BufReader<DefaultReader<R>>,
    writer: DefaultWriter<std::io::BufWriter<W>>,
    compression_threshold: Option<usize>,
    compression_level: flate2::Compression,
}

impl<R: std::io::Read, W: std::io::Write> DefaultStreamProvider<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: std::io::BufReader::with_capacity(4096, DefaultReader::Standard(reader)),
            writer: DefaultWriter::Standard(std::io::BufWriter::with_capacity(4096, writer)),
            compression_threshold: None,
            compression_level: flate2::Compression::default(),
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
    type CompressionLevel = flate2::Compression;

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

impl<R: std::io::Read + SetBlocking, W: std::io::Write> ReadStreamProvider
    for DefaultStreamProvider<R, W>
{
    type Error = std::io::Error;
    type BaseReader<'a>
        = &'a mut std::io::BufReader<DefaultReader<R>>
    where
        Self: 'a;

    fn read_stream(&mut self) -> Self::BaseReader<'_> {
        &mut self.reader
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
