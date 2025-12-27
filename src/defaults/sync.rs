extern crate std;

use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit, generic_array::GenericArray, inout::InOutBuf,
};

use crate::traits::{
    BoundableDecompressableReader, BoundableReader, BoundedReader, CompressableWriter,
    CompressionWriter, DecompressableReader, ReadStreamProvider, StreamProvider,
    WriteStreamProvider,
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
            Self::Encrypt(writer) => writer.write(buf),
            Self::Poisoned => unreachable!(),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Standard(writer) => writer.flush(),
            Self::Encrypt(writer) => writer.flush(),
            Self::Poisoned => unreachable!(),
        }
    }
}

impl<R> BoundableDecompressableReader for R
where
    R: std::io::BufRead,
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
    R: std::io::Read,
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
    R: std::io::Read,
{
    fn remaining(&self) -> usize {
        self.limit() as usize
    }

    fn discard(&mut self, amount: usize) -> Result<(), Self::Error> {
        if amount != 0 {
            let mut reader = <&mut std::io::Take<R> as std::io::Read>::take(self, amount as u64);
            let _ = std::io::copy(&mut reader, &mut std::io::sink())?;
        }
        Ok(())
    }
}

impl<R> DecompressableReader for R
where
    R: std::io::BufRead,
{
    type DecompressReader<'a>
        = flate2::bufread::ZlibDecoder<&'a mut R>
    where
        Self: 'a;

    fn with_decompression(&mut self) -> Self::DecompressReader<'_> {
        flate2::bufread::ZlibDecoder::new(self)
    }
}

impl CompressionWriter for flate2::write::ZlibEncoder<std::vec::Vec<u8>> {
    type Bytes = std::vec::Vec<u8>;

    fn into_bytes(self) -> Result<Self::Bytes, Self::Error> {
        let inner = self.finish()?;
        Ok(inner)
    }
}

impl<W> CompressableWriter for W
where
    W: std::io::Write,
{
    type Level = flate2::Compression;
    type CompressionWriter = flate2::write::ZlibEncoder<std::vec::Vec<u8>>;

    fn compression_writer(level: Self::Level) -> Self::CompressionWriter {
        flate2::write::ZlibEncoder::new(std::vec::Vec::new(), level)
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

    // TODO: Add warning about stale data in the buffer here
    pub fn with_encryption(&mut self, key: [u8; 16]) {
        self.reader.get_mut().with_encryption(&key);
        self.writer.with_encryption(&key);
    }
}

impl<R, W: std::io::Write> StreamProvider for DefaultStreamProvider<R, W> {
    type CompressionLevel = flate2::Compression;

    fn compression_threshold(&self) -> Option<usize> {
        self.compression_threshold
    }

    fn compression_level(&self) -> Self::CompressionLevel {
        self.compression_level
    }
}

impl<R: std::io::Read, W: std::io::Write> ReadStreamProvider for DefaultStreamProvider<R, W> {
    type BaseReader<'a>
        = &'a mut std::io::BufReader<DefaultReader<R>>
    where
        Self: 'a;

    fn read_stream(&mut self) -> Self::BaseReader<'_> {
        &mut self.reader
    }
}

impl<R: std::io::Read, W: std::io::Write> WriteStreamProvider for DefaultStreamProvider<R, W> {
    type BaseWriter<'a>
        = &'a mut DefaultWriter<std::io::BufWriter<W>>
    where
        Self: 'a;

    fn write_stream(&mut self) -> Self::BaseWriter<'_> {
        &mut self.writer
    }
}
