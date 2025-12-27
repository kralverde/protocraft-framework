use crate::traits::{Reader, Writer};

extern crate std;

impl<R> Reader for R
where
    R: std::io::Read,
{
    type Error = std::io::Error;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        <Self as std::io::Read>::read_exact(self, buf)?;
        Ok(())
    }
}

impl<W> Writer for W
where
    W: std::io::Write,
{
    type Error = std::io::Error;

    fn write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        <Self as std::io::Write>::write_all(self, data)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        <Self as std::io::Write>::flush(self)?;
        Ok(())
    }
}
