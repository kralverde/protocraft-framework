use crate::traits::{Reader, SetBlocking, Writer};

extern crate std;

impl<R> SetBlocking for &mut R
where
    R: SetBlocking,
{
    fn set_blocking(&mut self, blocking: bool) {
        (*self).set_blocking(blocking);
    }
}

impl<R> SetBlocking for std::io::BufReader<R>
where
    R: SetBlocking,
{
    fn set_blocking(&mut self, blocking: bool) {
        self.get_mut().set_blocking(blocking);
    }
}

impl SetBlocking for std::net::TcpStream {
    fn set_blocking(&mut self, blocking: bool) {
        self.set_nonblocking(!blocking).expect("");
    }
}

impl<R> Reader for R
where
    R: std::io::Read + SetBlocking,
{
    type Error = std::io::Error;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        <Self as std::io::Read>::read_exact(self, buf)?;
        Ok(())
    }

    fn try_read_byte(&mut self) -> Result<Option<u8>, Self::Error> {
        let mut buf = [0u8; 1];

        self.set_blocking(false);
        let result = match <Self as std::io::Read>::read(self, &mut buf) {
            Ok(amount) => {
                if amount == 0 {
                    Ok(None)
                } else {
                    Ok(Some(buf[0]))
                }
            }
            Err(err) => {
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        };
        self.set_blocking(true);
        result
    }

    fn discard(&mut self, amount: usize) -> Result<(), Self::Error> {
        if amount != 0 {
            let amount = amount as u64;
            let mut reader = <&mut R as std::io::Read>::take(self, amount);
            let amount_discarded = std::io::copy(&mut reader, &mut std::io::sink())?;
            if amount_discarded != amount {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF while discarding",
                ));
            }
        }
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
