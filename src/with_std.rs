use core::time::Duration;

use crate::traits::{Reader, SetBlocking, Writer};

extern crate std;

impl<R> SetBlocking for std::io::BufReader<R>
where
    R: SetBlocking<BlockingError = std::io::Error>,
{
    type BlockingError = std::io::Error;

    fn set_blocking(&mut self, blocking: bool) -> Result<(), Self::BlockingError> {
        self.get_mut().set_blocking(blocking)
    }
}

impl<R> SetBlocking for std::io::Take<R>
where
    R: SetBlocking<BlockingError = std::io::Error>,
{
    type BlockingError = std::io::Error;

    fn set_blocking(&mut self, blocking: bool) -> Result<(), Self::BlockingError> {
        self.get_mut().set_blocking(blocking)
    }
}

// std::io::Read implementors that allow non-blocking
impl SetBlocking for std::net::TcpStream {
    type BlockingError = std::io::Error;

    fn set_blocking(&mut self, blocking: bool) -> Result<(), Self::BlockingError> {
        self.set_nonblocking(!blocking)
    }
}
impl SetBlocking for std::boxed::Box<std::net::TcpStream> {
    type BlockingError = std::io::Error;

    fn set_blocking(&mut self, blocking: bool) -> Result<(), Self::BlockingError> {
        self.set_nonblocking(!blocking)
    }
}
impl SetBlocking for &std::net::TcpStream {
    type BlockingError = std::io::Error;

    fn set_blocking(&mut self, blocking: bool) -> Result<(), Self::BlockingError> {
        self.set_nonblocking(!blocking)
    }
}
impl SetBlocking for std::boxed::Box<&std::net::TcpStream> {
    type BlockingError = std::io::Error;

    fn set_blocking(&mut self, blocking: bool) -> Result<(), Self::BlockingError> {
        self.set_nonblocking(!blocking)
    }
}

// std::io::Read implementors that do not allow non-blocking
macro_rules! default_helper {
    ($type:ty) => {
        impl SetBlocking for $type {
            type BlockingError = std::io::Error;
        }
        impl SetBlocking for std::boxed::Box<$type> {
            type BlockingError = std::io::Error;
        }
    };
}
default_helper!(&[u8]);
default_helper!(std::fs::File);
default_helper!(&std::fs::File);
default_helper!(std::sync::Arc<std::fs::File>);
default_helper!(std::io::Stdin);
default_helper!(&std::io::Stdin);
default_helper!(std::io::StdinLock<'_>);
default_helper!(std::process::ChildStdin);
default_helper!(std::process::ChildStdout);
default_helper!(std::io::Empty);
default_helper!(std::io::Repeat);
default_helper!(std::collections::VecDeque<u8>);
impl<T: AsRef<[u8]>> SetBlocking for std::io::Cursor<T> {
    type BlockingError = std::io::Error;
}

impl<R> Reader for R
where
    R: std::io::Read + SetBlocking<BlockingError = std::io::Error>,
{
    type Error = std::io::Error;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        <Self as std::io::Read>::read_exact(self, buf)?;
        Ok(())
    }

    fn try_read_byte(&mut self) -> Result<Option<u8>, Self::Error> {
        // FIXME: Is there a better way to do this than sleeping to ensure all bytes have been sent
        // over the network? This function is only used once during the handshake.
        std::thread::sleep(Duration::from_millis(5));

        let mut buf = [0u8; 1];

        self.set_blocking(false)?;
        let result = <Self as std::io::Read>::read_exact(self, &mut buf);
        let result = result.map_or_else(
            |err| {
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(err)
                }
            },
            |_| Ok(Some(buf[0])),
        );
        self.set_blocking(true)?;
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
