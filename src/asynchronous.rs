#[cfg(feature = "tokio-io")]
mod tokio {
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use crate::traits::asynchronous::{AsyncReader, AsyncWriter};

    /// Wrapper type for types that implement tokio `AsyncRead` or `AsyncWrite`
    pub struct TokioIo<S>(pub S);

    impl<R> AsyncReader for TokioIo<R>
    where
        R: AsyncRead + Unpin,
    {
        type Error = tokio::io::Error;

        async fn async_read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
            self.0.read_exact(buf).await?;
            Ok(())
        }
    }

    impl<W> AsyncWriter for TokioIo<W>
    where
        W: AsyncWrite + Unpin,
    {
        type Error = tokio::io::Error;

        async fn async_write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.0.write_all(data).await?;
            Ok(())
        }

        async fn async_flush(&mut self) -> Result<(), Self::Error> {
            self.0.flush().await?;
            Ok(())
        }
    }
}

#[cfg(feature = "tokio-io")]
pub use crate::asynchronous::tokio::TokioIo;

#[cfg(feature = "futures-io")]
mod futures {
    use futures_io::{AsyncRead, AsyncWrite};
    use futures_util::{AsyncReadExt, AsyncWriteExt};

    use crate::traits::asynchronous::{AsyncReader, AsyncWriter};

    /// Wrapper type for types that implement futures-io `AsyncRead` or `AsyncWrite`
    pub struct FuturesIo<S>(pub S);

    impl<R> AsyncReader for FuturesIo<R>
    where
        R: AsyncRead + Unpin,
    {
        type Error = futures_io::Error;

        async fn async_read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
            self.0.read_exact(buf).await?;
            Ok(())
        }
    }

    impl<W> AsyncWriter for FuturesIo<W>
    where
        W: AsyncWrite + Unpin,
    {
        type Error = futures_io::Error;

        async fn async_write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.0.write_all(data).await?;
            Ok(())
        }

        async fn async_flush(&mut self) -> Result<(), Self::Error> {
            self.0.flush().await?;
            Ok(())
        }
    }
}

#[cfg(feature = "futures-io")]
pub use crate::asynchronous::futures::FuturesIo;
