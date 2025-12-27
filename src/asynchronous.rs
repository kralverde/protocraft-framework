#[cfg(feature = "tokio-io")]
mod tokio {
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use crate::traits::asynchronous::{AsyncReader, AsyncWriter};

    impl<R> AsyncReader for R
    where
        R: AsyncRead + Unpin,
    {
        type Error = tokio::io::Error;

        async fn async_read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
            self.read_exact(buf).await?;
            Ok(())
        }
    }

    impl<W> AsyncWriter for W
    where
        W: AsyncWrite + Unpin,
    {
        type Error = tokio::io::Error;

        async fn async_write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.write_all(data).await?;
            Ok(())
        }

        async fn async_flush(&mut self) -> Result<(), Self::Error> {
            self.flush().await?;
            Ok(())
        }
    }
}

// TODO: futures-io, embassy
