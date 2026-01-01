#[cfg(feature = "tokio-io")]
mod tokio {
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use crate::traits::asynchronous::{AsyncReader, AsyncWriter};

    /// Wrapper type for types that implement tokio `AsyncRead` or `AsyncWrite`
    pub struct TokioIo<S>(pub S);

    impl<S> From<S> for TokioIo<S> {
        fn from(value: S) -> Self {
            TokioIo(value)
        }
    }

    impl<R> AsyncReader for TokioIo<R>
    where
        R: AsyncRead + Unpin,
    {
        type Error = tokio::io::Error;

        async fn async_read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
            self.0.read_exact(buf).await?;
            Ok(())
        }

        async fn async_try_read_byte(&mut self) -> Result<Option<u8>, Self::Error> {
            let waker = Waker::noop();
            let mut context = Context::from_waker(waker);

            let future = self.0.read_u8();
            tokio::pin!(future);

            match future.poll(&mut context) {
                Poll::Pending => Ok(None),
                Poll::Ready(result) => result.map(Some),
            }
        }

        async fn async_discard(&mut self, amount: usize) -> Result<(), Self::Error> {
            if amount != 0 {
                let amount = amount as u64;
                let mut reader = (&mut self.0).take(amount);
                let amount_discarded = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await?;
                if amount_discarded != amount {
                    return Err(tokio::io::Error::new(
                        tokio::io::ErrorKind::UnexpectedEof,
                        "EOF while discarding",
                    ));
                }
            }
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
    use futures_util::{AsyncReadExt, AsyncWriteExt, FutureExt};

    use crate::traits::asynchronous::{AsyncReader, AsyncWriter};

    /// Wrapper type for types that implement futures-io `AsyncRead` or `AsyncWrite`
    pub struct FuturesIo<S>(pub S);

    impl<S> From<S> for FuturesIo<S> {
        fn from(value: S) -> Self {
            FuturesIo(value)
        }
    }

    impl<R> AsyncReader for FuturesIo<R>
    where
        R: AsyncRead + Unpin,
    {
        type Error = futures_io::Error;

        async fn async_read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
            self.0.read_exact(buf).await?;
            Ok(())
        }

        async fn async_try_read_byte(&mut self) -> Result<Option<u8>, Self::Error> {
            let mut buf = [0u8];
            match self.0.read_exact(&mut buf).now_or_never() {
                Some(result) => {
                    result?;
                    Ok(Some(buf[0]))
                }
                None => Ok(None),
            }
        }

        async fn async_discard(&mut self, amount: usize) -> Result<(), Self::Error> {
            if amount != 0 {
                let amount = amount as u64;
                let mut reader = (&mut self.0).take(amount);
                let amount_discarded =
                    futures_util::io::copy(&mut reader, &mut futures_util::io::sink()).await?;
                if amount_discarded != amount {
                    return Err(futures_io::Error::new(
                        futures_io::ErrorKind::UnexpectedEof,
                        "EOF while discarding",
                    ));
                }
            }
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
