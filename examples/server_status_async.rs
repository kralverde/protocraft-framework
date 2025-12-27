use protocraft_framework::{
    defaults::asynchronous::tokio::AsyncDefaultStreamProvider,
    error::{ReadError, WriteError},
    primatives::varint::VarInt,
    protocol::{Handshake, versions::v1_21_10},
    traits::{
        Serializable,
        asynchronous::{
            AsyncBoundedReader, AsyncFromReader, AsyncProtocolStateHandler, AsyncToWriter,
            AsyncWriter,
        },
    },
};
use tokio::net::{TcpListener, TcpStream};

#[allow(unused)]
#[derive(Debug)]
enum Error {
    Read(ReadError<tokio::io::Error>),
    Write(WriteError<tokio::io::Error>),
}

async fn handle_connection(stream: TcpStream) {
    if let Err(err) = handle_connection_with_errors(stream).await {
        println!("Error: {:?}", err);
    }
}

async fn handle_connection_with_errors(stream: TcpStream) -> Result<(), Error> {
    let (reader, writer) = stream.into_split();
    let provider = AsyncDefaultStreamProvider::new(reader, writer);
    let mut handler = v1_21_10::new_serverside(provider);

    // This is a handler that returns `Some(true)` if the client wants the status, `Some(false)` if
    // the client wants to login, and `None` if it is a legacy ping.
    enum HandshakeHandler {}
    impl AsyncProtocolStateHandler for HandshakeHandler {
        type PacketDesignator = Handshake;
        type Result = Option<bool>;

        async fn async_handle_packet<R>(
            designator: Self::PacketDesignator,
            reader: &mut R,
        ) -> Result<Self::Result, ReadError<R::Error>>
        where
            R: AsyncBoundedReader,
        {
            let result = match designator {
                Handshake::Standard => {
                    let _version = VarInt::async_from_reader(reader).await?;
                    let string_length: i32 = VarInt::async_from_reader(reader).await?.into();
                    if string_length < 0 {
                        return Err(ReadError::NegativeLength {
                            name: "handshake_address",
                        });
                    }
                    reader
                        .async_discard(string_length as usize + 2)
                        .await
                        .map_err(ReadError::StreamError)?;

                    let intent: i32 = VarInt::async_from_reader(reader).await?.into();
                    if intent <= 0 || intent > 3 {
                        return Err(ReadError::BadEnum {
                            name: "intent",
                            value: intent,
                        });
                    }

                    if intent == 1 { Some(true) } else { Some(false) }
                }
                Handshake::Legacy => None,
            };
            Ok(result)
        }
    }

    if let Some(is_status) = handler
        .async_read_handshake::<HandshakeHandler>()
        .await
        .map_err(Error::Read)?
    {
        if is_status {
            let mut handler = handler.into_status_state();

            // This is a handler that returns `Some(i64)` for a ping and `None` for a status
            // request
            enum StatusHandler {}
            impl AsyncProtocolStateHandler for StatusHandler {
                type PacketDesignator = v1_21_10::ServerboundStatusPacket;
                type Result = Option<i64>;

                async fn async_handle_packet<R>(
                    designator: Self::PacketDesignator,
                    reader: &mut R,
                ) -> Result<Self::Result, ReadError<R::Error>>
                where
                    R: AsyncBoundedReader,
                {
                    let result = match designator {
                        v1_21_10::ServerboundStatusPacket::StatusRequest => None,
                        v1_21_10::ServerboundStatusPacket::Ping => {
                            Some(i64::async_from_reader(reader).await?)
                        }
                    };

                    Ok(result)
                }
            }

            loop {
                if let Some(timestamp) = handler
                    .async_read_packet::<StatusHandler>()
                    .await
                    .map_err(Error::Read)?
                {
                    struct Pong(i64);
                    impl Serializable for Pong {
                        fn size(&self) -> usize {
                            self.0.size()
                        }
                    }
                    impl AsyncToWriter for Pong {
                        async fn async_to_writer<W>(
                            &self,
                            writer: &mut W,
                        ) -> Result<(), WriteError<W::Error>>
                        where
                            W: AsyncWriter,
                        {
                            self.0.async_to_writer(writer).await
                        }
                    }

                    handler
                        .async_write_packet(
                            v1_21_10::ClientboundStatusPacket::Pong,
                            &Pong(timestamp),
                        )
                        .await
                        .map_err(Error::Write)?;
                } else {
                    struct StatusPacket<'a>(&'a str);
                    impl<'a> StatusPacket<'a> {
                        fn new(payload: &'a str) -> Option<Self> {
                            if payload.len() > i32::MAX as usize {
                                None
                            } else {
                                Some(Self(payload))
                            }
                        }
                    }
                    impl Serializable for StatusPacket<'_> {
                        fn size(&self) -> usize {
                            VarInt::from(self.0.len() as i32).size() + self.0.len()
                        }
                    }
                    impl AsyncToWriter for StatusPacket<'_> {
                        async fn async_to_writer<W>(
                            &self,
                            writer: &mut W,
                        ) -> Result<(), WriteError<W::Error>>
                        where
                            W: AsyncWriter,
                        {
                            VarInt::from(self.0.len() as i32)
                                .async_to_writer(writer)
                                .await?;
                            writer
                                .async_write(self.0.as_bytes())
                                .await
                                .map_err(WriteError::StreamError)?;
                            Ok(())
                        }
                    }
                    handler
                        .async_write_packet(v1_21_10::ClientboundStatusPacket::StatusResponse,
                            &StatusPacket::new("{\"version\":{\"name\":\"1.21.10\",\"protocol\":773},\"description\":{\"text\":\"Hello, world!\"}}")
                                .expect("The message is too long!"),
                        ).await
                        .map_err(Error::Write)?;
                }
            }
        } else {
            let mut handler = handler.into_login_state();

            struct KickPacket(String);
            impl KickPacket {
                fn new(reason: &str) -> Option<Self> {
                    let payload = format!("{{\"text\":\"{}\"}}", reason);
                    if payload.len() > i32::MAX as usize {
                        None
                    } else {
                        Some(Self(payload))
                    }
                }
            }
            impl Serializable for KickPacket {
                fn size(&self) -> usize {
                    VarInt::from(self.0.len() as i32).size() + self.0.len()
                }
            }
            impl AsyncToWriter for KickPacket {
                async fn async_to_writer<W>(
                    &self,
                    writer: &mut W,
                ) -> Result<(), WriteError<W::Error>>
                where
                    W: AsyncWriter,
                {
                    VarInt::from(self.0.len() as i32)
                        .async_to_writer(writer)
                        .await?;
                    writer
                        .async_write(self.0.as_bytes())
                        .await
                        .map_err(WriteError::StreamError)?;
                    Ok(())
                }
            }

            handler
                .async_write_packet(
                    v1_21_10::ClientboundLoginPacket::Disconnect,
                    &KickPacket::new("We haven't actually implemented the server!")
                        .expect("The message is too long!"),
                )
                .await
                .map_err(Error::Write)?;
        }
    } else {
        println!("Got legacy ping");
        // TODO: Legacy disconnect
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:25565")
        .await
        .expect("Failed to create listener");
    println!("Listening on port 25565");

    loop {
        let (stream, socket) = listener
            .accept()
            .await
            .expect("Failed to accept connection");
        println!("Accepted connection: {}", socket);

        tokio::spawn(handle_connection(stream));
    }
}
