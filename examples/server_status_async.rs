use protocraft_framework::{
    defaults::asynchronous::tokio::AsyncDefaultStreamProvider,
    error::{ReadError, WriteError},
    primatives::varint::VarInt,
    protocol::{Handshake, versions::v1_21_10},
    traits::asynchronous::{AsyncBoundedReader, AsyncFromReader, AsyncProtocolStateHandler},
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
            reader: R,
        ) -> Result<(R, Self::Result), ReadError<R::Error>>
        where
            R: AsyncBoundedReader,
        {
            let result = match designator {
                Handshake::Standard => {
                    let (reader, _version) = VarInt::async_from_reader(reader).await?;
                    let (mut reader, string_length) = VarInt::async_from_reader(reader).await?;
                    let string_length: i32 = string_length.into();
                    if string_length < 0 {
                        return Err(ReadError::NegativeLength {
                            name: "handshake_address",
                        });
                    }
                    reader
                        .async_discard(string_length as usize + 2)
                        .await
                        .map_err(ReadError::StreamError)?;

                    let (reader, intent) = VarInt::async_from_reader(reader).await?;
                    let intent: i32 = intent.into();
                    if intent <= 0 || intent > 3 {
                        return Err(ReadError::BadEnum {
                            name: "intent",
                            value: intent,
                        });
                    }

                    let result = if intent == 1 { Some(true) } else { Some(false) };
                    (reader, result)
                }
                Handshake::Legacy => (reader, None),
            };
            Ok(result)
        }
    }

    let result = handler.async_read_handshake::<HandshakeHandler>().await;
    println!("{:?}", result);
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:25565")
        .await
        .expect("Failed to create listener");
    println!("Connect to port 25565 to see the handshake packet!");

    loop {
        let (stream, socket) = listener
            .accept()
            .await
            .expect("Failed to accept connection");
        println!("Accepted connection: {}", socket);

        tokio::spawn(handle_connection(stream));
    }
}
