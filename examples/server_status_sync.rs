use std::{
    net::{TcpListener, TcpStream},
    thread,
};

use protocraft_framework::{
    defaults::sync::DefaultStreamProvider,
    error::{ReadError, WriteError},
    primatives::varint::VarInt,
    protocol::{Handshake, versions::v1_21_10},
    traits::{FromReader, ProtocolStateHandler, Serializable, ToWriter, Writer},
};

#[allow(unused)]
#[derive(Debug)]
enum Error {
    Read(ReadError<std::io::Error>),
    Write(WriteError<std::io::Error>),
}

fn handle_connection(stream: TcpStream) {
    if let Err(err) = handle_connection_with_errors(stream) {
        println!("Error: {:?}", err);
    }
}

fn handle_connection_with_errors(stream: TcpStream) -> Result<(), Error> {
    let cloned = stream.try_clone().expect("Stream clone failed");
    let provider = DefaultStreamProvider::new(stream, cloned);
    let mut handler = v1_21_10::new_serverside(provider);

    // This is a handler that returns `Some(true)` if the client wants the status, `Some(false)` if
    // the client wants to login, and `None` if it is a legacy ping.
    enum HandshakeHandler {}
    impl ProtocolStateHandler for HandshakeHandler {
        type PacketDesignator = Handshake;
        type Result = Option<bool>;

        fn handle_packet<R>(
            designator: Self::PacketDesignator,
            reader: &mut R,
        ) -> Result<Self::Result, protocraft_framework::error::ReadError<R::Error>>
        where
            R: protocraft_framework::traits::BoundedReader,
        {
            let result = match designator {
                Handshake::Standard => {
                    let _version: i32 = VarInt::from_reader(reader)?.into();
                    let string_length: i32 = VarInt::from_reader(reader)?.into();
                    if string_length < 0 {
                        return Err(ReadError::NegativeLength {
                            name: "handshake_address",
                        });
                    }
                    reader
                        .discard(string_length as usize + 2)
                        .map_err(ReadError::StreamError)?;

                    let intent: i32 = VarInt::from_reader(reader)?.into();
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
        .read_handshake::<HandshakeHandler>()
        .map_err(Error::Read)?
    {
        if is_status {
            let mut handler = handler.into_status_state();

            // This is a handler that returns `Some(i64)` for a ping and `None` for a status
            // request
            enum StatusHandler {}
            impl ProtocolStateHandler for StatusHandler {
                type PacketDesignator = v1_21_10::ServerboundStatusPacket;
                type Result = Option<i64>;

                fn handle_packet<R>(
                    designator: Self::PacketDesignator,
                    reader: &mut R,
                ) -> Result<Self::Result, ReadError<R::Error>>
                where
                    R: protocraft_framework::traits::BoundedReader,
                {
                    let result = match designator {
                        v1_21_10::ServerboundStatusPacket::StatusRequest => None,
                        v1_21_10::ServerboundStatusPacket::Ping => Some(i64::from_reader(reader)?),
                    };

                    Ok(result)
                }
            }

            loop {
                if let Some(timestamp) = handler
                    .read_packet::<StatusHandler>()
                    .map_err(Error::Read)?
                {
                    struct Pong(i64);
                    impl Serializable for Pong {
                        fn size(&self) -> usize {
                            self.0.size()
                        }
                    }
                    impl ToWriter for Pong {
                        fn to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
                        where
                            W: Writer,
                        {
                            self.0.to_writer(writer)
                        }
                    }

                    handler
                        .write_packet(v1_21_10::ClientboundStatusPacket::Pong, &Pong(timestamp))
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
                    impl ToWriter for StatusPacket<'_> {
                        fn to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
                        where
                            W: Writer,
                        {
                            VarInt::from(self.0.len() as i32).to_writer(writer)?;
                            writer
                                .write(self.0.as_bytes())
                                .map_err(WriteError::StreamError)?;
                            Ok(())
                        }
                    }
                    handler
                        .write_packet(v1_21_10::ClientboundStatusPacket::StatusResponse,
                            &StatusPacket::new("{\"version\":{\"name\":\"1.21.10\",\"protocol\":773},\"description\":{\"text\":\"Hello, world!\"}}")
                                .expect("The message is too long!"),
                        )
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
            impl ToWriter for KickPacket {
                fn to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
                where
                    W: Writer,
                {
                    VarInt::from(self.0.len() as i32).to_writer(writer)?;
                    writer
                        .write(self.0.as_bytes())
                        .map_err(WriteError::StreamError)?;
                    Ok(())
                }
            }

            handler
                .write_packet(
                    v1_21_10::ClientboundLoginPacket::Disconnect,
                    &KickPacket::new("We haven't actually implemented the server!")
                        .expect("The message is too long!"),
                )
                .map_err(Error::Write)?;
        }
    } else {
        println!("Got legacy ping");
        // TODO: Legacy disconnect
    }

    Ok(())
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:25565").expect("Failed to create listener");
    println!("Listening on port 25565");

    loop {
        let (stream, socket) = listener.accept().expect("Failed to accept connection");
        println!("Accepted connection: {}", socket);

        thread::spawn(move || handle_connection(stream));
    }
}
