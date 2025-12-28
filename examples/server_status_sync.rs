use std::{
    net::{TcpListener, TcpStream},
    thread,
};

use protocraft_framework::{
    defaults::sync::DefaultStreamProvider,
    error::{ReadError, WriteError},
    primatives::varint::VarInt,
    protocol::{versions::v1_21_10, Handshake, LegacyPingResponse},
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

                    if intent == 1 {
                        Some(true)
                    } else {
                        Some(false)
                    }
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
                            if payload.len() > i16::MAX as usize {
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
                            &StatusPacket::new("{\"version\":{\"name\":\"1.21.10\",\"protocol\":773},\"players\":{\"max\":0,\"online\":0,\"sample\":[]},\"description\":{\"text\":\"Hello, world!\"},\"favicon\":\"data:image/png;base64,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\",\"enforcesSecureChat\":false}")
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
                    if payload.len() > i16::MAX as usize {
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
        let response = LegacyPingResponse::new("1.21.10", "Wow! You're an old client!", "0", "0")
            .expect("The packet payload is too big!");
        handler
            .write_legacy_ping_response(&response)
            .map_err(Error::Write)?;
    }

    Ok(())
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:25565").expect("Failed to create listener");
    println!("Listening on port 25565");

    loop {
        let (stream, socket) = listener.accept().expect("Failed to accept connection");
        println!("Accepted connection: {}", socket);

        // Inefficient, but shows can be delegated to a seperate thread
        thread::spawn(move || handle_connection(stream));
    }
}
