use std::net::TcpListener;

use protocraft_framework::{
    defaults::{Compression, sync::DefaultStreamProvider},
    error::{ReadError, WriteError},
    primatives::varint::VarInt,
    protocol::{Handshake, versions::v1_7_10},
    traits::{BoundedReader, FromReader, ProtocolStateHandler, Serializable, ToWriter, Writer},
};

// This is what we will be passing by type later on.
enum HandshakeHandler {}

// Here we implement `ProtocolStateHandler` for `HandshakeHandler`. A `ProtocolStateHandler`
// defines a `PacketDesignator` or "what kind of packets can we receive" and a `Result` or the
// output of the handler. `PacketDesignator`'s are enums representing all of the valid packets
// for a certain protocol state and whether it is clientbound or serverbound.
//
// `Handshake` is the `PacketDesignator` for all versions of Minecraft and is the starting spot for
// the protocol. In order to handle other kinds of packets, you need to implement a
// `ProtocolStateHandler` whose `PacketDesignator` is the collection of packets avaliable for that
// state. Most modern Minecraft versions have four states: Handshake, Status, Login, and Play.
// More modern versions have another Config state.
//
// For instance, If I want to handle server bound packets for Minecraft version 1.10.1 in the
// Login state, my `ProtocolStateHandler` needs to have
// `type PacketDesignator = protocraft_framework::protocol::v1_10_1::ServerboundLoginPacket`.
impl ProtocolStateHandler for HandshakeHandler {
    type PacketDesignator = Handshake;
    type Result = String;

    fn handle_packet<R>(
        designator: Self::PacketDesignator,
        // For modern minecraft packets, the reader contains all of the data in the packet. The
        // reader is effectively a byte stream and you must choose how to enterpret it based on the
        // `PacketDesignator` type. With the reader you can fill buffers, discard bytes, query how
        // may bytes remain on the reader, and pass it into types that implement `FromReader`. You
        // can even ignore the reader will no side effects! The library backend will clean up the
        // extra data for you. Compression and encryption will also be handled by this point, so
        // you only need to handle the raw data.
        //
        // The base primatives and `VarInt` implement `FromReader` out of the box, but you can and
        // should implement it for more complex shared sub-packet structures.
        // (See https://minecraft.wiki/w/Java_Edition_protocol/Packets#Definitions)
        reader: &mut R,
    ) -> Result<Self::Result, ReadError<R::Error>>
    where
        R: BoundedReader,
    {
        Ok(match designator {
            Handshake::Standard => {
                // This is a modern Minecraft Client!
                let remaining = reader.remaining();

                // See https://minecraft.wiki/w/Java_Edition_protocol/Packets#Handshake for more
                // information.
                let protocol_version: i32 = VarInt::from_reader(reader)?.into();
                let hostname_length: i32 = VarInt::from_reader(reader)?.into();
                if hostname_length < 0 {
                    return Err(ReadError::NegativeLength {
                        name: "hostname_length",
                    });
                }
                let hostname_length = hostname_length as usize;
                let mut buf = vec![0u8; hostname_length];
                reader.read_exact(&mut buf)?;
                let hostname = String::from_utf8(buf).map_err(|_| ReadError::StringDecode {
                    name: "Failed to decode utf8",
                })?;
                let port = u16::from_reader(reader)?;
                let intent: i32 = VarInt::from_reader(reader)?.into();

                format!(
                    "A minecraft client from version 1.7+ using protocol version {} connected to {}:{} (thats us!) with this intention: {}. There were {} bytes in this packet.",
                    protocol_version, hostname, port, intent, remaining
                )
            }
            Handshake::Legacy1_6 => {
                // This is a Minecraft version 1.6 Client!
                // See https://minecraft.wiki/w/Java_Edition_protocol/Server_List_Ping#1.6 for more
                // information.
                let protocol_version = u8::from_reader(reader)?;
                let hostname_length = u16::from_reader(reader)?;

                // Collect utf16 code units
                let mut buf = Vec::with_capacity(hostname_length as usize);
                for _ in 0..hostname_length {
                    let codeunit = u16::from_reader(reader)?;
                    buf.push(codeunit);
                }
                let hostname = String::from_utf16(&buf).map_err(|_| ReadError::StringDecode {
                    name: "Failed to decode utf16",
                })?;

                let port = i32::from_reader(reader)?;
                format!(
                    "A minecraft client from version 1.6 using protocol version {} connected to {}:{} (thats us!)",
                    protocol_version, hostname, port
                )
            }
            Handshake::Legacy1_5 => {
                "A minecraft client from version 1.4 or 1.5 sent a handshake!".into()
            }
            Handshake::Legacy1_3 => {
                "A minecraft client from before version 1.4 sent a handshake!".into()
            }
        })
    }
}

fn main() {
    // Create a local server listening on port 25565.
    let listener = TcpListener::bind("127.0.0.1:25565").expect("Failed to create a TCP listener");
    let (stream, _addr) = listener.accept().expect("Failed to accept new connection");

    // Create a stream provider using the `DefaultStreamProvider`. You should use the
    // `DefaultStreamProvider` unless you have a good reason not to. (Maybe you want to go ham and
    // write a Minecraft server for a embedded chip).
    let stream_provider =
        DefaultStreamProvider::new(&stream, &stream, Compression::default(), 4096);

    // Here we create a new serverside handler for protocol version 1.7.10 (We can also create a
    // clientside handler with `new_clientside` if you want to make a Minecraft client). This
    // initializes a ProtocolHandler in the Handshake state and we can call `read_handshake` with
    // our `HandshakeHandler` we defined above. While we are using protocol version 1.7.10, the
    // handshake and status states have remained unchanged and this example will work with any
    // version.
    let mut handler = v1_7_10::new_serverside(stream_provider);
    let result = handler
        .read_handshake::<HandshakeHandler>()
        .expect("Failed to read the handshake!");
    println!("{}", result);

    // Now lets assume a modern client connected that wants to go into the status state. Our
    // handler has `into_xxx_state` functions that convert the handler into a next legal state.
    let mut handler = handler.into_status_state();

    // Now we need to define a `ProtocolStateHandler` for the status state. There are only two
    // packets in the status state, only one of which has information, so I will represent them as
    // `Option<i64>`.
    enum MyStatusStateHandler {}
    impl ProtocolStateHandler for MyStatusStateHandler {
        // We now need to handle serverbound status packets.
        type PacketDesignator = v1_7_10::ServerboundStatusPacket;
        type Result = Option<i64>;

        fn handle_packet<R>(
            designator: Self::PacketDesignator,
            reader: &mut R,
        ) -> Result<Self::Result, ReadError<R::Error>>
        where
            R: BoundedReader,
        {
            Ok(match designator {
                // The status request packet has no associated data, so we just return `None`
                v1_7_10::ServerboundStatusPacket::Request => None,
                // the ping packet has an `i64` timestamp, so we'll return that.
                v1_7_10::ServerboundStatusPacket::Ping => {
                    let timestamp = i64::from_reader(reader)?;
                    Some(timestamp)
                }
            })
        }
    }

    let result = handler
        .read_packet::<MyStatusStateHandler>()
        .expect("Failed to read the packet!");

    println!("The result of our status state handler was: {:?}", result);
    assert_eq!(
        result, None,
        "Oops, this should have been a StatusRequest packet..."
    );

    // Lets respond! We need a type that implements `Serializable` and `ToWriter`.
    // We'll use https://minecraft.wiki/w/Java_Edition_protocol/Packets#Status_Response
    // as a reference for this packet.
    struct MyStatusResponse<'a>(&'a str);
    impl Serializable for MyStatusResponse<'_> {
        // This is how may bytes will be written to the stream.
        fn size(&self) -> usize {
            let length_prefix = VarInt::from(self.0.len() as i32).size();
            length_prefix + self.0.len()
        }
    }
    impl ToWriter for MyStatusResponse<'_> {
        // This is where the actual writing happens. The writer can write u8 slices and can be
        // passed to other implementors of `ToWriter`. Compression and encryption will be handled
        // for you, so just write the raw data here.
        fn to_writer<W>(&self, writer: &mut W) -> Result<(), WriteError<W::Error>>
        where
            W: Writer,
        {
            VarInt::from(self.0.len() as i32).to_writer(writer)?;
            writer.write(self.0.as_bytes())?;
            Ok(())
        }
    }

    let example_response = "{
    \"version\": {
        \"name\": \"1.21.8\",
        \"protocol\": 772
    },
    \"players\": {
        \"max\": 20,
        \"online\": 1,
        \"sample\": [
            {
                \"name\": \"thinkofdeath\",
                \"id\": \"4566e69f-c907-48ee-8d71-d7ba5aa00d20\"
            }
        ]
    },
    \"description\": {
        \"text\": \"Hello, world!\"
    },
    \"enforcesSecureChat\": false
}";

    // We need to tell the handler what type of packet `MyStatusResponse` is. You can only select
    // packets that are valid for the handler's state.
    handler
        .write_packet(
            v1_7_10::ClientboundStatusPacket::Response,
            &MyStatusResponse(example_response),
        )
        .expect("Failed to write the packet!");

    // You should now see a response on the Minecraft client!
    println!("All Done");
}
