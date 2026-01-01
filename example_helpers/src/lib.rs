use crab_nbt::nbt;
use pkcs8::EncodePublicKey;
use protocraft_framework::{
    error::{ReadError, WriteError},
    primatives::varint::VarInt,
    protocol::{Handshake, Legacy1_3PingResponse, Legacy1_6PingResponse, versions::v1_21_10},
    traits::{
        BoundedReader, EncryptableStreamProvider, FromReader, ProtocolStateHandler,
        ReadStreamProvider, Serializable, ToWriter, WriteStreamProvider, Writer,
    },
};
use rand::Rng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use uuid::Uuid;

#[cfg(feature = "async")]
use protocraft_framework::traits::asynchronous::{
    AsyncBoundedReader, AsyncFromReader, AsyncProtocolStateHandler, AsyncReadStreamProvider,
    AsyncToWriter, AsyncWriteStreamProvider, AsyncWriter,
};

// A bare-bones server for examples

#[allow(unused)]
#[derive(Debug)]
pub enum Error<R, W> {
    Read(ReadError<R>),
    Write(WriteError<W>),
}

#[derive(Debug)]
enum HandshakeResult {
    Legacy(bool),
    Standard(bool),
}

macro_rules! sync_and_async_helper {
    ($func:tt) => {
        pub fn handle_connection_with_errors<P>(
            provider: P,
        ) -> Result<(), Error<<P as ReadStreamProvider>::Error, <P as WriteStreamProvider>::Error>>
        where
            P: ReadStreamProvider + WriteStreamProvider + EncryptableStreamProvider,
        {
            macro_rules! handler {
                () => (v1_21_10::new_serverside(provider));
            }

            macro_rules! read {
                ($reader:ident => $type:ty) => (<$type as FromReader>::from_reader($reader)?);
            }

            macro_rules! read_bytes {
                ($reader:ident($count:literal)) => {{
                    let mut buf = [0u8; $count];
                    $reader.read_exact(&mut buf).map_err(ReadError::StreamError)?;
                    buf
                }};
                ($reader:ident($count:expr)) => {{
                    let mut buf = vec![0u8; $count];
                    $reader.read_exact(&mut buf).map_err(ReadError::StreamError)?;
                    buf
                }};
            }

            macro_rules! write {
                ($type:ident($value:expr) => $writer:ident) => (<$type as ToWriter>::to_writer(&$value, $writer)?);
            }

            macro_rules! write_bytes {
                ($bytes:expr => $writer:ident) => ($writer.write($bytes).map_err(WriteError::StreamError)?)
            }

            macro_rules! discard {
                ($reader:ident($count:expr)) => {
                    $reader.discard($count).map_err(ReadError::StreamError)?
                };
            }

            macro_rules! state_handler {
                ($name:ident($in:path=>$out:path) ($designator:ident, $reader:ident)$handler_func:tt) => {
                    enum $name {}
                    impl ProtocolStateHandler for $name {
                        type PacketDesignator = $in;
                        type Result = $out;

                        fn handle_packet<R>(
                            $designator: Self::PacketDesignator,
                            $reader: &mut R,
                        ) -> Result<Self::Result, ReadError<R::Error>>
                        where
                            R: BoundedReader,
                        {
                            $handler_func
                        }
                    }
                };
            }

            macro_rules! read_handshake {
                ($handler:ident, $state_handler:ident) => {
                    $handler
                        .read_handshake::<$state_handler>()
                        .map_err(Error::Read)?
                }
            }

            macro_rules! read_packet {
                ($handler:ident, $state_handler:ident) => {
                    $handler
                        .read_packet::<$state_handler>()
                        .map_err(Error::Read)?
                }
            }

            macro_rules! try_read_packet {
                ($handler:ident, $state_handler:ident) => {
                    $handler
                        .read_packet::<$state_handler>()
                }
            }

            macro_rules! write_packet {
                ($handler:ident, $packet_type:path, $packet:ident) => {
                    $handler
                        .write_packet($packet_type, &$packet)
                        .map_err(Error::Write)?
                }
            }

            macro_rules! write_legacy_1_3 {
                ($handler:ident, $motd:literal) => {
                    let response = Legacy1_3PingResponse::new(
                        $motd,
                        "1",
                        "1",
                    )
                    .expect("The packet payload is too big!");

                    $handler
                        .write_legacy_1_3_ping_response(&response)
                        .map_err(Error::Write)?;
                }
            }

            macro_rules! write_legacy_1_6 {
                ($handler:ident, $version:literal, $motd:literal) => {
                    let response = Legacy1_6PingResponse::new(
                        $version,
                        $motd,
                        "0",
                        "0",
                    )
                    .expect("The packet payload is too big!");

                    $handler
                        .write_legacy_1_6_ping_response(&response)
                        .map_err(Error::Write)?;
                }
            }

            macro_rules! to_writer {
                ($type:path => ($this:ident,$writer:ident) $write_func:tt) => {
                    impl ToWriter for $type {
                        fn to_writer<W>(
                            &self,
                            $writer: &mut W,
                        ) -> Result<(), WriteError<W::Error>>
                        where
                            W: Writer,
                        {
                            let $this = self;
                            $write_func
                        }
                    }
                }
            }

            $func
        }

        #[cfg(feature = "async")]
        pub async fn async_handle_connection_with_errors<P>(
            provider: P,
        ) -> Result<(), Error<<P as AsyncReadStreamProvider>::Error, <P as AsyncWriteStreamProvider>::Error>>
        where
            P: AsyncReadStreamProvider + AsyncWriteStreamProvider + EncryptableStreamProvider,
        {
            macro_rules! handler {
                () => (v1_21_10::new_serverside(provider));
            }

            macro_rules! read {
                ($reader:ident => $type:ty) => (<$type as AsyncFromReader>::async_from_reader($reader).await?);
            }

            macro_rules! read_bytes {
                ($reader:ident($count:literal)) => {{
                    let mut buf = [0u8; $count];
                    $reader.async_read_exact(&mut buf).await.map_err(ReadError::StreamError)?;
                    buf
                }};
                ($reader:ident($count:expr)) => {{
                    let mut buf = vec![0u8; $count];
                    $reader.async_read_exact(&mut buf).await.map_err(ReadError::StreamError)?;
                    buf
                }};
            }

            macro_rules! write {
                ($type:ident($value:expr) => $writer:ident) => (<$type as AsyncToWriter>::async_to_writer(&$value, $writer).await?);
            }

            macro_rules! write_bytes {
                ($bytes:expr => $writer:ident) => ($writer.async_write($bytes).await.map_err(WriteError::StreamError)?)
            }

            macro_rules! discard {
                ($reader:ident($count:expr)) => {
                    $reader.async_discard($count).await.map_err(ReadError::StreamError)?
                };
            }

            macro_rules! state_handler {
                ($name:ident($in:path=>$out:path) ($designator:ident, $reader:ident)$handler_func:tt) => {
                    enum $name {}
                    impl AsyncProtocolStateHandler for $name {
                        type PacketDesignator = $in;
                        type Result = $out;

                        async fn async_handle_packet<R>(
                            $designator: Self::PacketDesignator,
                            $reader: &mut R,
                        ) -> Result<Self::Result, ReadError<R::Error>>
                        where
                            R: AsyncBoundedReader,
                        $handler_func
                    }
                };
            }

            macro_rules! read_handshake {
                ($handler:ident, $state_handler:ident) => {
                    $handler
                        .async_read_handshake::<$state_handler>()
                        .await.map_err(Error::Read)?
                }
            }

            macro_rules! read_packet {
                ($handler:ident, $state_handler:ident) => {
                    $handler
                        .async_read_packet::<$state_handler>()
                        .await.map_err(Error::Read)?
                }
            }

            macro_rules! try_read_packet {
                ($handler:ident, $state_handler:ident) => {
                    $handler
                        .async_read_packet::<$state_handler>()
                        .await
                }
            }

            macro_rules! write_packet {
                ($handler:ident, $packet_type:path, $packet:ident) => {
                    $handler
                        .async_write_packet($packet_type, &$packet)
                        .await.map_err(Error::Write)?
                }
            }

            macro_rules! write_legacy_1_3 {
                ($handler:ident, $motd:literal) => {
                    let response = Legacy1_3PingResponse::new(
                        $motd,
                        "1",
                        "1",
                    )
                    .expect("The packet payload is too big!");

                    $handler
                        .async_write_legacy_1_3_ping_response(&response)
                        .await.map_err(Error::Write)?;
                }
            }

            macro_rules! write_legacy_1_6 {
                ($handler:ident, $version:literal, $motd:literal) => {
                    let response = Legacy1_6PingResponse::new(
                        $version,
                        $motd,
                        "0",
                        "0",
                    )
                    .expect("The packet payload is too big!");

                    $handler
                        .async_write_legacy_1_6_ping_response(&response)
                        .await.map_err(Error::Write)?;
                }
            }

            macro_rules! to_writer {
                ($type:path => ($this:ident,$writer:ident) $write_func:tt) => {
                    impl AsyncToWriter for $type {
                        async fn async_to_writer<W>(
                            &self,
                            $writer: &mut W,
                        ) -> Result<(), WriteError<W::Error>>
                        where
                            W: AsyncWriter,
                        {
                            let $this = self;
                            let result = $write_func;
                            result
                        }
                    }
                }
            }

            $func
        }
    };
}

sync_and_async_helper!({
    let mut handler = handler!();

    // This is a handler that returns `Standard(true)` if the client wants the status or `Standard(false)` if
    // the client wants to login, and `Legacy(false)` if it is a >=1.4 legacy ping or `Legacy(true)`
    // if it is a <=1.3 legacy ping.

    state_handler!(HandshakeHandler(Handshake => HandshakeResult) (designator, reader){
        let result = match designator {
            Handshake::Standard => {
                let _version = read!(reader => VarInt);
                let string_length: i32 = read!(reader => VarInt).into();
                if string_length < 0 {
                    return Err(ReadError::NegativeLength {
                        name: "handshake_address",
                    });
                }

                discard!(reader(string_length as usize + 2));

                let intent: i32 = read!(reader => VarInt).into();
                if intent <= 0 || intent > 3 {
                    return Err(ReadError::BadEnum {
                        name: "intent",
                        value: intent,
                    });
                }

                let is_status = intent == 1;
                HandshakeResult::Standard(is_status)
            }
            Handshake::Legacy1_5 | Handshake::Legacy1_6 => HandshakeResult::Legacy(false),
            Handshake::Legacy1_3 => HandshakeResult::Legacy(true),
        };
        Ok(result)
    });

    match read_handshake!(handler, HandshakeHandler) {
        HandshakeResult::Standard(is_status) => {
            if is_status {
                let mut handler = handler.into_status_state();

                // This is a handler that returns `Some(i64)` for a ping and `None` for a status
                // request

                state_handler!(StatusHandler(v1_21_10::ServerboundStatusPacket => Option<i64>) (designator, reader){
                    let result = match designator {
                        v1_21_10::ServerboundStatusPacket::StatusRequest => None,
                        v1_21_10::ServerboundStatusPacket::Ping => Some(read!(reader => i64))
                    };

                    Ok(result)
                });

                if read_packet!(handler, StatusHandler).is_some() {
                    // Close the stream; we expect a status request first.
                    return Ok(());
                };

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
                to_writer!(StatusPacket<'_> => (this, writer){
                    let length = VarInt::from(this.0.len() as i32);
                    write!(VarInt(length) => writer);
                    write_bytes!(this.0.as_bytes() => writer);
                    Ok(())
                });

                let packet = StatusPacket::new("{\"version\":{\"name\":\"1.21.10\",\"protocol\":773},\"players\":{\"max\":0,\"online\":0,\"sample\":[]},\"description\":{\"text\":\"Hello, world!\"},\"favicon\":\"data:image/png;base64,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\",\"enforcesSecureChat\":false}")
                                .expect("The message is too long!");
                write_packet!(
                    handler,
                    v1_21_10::ClientboundStatusPacket::StatusResponse,
                    packet
                );

                let Some(timestamp) = read_packet!(handler, StatusHandler) else {
                    // Close the stream; we expected a ping now.
                    return Ok(());
                };

                struct Pong(i64);
                impl Serializable for Pong {
                    fn size(&self) -> usize {
                        self.0.size()
                    }
                }
                to_writer!(Pong => (this, writer){
                    write!(i64(this.0) => writer);
                    Ok(())
                });

                let packet = Pong(timestamp);
                write_packet!(handler, v1_21_10::ClientboundStatusPacket::Pong, packet);

                // The client should disconnect at this point.
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
                to_writer!(KickPacket => (this, writer){
                    let length = VarInt::from(this.0.len() as i32);
                    write!(VarInt(length) => writer);
                    write_bytes!(this.0.as_bytes() => writer);
                    Ok(())
                });

                macro_rules! kick {
                    ($reason:expr) => {{
                        let packet = KickPacket::new($reason).expect("The message is too long!");
                        write_packet!(
                            handler,
                            v1_21_10::ClientboundLoginPacket::Disconnect,
                            packet
                        );
                        return Ok(());
                    }};
                }

                state_handler!(RecvStart(v1_21_10::ServerboundLoginPacket => Option<(String, Uuid)>) (designator, reader){
                    Ok(
                        if matches!(designator, v1_21_10::ServerboundLoginPacket::LoginStart) {
                            let name_length: i32 = read!(reader => VarInt).into();
                            if name_length < 0 {
                                return Err(ReadError::NegativeLength { name: "login_name" });
                            }
                            if name_length > 16 {
                                return Err(ReadError::OverSized {
                                    name: "login_name",
                                    maximum: 16,
                                    was: name_length as usize,
                                });
                            }

                            let raw_string = read_bytes!(reader(name_length as usize));
                            let username = String::from_utf8(raw_string)
                                .map_err(|_| ReadError::StringDecode { name: "login_name" })?;

                            let raw_uuid = read_bytes!(reader(16));
                            let uuid = Uuid::from_bytes(raw_uuid);

                            Some((username, uuid))
                        } else {
                            None
                        },
                    )
                });

                let Some((name, uuid)) = read_packet!(handler, RecvStart) else {
                    kick!("You didn't send the expected LoginStart packet!");
                };

                println!("Making key pair...");
                let (token, rsa_priv) = {
                    let mut rng = rand::thread_rng();
                    let mut token = [0u8; 16];

                    rng.fill(&mut token);

                    let rsa_priv = RsaPrivateKey::new(&mut rng, 1024)
                        .expect("Failed to create RSA private key");

                    (token, rsa_priv)
                };

                let rsa_pub = rsa_priv.to_public_key();
                let der = rsa_pub.to_public_key_der().expect("Failed to create DER");
                let der_bytes = der.as_bytes();

                struct EncryptionRequest<'a> {
                    public_key: &'a [u8],
                    token: &'a [u8],
                }
                impl<'a> EncryptionRequest<'a> {
                    fn new(pubkey: &'a [u8], token: &'a [u8]) -> Self {
                        assert!(pubkey.len() < i32::MAX as usize);
                        assert!(token.len() < i32::MAX as usize);
                        Self {
                            public_key: pubkey,
                            token,
                        }
                    }
                }
                impl Serializable for EncryptionRequest<'_> {
                    fn size(&self) -> usize {
                        1 + VarInt::from(self.public_key.len() as i32).size()
                            + self.public_key.len()
                            + VarInt::from(self.token.len() as i32).size()
                            + self.token.len()
                            + 1
                    }
                }
                to_writer!(EncryptionRequest<'_> => (this, writer){
                    // No server ID
                    let zero = VarInt::from(0);
                    write!(VarInt(zero) => writer);
                    let pubkey_length = VarInt::from(this.public_key.len() as i32);
                    write!(VarInt(pubkey_length) => writer);
                    write_bytes!(&this.public_key => writer);
                    let token_length = VarInt::from(this.token.len() as i32);
                    write!(VarInt(token_length) => writer);
                    write_bytes!(&this.token => writer);
                    // Don't authenticate
                    write!(u8(0) => writer);
                    Ok(())
                });

                let encryption_request_packet = EncryptionRequest::new(der_bytes, &token);
                write_packet!(
                    handler,
                    v1_21_10::ClientboundLoginPacket::EncryptionRequest,
                    encryption_request_packet
                );

                state_handler!(EncryptionResponse(v1_21_10::ServerboundLoginPacket => Option<(Vec<u8>, Vec<u8>)>) (designator, reader) {
                    Ok(
                        if matches!(
                            designator,
                            v1_21_10::ServerboundLoginPacket::EncryptionResponse
                        ) {
                            let shared_secret_length: i32 = read!(reader => VarInt).into();
                            let shared_secret = read_bytes!(reader(shared_secret_length as usize));
                            let verify_token_length: i32 = read!(reader => VarInt).into();
                            let verify_token = read_bytes!(reader(verify_token_length as usize));
                            Some((shared_secret, verify_token))
                        } else {
                            None
                        },
                    )
                });

                let Some((secret, response_token)) = read_packet!(handler, EncryptionResponse)
                else {
                    kick!("You didn't send the expected EncryptionResponse packet!");
                };

                let Ok(response_token) = rsa_priv.decrypt(Pkcs1v15Encrypt, &response_token) else {
                    kick!("We were unable to decrypt the token!");
                };

                if response_token != token {
                    kick!("You sent a different token!");
                }

                let Ok(secret) = rsa_priv.decrypt(Pkcs1v15Encrypt, &secret) else {
                    kick!("We were unable to decrypt the secret!");
                };

                if secret.len() != 16 {
                    kick!("You didn't send a 128 bit key!");
                }

                handler
                    .provider_mut()
                    .with_encryption(secret.try_into().unwrap());

                // Set compression to 1 so everything gets compressed for testing purposes
                struct SetCompression {}
                impl Serializable for SetCompression {
                    fn size(&self) -> usize {
                        1
                    }
                }
                to_writer!(SetCompression => (_this, writer){
                    let one = VarInt::from(1);
                    write!(VarInt(one) => writer);
                    Ok(())
                });

                let packet = SetCompression {};
                write_packet!(
                    handler,
                    v1_21_10::ClientboundLoginPacket::SetCompression,
                    packet
                );

                handler.provider_mut().set_compression_threshold(Some(1));

                struct LoginSuccess {
                    username: String,
                    uuid: Uuid,
                }
                impl LoginSuccess {
                    fn new(username: String, uuid: Uuid) -> Self {
                        assert!(username.len() <= 16);
                        Self { username, uuid }
                    }
                }
                impl Serializable for LoginSuccess {
                    fn size(&self) -> usize {
                        VarInt::from(self.username.len() as i32).size() + self.username.len() + 17
                    }
                }
                to_writer!(LoginSuccess => (this, writer){
                    write_bytes!(this.uuid.as_bytes() => writer);
                    let username_length = VarInt::from(this.username.len() as i32);
                    write!(VarInt(username_length) => writer);
                    write_bytes!(this.username.as_bytes() => writer);

                    // Empty list of properties
                    let zero = VarInt::from(0);
                    write!(VarInt(zero) => writer);
                    Ok(())
                });

                let packet = LoginSuccess::new(name, uuid);
                write_packet!(
                    handler,
                    v1_21_10::ClientboundLoginPacket::LoginSuccess,
                    packet
                );

                state_handler!(LoginAcknowledge (v1_21_10::ServerboundLoginPacket => bool) (designator, _reader) {
                    Ok(matches!(
                        designator,
                        v1_21_10::ServerboundLoginPacket::LoginAcknowledge
                    ))
                });

                if !read_packet!(handler, LoginAcknowledge) {
                    kick!("You didn't send the expected LoginAcknowledge packet!");
                };

                let mut handler = handler.into_next_state();

                struct Nbt(Vec<u8>);
                impl Serializable for Nbt {
                    fn size(&self) -> usize {
                        self.0.len()
                    }
                }
                to_writer!(Nbt => (this, writer) {
                    write_bytes!(&this.0 => writer);
                    Ok(())
                });

                let nbt = nbt!("", {
                    "type": "minecraft:notice",
                    "title": "This has been a Basic Minecraft Server™",
                    "body": [
                        {
                            "type": "minecraft:plain_message",
                            "contents": {
                                "text": "This example server sucessfully enabled encryption and compression and is now in the \"Configuration\" state of the login process.",
                            },
                            "width": 300i32
                        },
                        {
                            "type": "minecraft:plain_message",
                            "contents": {
                                "text": "All that is left is sending the rest of the configuration data to the client and then implementing the \"Play\" state of the server!",
                                "italic": true,
                            },
                            "width": 300i32
                        }
                    ],
                    "can_close_with_escape": false,
                    "after_action": "close",
                    "action": {
                        "label": "All Done",
                        "action": {
                            "type": "custom",
                            "id": "custom:close"
                        }
                    }
                });

                let packet = Nbt(nbt.write_unnamed().into());
                write_packet!(
                    handler,
                    v1_21_10::ClientboundConfigPacket::ShowDialog,
                    packet
                );

                state_handler!(ConfigPacket(v1_21_10::ServerboundConfigPacket => bool) (designator, _reader) {
                    Ok(matches!(
                        designator,
                        v1_21_10::ServerboundConfigPacket::CustomClick
                    ))
                });

                // TODO: We should also send keep alive packets here to keep the client from timing out
                loop {
                    if read_packet!(handler, ConfigPacket) {
                        break;
                    }
                }

                struct ClearDialog {}
                impl Serializable for ClearDialog {
                    fn size(&self) -> usize {
                        0
                    }
                }
                to_writer!(ClearDialog => (_this, _writer) {
                    Ok(())
                });

                let packet = ClearDialog {};
                write_packet!(
                    handler,
                    v1_21_10::ClientboundConfigPacket::ClearDialog,
                    packet
                );

                let nbt = nbt!("", {
                    "text": "That's all folks!",
                    "color": "yellow"
                });

                let packet = Nbt(nbt.write_unnamed().into());
                write_packet!(
                    handler,
                    v1_21_10::ClientboundConfigPacket::Disconnect,
                    packet
                );
            }
        }
        HandshakeResult::Legacy(is_pre) => {
            if is_pre {
                write_legacy_1_3!(handler, "Wow! You're a really, really old client!");
            } else {
                write_legacy_1_6!(handler, "1.21.10", "Wow! You're an old client!");
            }

            // We need to wait for them to close the connection due to a race condition in old versions
            try_read_packet!(handler, HandshakeHandler)
                .expect_err("The client should close the connection here");
        }
    }

    Ok(())
});
