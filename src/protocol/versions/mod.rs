#[macro_export]
macro_rules! _build_protocol_state {
    ($state:ident, $state_designator:ident, $state_name:literal, $($id:literal => $packet_name:ident)+) => {
        pub enum $state {}
        pub enum $state_designator {
        $(
            $packet_name
        ),+
        }
        impl $crate::traits::ProtocolState for $state {
            const STATE_NAME: &'static str = $state_name;
            type PacketDesignator = $state_designator;

            fn designator_from_id(id: i32) -> Option<Self::PacketDesignator> {
                match id {
                $(
                    $id => Some($state_designator::$packet_name),
                )+
                    _ => None
                }
            }
        }
        impl $state_designator {
            pub const fn id(&self) -> i32 {
                match self {
                $(
                    Self::$packet_name => $id
                ),+
                }
            }
        }
    }
}

#[macro_export]
macro_rules! _build_protocol_writer {
    ($state:ident, $reciprocal:ident) => {
        impl<P: $crate::traits::WriteStreamProvider> $crate::protocol::ProtocolHandler<P, $state> {
            pub fn write_packet<PACKET>(
                &mut self,
                packet: $reciprocal,
                payload: &PACKET,
            ) -> Result<
                (),
                $crate::error::WriteError<<P::BaseWriter<'_> as $crate::traits::Writer>::Error>,
            >
            where
                PACKET: $crate::traits::ToWriter,
            {
                self.write_packet_internal(packet.id(), payload)
            }
        }

        #[cfg(feature = "async")]
        impl<P: $crate::traits::asynchronous::AsyncWriteStreamProvider>
            $crate::protocol::ProtocolHandler<P, $state>
        {
            pub async fn async_write_packet<PACKET>(
                &mut self,
                packet: $reciprocal,
                payload: &PACKET,
            ) -> Result<
                (),
                $crate::error::WriteError<
                    <P::AsyncBaseWriter<'_> as $crate::traits::asynchronous::AsyncWriter>::Error,
                >,
            >
            where
                PACKET: $crate::traits::asynchronous::AsyncToWriter,
            {
                self.async_write_packet_internal(packet.id(), payload).await
            }
        }
    };
}

#[macro_export]
macro_rules! build_protocol {
    ($name:ident($version:literal):
        status:
            clientbound:
                $( $s_c_id:literal => $s_c_name:ident )+
            serverbound:
                $( $s_s_id:literal => $s_s_name:ident )+
        login:
            clientbound:
                $( $l_c_id:literal => $l_c_name:ident )+
            serverbound:
                $( $l_s_id:literal => $l_s_name:ident )+
        config:
            clientbound:
                $( $c_c_id:literal => $c_c_name:ident )+
            serverbound:
                $( $c_s_id:literal => $c_s_name:ident )+
        play:
            clientbound:
                $( $p_c_id:literal => $p_c_name:ident )+
            serverbound:
                $( $p_s_id:literal => $p_s_name:ident )+
    ) => {
        pub mod $name {
            pub const VERSION: u16 = $version;

            pub enum ClientboundHandshakeState {}
            impl $crate::traits::ProtocolState for ClientboundHandshakeState {
                const STATE_NAME: &'static str = "clientbound_handshake";
                type PacketDesignator = $crate::protocol::Handshake;

                fn designator_from_id(_id: i32) -> Option<Self::PacketDesignator> {
                    None
                }
            }

            pub enum ServerboundHandshakeState {}
            impl $crate::traits::ProtocolState for ServerboundHandshakeState {
                const STATE_NAME: &'static str = "serverbound_handshake";
                type PacketDesignator = $crate::protocol::Handshake;

                fn designator_from_id(id: i32) -> Option<Self::PacketDesignator> {
                    if id == 0 {
                        Some($crate::protocol::Handshake::Standard)
                    } else {
                        None
                    }
                }
            }

            $crate::_build_protocol_state!(ClientboundStatusState, ClientboundStatusPacket, "clientbound_status", $($s_c_id => $s_c_name)+);
            $crate::_build_protocol_state!(ServerboundStatusState, ServerboundStatusPacket, "serverbound_status", $($s_s_id => $s_s_name)+);

            $crate::_build_protocol_writer!(ClientboundStatusState, ServerboundStatusPacket);
            $crate::_build_protocol_writer!(ServerboundStatusState, ClientboundStatusPacket);

            $crate::_build_protocol_state!(ClientboundLoginState, ClientboundLoginPacket, "clientbound_login", $($l_c_id => $l_c_name)+);
            $crate::_build_protocol_state!(ServerboundLoginState, ServerboundLoginPacket, "serverbound_login", $($l_s_id => $l_s_name)+);

            $crate::_build_protocol_writer!(ClientboundLoginState, ServerboundLoginPacket);
            $crate::_build_protocol_writer!(ServerboundLoginState, ClientboundLoginPacket);

            $crate::_build_protocol_state!(ClientboundConfigState, ClientboundConfigPacket, "clientbound_config", $($c_c_id => $c_c_name)+);
            $crate::_build_protocol_state!(ServerboundConfigState, ServerboundConfigPacket, "serverbound_config", $($c_s_id => $c_s_name)+);

            $crate::_build_protocol_writer!(ClientboundConfigState, ServerboundConfigPacket);
            $crate::_build_protocol_writer!(ServerboundConfigState, ClientboundConfigPacket);

            $crate::_build_protocol_state!(ClientboundPlayState, ClientboundPlayPacket, "clientbound_play", $($p_c_id => $p_c_name)+);
            $crate::_build_protocol_state!(ServerboundPlayState, ServerboundPlayPacket, "serverbound_play", $($p_s_id => $p_s_name)+);

            $crate::_build_protocol_writer!(ClientboundPlayState, ServerboundPlayPacket);
            $crate::_build_protocol_writer!(ServerboundPlayState, ClientboundPlayPacket);

            impl $crate::traits::HandshakeProtocolState for ClientboundHandshakeState {
                type StatusState = ClientboundStatusState;
                type LoginState = ClientboundLoginState;
            }

            impl $crate::traits::HandshakeProtocolState for ServerboundHandshakeState {
                type StatusState = ServerboundStatusState;
                type LoginState = ServerboundLoginState;
            }

            impl $crate::traits::HasNextProtocolState for ClientboundLoginState {
                type NextState = ClientboundConfigState;
            }

            impl $crate::traits::HasNextProtocolState for ServerboundLoginState {
                type NextState = ServerboundConfigState;
            }

            impl $crate::traits::HasNextProtocolState for ClientboundConfigState {
                type NextState = ClientboundPlayState;
            }

            impl $crate::traits::HasNextProtocolState for ServerboundConfigState {
                type NextState = ServerboundPlayState;
            }

            pub fn new_serverside<P>(provider: P) -> $crate::protocol::ProtocolHandler<P, ServerboundHandshakeState> {
                $crate::protocol::ProtocolHandler {
                    provider,
                    _x: ::core::marker::PhantomData {}
                }
            }

            pub fn new_clientside<P>(provider: P) -> $crate::protocol::ProtocolHandler<P, ClientboundHandshakeState> {
                $crate::protocol::ProtocolHandler {
                    provider,
                    _x: ::core::marker::PhantomData {}
                }
            }
        }
    };
}

// See https://minecraft.wiki/w/Minecraft_Wiki:Projects/wiki.vg_merge/Protocol_version_numbers
mod v773;
pub use v773::v1_21_10;
