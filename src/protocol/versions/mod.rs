#[doc(hidden)]
#[macro_export]
macro_rules! _build_protocol_state {
    ($state:ident, $state_designator:ident, $state_name:literal, $($id:literal => $packet_name:ident)+) => {
        /// The specific protocol state
        pub enum $state {}
        /// The packets that are avaliable in the specific protocol state
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            /// Returns the associated packet id for the packet type
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

#[doc(hidden)]
#[macro_export]
macro_rules! _build_protocol_writer {
    ($state:ident, $reciprocal:ident) => {
        impl<P: $crate::traits::WriteStreamProvider> $crate::protocol::ProtocolHandler<P, $state> {
            /// Writes a packet to the stream given a packet type `packet` and the internal packet
            /// data `payload`.
            pub fn write_packet<PACKET>(
                &mut self,
                packet: $reciprocal,
                payload: &PACKET,
            ) -> Result<
                (),
                $crate::error::WriteError<<P::BaseWriter<'_> as $crate::traits::Writer>::Error>,
            >
            where
                PACKET: $crate::traits::ToWriter + $crate::traits::Serializable,
            {
                self.write_packet_internal(packet.id(), payload)
            }
        }

        /// Writes a packet to the stream given a packet type `packet` and the internal packet
        /// data `payload`.
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
                PACKET: $crate::traits::asynchronous::AsyncToWriter + $crate::traits::Serializable,
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
            /// The protocol version number
            pub const VERSION: u16 = $version;

            /// Represents a client in the handshake state
            pub enum ClientboundHandshakeState {}
            impl $crate::traits::ProtocolState for ClientboundHandshakeState {
                const STATE_NAME: &'static str = "clientbound_handshake";
                type PacketDesignator = $crate::protocol::Handshake;

                fn designator_from_id(_id: i32) -> Option<Self::PacketDesignator> {
                    None
                }
            }

            /// Represents a server in the handshake state
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

            /// Creates a new serverside protocol handler for this version
            pub fn new_serverside<P>(provider: P) -> $crate::protocol::ProtocolHandler<P, ServerboundHandshakeState> {
                $crate::protocol::ProtocolHandler {
                    provider,
                    _x: ::core::marker::PhantomData {}
                }
            }

            /// Creates a new clientside protocol handler for this version
            pub fn new_clientside<P>(provider: P) -> $crate::protocol::ProtocolHandler<P, ClientboundHandshakeState> {
                $crate::protocol::ProtocolHandler {
                    provider,
                    _x: ::core::marker::PhantomData {}
                }
            }
        }
    };
}

#[macro_export]
macro_rules! build_protocol_pre_1_21_2 {
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
        play:
            clientbound:
                $( $p_c_id:literal => $p_c_name:ident )+
            serverbound:
                $( $p_s_id:literal => $p_s_name:ident )+
    ) => {
        pub mod $name {
            /// The protocol version number
            pub const VERSION: u16 = $version;

            /// Represents a client in the handshake state
            pub enum ClientboundHandshakeState {}
            impl $crate::traits::ProtocolState for ClientboundHandshakeState {
                const STATE_NAME: &'static str = "clientbound_handshake";
                type PacketDesignator = $crate::protocol::Handshake;

                fn designator_from_id(_id: i32) -> Option<Self::PacketDesignator> {
                    None
                }
            }

            /// Represents a server in the handshake state
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
                type NextState = ClientboundPlayState;
            }

            impl $crate::traits::HasNextProtocolState for ServerboundLoginState {
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

#[cfg(feature = "v1_21_11")]
mod v774;
#[cfg(feature = "v1_21_11")]
pub use v774::v1_21_11;

#[cfg(any(feature = "v1_21_10", feature = "v1_21_9"))]
mod v773;
#[cfg(feature = "v1_21_9")]
pub use v773::v1_21_9;
#[cfg(feature = "v1_21_10")]
pub use v773::v1_21_10;

#[cfg(any(feature = "v1_21_8", feature = "v1_21_7"))]
mod v772;
#[cfg(feature = "v1_21_7")]
pub use v772::v1_21_7;
#[cfg(feature = "v1_21_8")]
pub use v772::v1_21_8;

#[cfg(feature = "v1_21_6")]
mod v771;
#[cfg(feature = "v1_21_6")]
pub use v771::v1_21_6;

#[cfg(feature = "v1_21_5")]
mod v770;
#[cfg(feature = "v1_21_5")]
pub use v770::v1_21_5;

#[cfg(feature = "v1_21_4")]
mod v769;
#[cfg(feature = "v1_21_4")]
pub use v769::v1_21_4;

#[cfg(any(feature = "v1_21_0", feature = "v1_21_1"))]
mod v767;
#[cfg(feature = "v1_21_0")]
pub use v767::v1_21_0;
#[cfg(feature = "v1_21_1")]
pub use v767::v1_21_1;

#[cfg(any(feature = "v1_20_5", feature = "v1_20_6"))]
mod v766;
#[cfg(feature = "v1_20_5")]
pub use v766::v1_20_5;
#[cfg(feature = "v1_20_6")]
pub use v766::v1_20_6;

#[cfg(any(feature = "v1_20_3", feature = "v1_20_4"))]
mod v765;
#[cfg(feature = "v1_20_3")]
pub use v765::v1_20_3;
#[cfg(feature = "v1_20_4")]
pub use v765::v1_20_4;

#[cfg(feature = "v1_20_2")]
mod v764;
#[cfg(feature = "v1_20_2")]
pub use v764::v1_20_2;

#[cfg(any(feature = "v1_20_0", feature = "v1_20_1"))]
mod v763;
#[cfg(feature = "v1_20_0")]
pub use v763::v1_20_0;
#[cfg(feature = "v1_20_1")]
pub use v763::v1_20_1;

#[cfg(feature = "v1_19_4")]
mod v762;
#[cfg(feature = "v1_19_4")]
pub use v762::v1_19_4;

#[cfg(feature = "v1_19_3")]
mod v761;
#[cfg(feature = "v1_19_3")]
pub use v761::v1_19_3;

#[cfg(any(feature = "v1_19_1", feature = "v1_19_2"))]
mod v760;
#[cfg(feature = "v1_19_1")]
pub use v760::v1_19_1;
#[cfg(feature = "v1_19_2")]
pub use v760::v1_19_2;

#[cfg(feature = "v1_19_0")]
mod v759;
#[cfg(feature = "v1_19_0")]
pub use v759::v1_19_0;

#[cfg(feature = "v1_18_2")]
mod v758;
#[cfg(feature = "v1_18_2")]
pub use v758::v1_18_2;

#[cfg(any(feature = "v1_18_1", feature = "v1_18_0"))]
mod v757;
#[cfg(feature = "v1_18_0")]
pub use v757::v1_18_0;
#[cfg(feature = "v1_18_1")]
pub use v757::v1_18_1;

#[cfg(feature = "v1_17_1")]
mod v756;
#[cfg(feature = "v1_17_1")]
pub use v756::v1_17_1;

#[cfg(feature = "v1_17_0")]
mod v755;
#[cfg(feature = "v1_17_0")]
pub use v755::v1_17_0;

#[cfg(any(feature = "v1_16_5", feature = "v1_16_4"))]
mod v754;
#[cfg(feature = "v1_16_4")]
pub use v754::v1_16_4;
#[cfg(feature = "v1_16_5")]
pub use v754::v1_16_5;

#[cfg(feature = "v1_16_3")]
mod v753;
#[cfg(feature = "v1_16_3")]
pub use v753::v1_16_3;

#[cfg(feature = "v1_15_2")]
mod v578;
#[cfg(feature = "v1_15_2")]
pub use v578::v1_15_2;

#[cfg(feature = "v1_14_4")]
mod v498;
#[cfg(feature = "v1_14_4")]
pub use v498::v1_14_4;

#[cfg(feature = "v1_13_2")]
mod v404;
#[cfg(feature = "v1_13_2")]
pub use v404::v1_13_2;

#[cfg(feature = "v1_13_1")]
mod v401;
#[cfg(feature = "v1_13_1")]
pub use v401::v1_13_1;

#[cfg(feature = "v1_12_2")]
mod v340;
#[cfg(feature = "v1_12_2")]
pub use v340::v1_12_2;

#[cfg(feature = "v1_12_1")]
mod v338;
#[cfg(feature = "v1_12_1")]
pub use v338::v1_12_1;

#[cfg(feature = "v1_12_0")]
mod v335;
#[cfg(feature = "v1_12_0")]
pub use v335::v1_12_0;

#[cfg(any(feature = "v1_11_1", feature = "v1_11_2"))]
mod v316;
#[cfg(feature = "v1_11_1")]
pub use v316::v1_11_1;
#[cfg(feature = "v1_11_2")]
pub use v316::v1_11_2;

#[cfg(feature = "v1_11_0")]
mod v315;
#[cfg(feature = "v1_11_0")]
pub use v315::v1_11_0;

#[cfg(any(feature = "v1_10_2", feature = "v1_10_1", feature = "v1_10_0"))]
mod v210;
#[cfg(feature = "v1_10_0")]
pub use v210::v1_10_0;
#[cfg(feature = "v1_10_1")]
pub use v210::v1_10_1;
#[cfg(feature = "v1_10_2")]
pub use v210::v1_10_2;

#[cfg(any(feature = "v1_9_4", feature = "v1_9_3"))]
mod v110;
#[cfg(feature = "v1_9_3")]
pub use v110::v1_9_3;
#[cfg(feature = "v1_9_4")]
pub use v110::v1_9_4;

#[cfg(feature = "v1_9_2")]
mod v109;
#[cfg(feature = "v1_9_2")]
pub use v109::v1_9_2;

#[cfg(feature = "v1_9_1")]
mod v108;
#[cfg(feature = "v1_9_1")]
pub use v108::v1_9_1;

#[cfg(feature = "v1_9_0")]
mod v107;
#[cfg(feature = "v1_9_0")]
pub use v107::v1_9_0;

#[cfg(any(
    feature = "v1_8_9",
    feature = "v1_8_8",
    feature = "v1_8_7",
    feature = "v1_8_6",
    feature = "v1_8_5",
    feature = "v1_8_4",
    feature = "v1_8_3",
    feature = "v1_8_2",
    feature = "v1_8_1",
    feature = "v1_8_0",
))]
mod v47;
#[cfg(feature = "v1_8_0")]
pub use v47::v1_8_0;
#[cfg(feature = "v1_8_1")]
pub use v47::v1_8_1;
#[cfg(feature = "v1_8_2")]
pub use v47::v1_8_2;
#[cfg(feature = "v1_8_3")]
pub use v47::v1_8_3;
#[cfg(feature = "v1_8_4")]
pub use v47::v1_8_4;
#[cfg(feature = "v1_8_5")]
pub use v47::v1_8_5;
#[cfg(feature = "v1_8_6")]
pub use v47::v1_8_6;
#[cfg(feature = "v1_8_7")]
pub use v47::v1_8_7;
#[cfg(feature = "v1_8_8")]
pub use v47::v1_8_8;
#[cfg(feature = "v1_8_9")]
pub use v47::v1_8_9;

#[cfg(any(
    feature = "v1_7_10",
    feature = "v1_7_9",
    feature = "v1_7_8",
    feature = "v1_7_7",
    feature = "v1_7_6",
))]
mod v5;
#[cfg(feature = "v1_7_6")]
pub use v5::v1_7_6;
#[cfg(feature = "v1_7_7")]
pub use v5::v1_7_7;
#[cfg(feature = "v1_7_8")]
pub use v5::v1_7_8;
#[cfg(feature = "v1_7_9")]
pub use v5::v1_7_9;
#[cfg(feature = "v1_7_10")]
pub use v5::v1_7_10;

#[cfg(any(
    feature = "v1_7_5",
    feature = "v1_7_4",
    feature = "v1_7_3",
    feature = "v1_7_2",
))]
mod v4;
#[cfg(feature = "v1_7_2")]
pub use v4::v1_7_2;
#[cfg(feature = "v1_7_3")]
pub use v4::v1_7_3;
#[cfg(feature = "v1_7_4")]
pub use v4::v1_7_4;
#[cfg(feature = "v1_7_5")]
pub use v4::v1_7_5;
