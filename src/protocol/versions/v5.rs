build_protocol_pre_1_21_2!(v1_7_6(5):
    status:
        clientbound:
            0x00 => Response
            0x01 => Ping
        serverbound:
            0x00 => Request
            0x01 => Ping
    login:
        clientbound:
            0x00 => Disconnect
            0x01 => EncryptionRequest
            0x02 => LoginSuccess
        serverbound:
            0x00 => LoginStart
            0x01 => EncryptionResponse
    play:
        clientbound:
            0x00 => KeepAlive
            0x01 => JoinGame
            0x02 => ChatMessage
            0x03 => TimeUpdate
            0x04 => EntityEquipment
            0x05 => SpawnPosition
            0x06 => UpdateHealth
            0x07 => Respawn
            0x08 => PlayerPositionAndLook
            0x09 => HeldItemChange
            0x0A => UseBed
            0x0B => Animation
            0x0C => SpawnPlayer
            0x0D => CollectItem
            0x0E => SpawnObject
            0x0F => SpawnMob
            0x10 => SpawnPainting
            0x11 => SpawnExperienceOrb
            0x12 => EntityVelocity
            0x13 => DestroyEntities
            0x14 => Entity
            0x15 => EntityRelativeMove
            0x16 => EntityLook
            0x17 => EntityLookandRelativeMove
            0x18 => EntityTeleport
            0x19 => EntityHeadLook
            0x1A => EntityStatus
            0x1B => AttachEntity
            0x1C => EntityMetadata
            0x1D => EntityEffect
            0x1E => RemoveEntityEffect
            0x1F => SetExperience
            0x20 => EntityProperties
            0x21 => ChunkData
            0x22 => MultiBlockChange
            0x23 => BlockChange
            0x24 => BlockAction
            0x25 => BlockBreakAnimation
            0x26 => MapChunkBulk
            0x27 => Explosion
            0x28 => Effect
            0x29 => Effects
            0x2A => SoundEffect
            0x2B => Particle
            0x2C => ChangeGameState
            0x2D => SpawnGlobalEntity
            0x2E => OpenWindow
            0x2F => CloseWindow
            0x30 => SetSlot
            0x31 => WindowItems
            0x32 => WindowProperty
            0x33 => ConfirmTransaction
            0x34 => UpdateSign
            0x35 => Maps
            0x36 => UpdateBlockEntity
            0x37 => SignEditorOpen
            0x38 => Statistics
            0x39 => PlayerListItem
            0x3A => PlayerAbilities
            0x3B => TabComplete
            0x3C => ScoreboardObjective
            0x3D => UpdateScore
            0x3E => DisplayScoreboard
            0x3F => Teams
            0x40 => PluginMessage
            0x41 => Disconnect
        serverbound:
            0x00 => KeepAlive
            0x01 => ChatMessage
            0x02 => UseEntity
            0x03 => Player
            0x04 => PlayerPosition
            0x05 => PlayerLook
            0x06 => PlayerPositionAndLook
            0x07 => PlayerDigging
            0x08 => PlayerBlockPlacement
            0x09 => HeldItemChange
            0x0A => Animation
            0x0B => EntityAction
            0x0C => SteerVehicle
            0x0D => CloseWindow
            0x0E => ClickWindow
            0x0F => ConfirmTransaction
            0x10 => CreativeInventoryAction
            0x11 => EnchantItem
            0x12 => UpdateSign
            0x13 => PlayerAbilities
            0x14 => TabComplete
            0x15 => ClientSettings
            0x16 => ClientStatus
            0x17 => PluginMessage
);

pub use v1_7_6 as v1_7_7;
pub use v1_7_6 as v1_7_8;
pub use v1_7_6 as v1_7_9;
pub use v1_7_6 as v1_7_10;
