# Protocraft Framework

This crate provides traits for receiving and sending Minecraft packets,
synchronous and asynchronous defaults, strongly typed implementations of
protocol handlers, and (in progress) representations of every release
protocol version in java Minecraft.

## Examples

See [Examples](examples/) for a basic synchronous and asynchronous server. [This](examples/basic_handshake.rs)
serves as a basic example-tutorial.

## Features

By default, this crate only provides synchronous traits and a packet
handling logic and is both `no_std` and `no_alloc`.

To use pre-made protocols, use the feature `vx_y_z` where `x` is the
major version, `y` is the sub version, and `z` is the minor version.
For example:

```
features = ["v1_21_10"]
```

Version features remain `no_std` and `no_alloc`.

| Feature | Description | `no_std` | `no_alloc` |
| ------- | ----------- | ------ | -------- |
| `async` | Adds async traits. | `true` | `true` |
| `std` | Implements `Reader` and `Writer` for `std::io::Read` and `std::io::Write` | `false` | `false` |
| `tokio-io` | Implements `AsyncReader` and `AsyncWriter` for `tokio::io::Read` and `tokio::io::Write` | `false` | `false` |
| `futures-io` | Implements `AsyncReader` and `AsyncWriter` for `futures_io::AsyncRead` and `futures_io::AsyncWrite` | `false` | `false` |
| `defaults` | Implements a default synchronous `StreamProvider` | `false` | `false` |
| `tokio-defaults` | Implements a default asynchronous `StreamProvider` using `tokio` | `false` | `false` |
| `futures-defaults` | Implements a default asynchronous `StreamProvider` using `futures_io` | `false` | `false` |

## Minecraft Versions Not Yet Implemented

- [ ] 1.21.11+
- [ ] 1.16.0 - 1.16.2
- [ ] 1.15.0 - 1.15.1
- [ ] 1.14.0 - 1.14.3
- [ ] 1.13.0
- [ ] pre 1.7 - 1.7.1

The goal is to support all release versions.

## Goals

- [x] Allow only the use of valid packets depending on the protocol state
and whether the packet is clientbound or serverbound.
- [x] Handle errors and parse Minecraft packets to provide the user a window
into the raw packet data.
- [x] Provide sane defaults to handle compression and encryption.
- [x] Support and detect different Minecraft versions.
- [ ] Provide seemless inter-version support. (A WIP; Protocol versions are
currently distinct from one another)

## Non-Goals

Packets since the Netty re-write are very complex; this library does not provide
distinct fields or provide serialization for subfields of packets.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.
