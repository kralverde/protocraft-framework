# Protocraft Framework

This crate provides traits for receiving and sending Minecraft packets,
synchronous and asynchronous defaults, strongly typed implementations of
protocol handlers, and (in progress) representations of every release
protocol version in java Minecraft.

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

## Non-Goals

Packets since the Netty re-write are very complex. This library's goal is not
to provide an implementation of every packet, but to provide the library user:

- [x] Allow the use of packets only in the correct protocol state.
- [x] Handle errors and parse packets outside of the actual content.
- [x] Provide the library user context of the type of packet being handled
and a bounded stream reader to parse the packet contents themselves.

## Examples

See [Examples](examples/) for a basic synchronous and asynchronous server.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.
