# blerpc-protocol-dart

BLE RPC protocol library for Dart.

Part of the [bleRPC](https://blerpc.net) project.

## Overview

Pure Dart implementation of the bleRPC binary protocol:

- Container fragmentation and reassembly with MTU-aware splitting
- Command packet encoding/decoding with protobuf payload support
- Control messages (timeout, stream end, capabilities, error)
- **Encryption layer** — E2E encryption with X25519 key exchange, Ed25519 signatures, and AES-128-GCM

## Installation

```yaml
dependencies:
  blerpc_protocol: ^0.6.0
```

Or use a git dependency:

```yaml
dependencies:
  blerpc_protocol:
    git:
      url: https://github.com/tdaira/blerpc-protocol-dart.git
      ref: main
```

## Usage

```dart
import 'package:blerpc_protocol/blerpc_protocol.dart';

// Encode a command
final packet = CommandPacket(
  cmdType: CommandType.request,
  cmdName: 'Echo',
  data: protobufBytes,
);
final payload = packet.serialize();

// Split into BLE-sized containers
final splitter = ContainerSplitter(mtu: 247);
final containers = splitter.split(payload);

// Send containers over BLE, then reassemble on the other side
final assembler = ContainerAssembler();
for (final container in receivedContainers) {
  final result = assembler.feed(container);
  if (result != null) {
    final response = CommandPacket.deserialize(result);
  }
}
```

## Encryption

The library provides E2E encryption using a 4-step key exchange protocol (X25519 ECDH + Ed25519 signatures) and AES-128-GCM session encryption.

```dart
import 'package:blerpc_protocol/blerpc_protocol.dart';

// Perform key exchange (central side)
final session = await centralPerformKeyExchange(
  send: (data) async => await bleSend(data),
  receive: () async => await bleReceive(),
);

// Encrypt outgoing commands
final ciphertext = await session.encrypt(plaintext);

// Decrypt incoming commands
final plaintext = await session.decrypt(ciphertext);
```

## Requirements

- Dart SDK ^3.5.0

## License

[Apache-2.0](LICENSE)
