// Container types, control commands, and protocol constants for blerpc.

/// Container type field (2 bits in flags byte).
enum ContainerType {
  first(0x00),
  subsequent(0x01),
  control(0x03);

  const ContainerType(this.value);
  final int value;

  static ContainerType fromValue(int v) => switch (v) {
        0x00 => first,
        0x01 => subsequent,
        0x03 => control,
        _ => throw ArgumentError('Unknown ContainerType: $v'),
      };
}

/// Control command field (4 bits in flags byte).
enum ControlCmd {
  none(0x0),
  timeout(0x1),
  streamEndC2P(0x2),
  streamEndP2C(0x3),
  capabilities(0x4),
  error(0x5),
  keyExchange(0x6);

  const ControlCmd(this.value);
  final int value;

  static ControlCmd fromValue(int v) => switch (v) {
        0x0 => none,
        0x1 => timeout,
        0x2 => streamEndC2P,
        0x3 => streamEndP2C,
        0x4 => capabilities,
        0x5 => error,
        0x6 => keyExchange,
        _ => throw ArgumentError('Unknown ControlCmd: $v'),
      };
}

// Error codes for ControlCmd.error
const int blerpcErrorResponseTooLarge = 0x01;
const int blerpcErrorBusy = 0x02;

// Capabilities flags (bit field)
const int capabilityFlagEncryptionSupported = 0x0001;

// Header sizes
const int firstHeaderSize =
    6; // txnId(1) + seq(1) + flags(1) + totalLen(2) + payloadLen(1)
const int subsequentHeaderSize =
    4; // txnId(1) + seq(1) + flags(1) + payloadLen(1)
const int controlHeaderSize = 4; // txnId(1) + seq(1) + flags(1) + payloadLen(1)

// ATT header bytes subtracted from MTU
const int attOverhead = 3;
