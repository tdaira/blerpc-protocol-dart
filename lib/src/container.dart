// Container serialize/deserialize for blerpc.
//
// Container format (bits):
// | transaction_id(8) | sequence_number(8) | type(2)|control_cmd(4)|reserved(2) |
// | total_length(16 or 0) | payload_len(8) | payload(variable) |
//
// type=0b00 (FIRST): has total_length, header = 6 bytes
// type=0b01 (SUBSEQUENT): no total_length, header = 4 bytes
// type=0b11 (CONTROL): no total_length, header = 4 bytes
//
// All multi-byte fields are little-endian.
import 'dart:typed_data';

import 'container_types.dart';

/// Pack type(2) | control_cmd(4) | reserved(2) into a single byte.
int packFlags(ContainerType type, [ControlCmd cmd = ControlCmd.none]) {
  return ((type.value & 0x03) << 6) | ((cmd.value & 0x0F) << 2);
}

/// Unpack flags byte into (type, control_cmd).
(ContainerType, ControlCmd) unpackFlags(int flagsByte) {
  final type = ContainerType.fromValue((flagsByte >> 6) & 0x03);
  final cmd = ControlCmd.fromValue((flagsByte >> 2) & 0x0F);
  return (type, cmd);
}

/// A single container packet.
class Container {
  final int transactionId;
  final int sequenceNumber;
  final ContainerType containerType;
  final ControlCmd controlCmd;
  final int totalLength; // Only meaningful for FIRST
  final Uint8List payload;

  Container({
    required this.transactionId,
    required this.sequenceNumber,
    required this.containerType,
    this.controlCmd = ControlCmd.none,
    this.totalLength = 0,
    Uint8List? payload,
  }) : payload = payload ?? Uint8List(0);

  /// Serialize container to bytes.
  Uint8List serialize() {
    final flags = packFlags(containerType, controlCmd);

    if (containerType == ContainerType.first) {
      final buf = ByteData(firstHeaderSize + payload.length);
      buf.setUint8(0, transactionId);
      buf.setUint8(1, sequenceNumber);
      buf.setUint8(2, flags);
      buf.setUint16(3, totalLength, Endian.little);
      buf.setUint8(5, payload.length);
      final bytes = buf.buffer.asUint8List();
      bytes.setRange(
          firstHeaderSize, firstHeaderSize + payload.length, payload);
      return bytes;
    } else {
      final buf = ByteData(subsequentHeaderSize + payload.length);
      buf.setUint8(0, transactionId);
      buf.setUint8(1, sequenceNumber);
      buf.setUint8(2, flags);
      buf.setUint8(3, payload.length);
      final bytes = buf.buffer.asUint8List();
      bytes.setRange(
          subsequentHeaderSize, subsequentHeaderSize + payload.length, payload);
      return bytes;
    }
  }

  /// Deserialize bytes into a Container.
  static Container deserialize(Uint8List data) {
    if (data.length < 4) {
      throw ArgumentError('Container too short: ${data.length} bytes');
    }

    final transactionId = data[0];
    final sequenceNumber = data[1];
    final (containerType, controlCmd) = unpackFlags(data[2]);

    if (containerType == ContainerType.first) {
      if (data.length < firstHeaderSize) {
        throw ArgumentError('FIRST container too short: ${data.length} bytes');
      }
      final bd = ByteData.sublistView(data);
      final totalLength = bd.getUint16(3, Endian.little);
      final payloadLen = data[5];
      final payload =
          data.sublist(firstHeaderSize, firstHeaderSize + payloadLen);
      return Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: containerType,
        controlCmd: controlCmd,
        totalLength: totalLength,
        payload: payload,
      );
    } else {
      final payloadLen = data[3];
      final payload =
          data.sublist(subsequentHeaderSize, subsequentHeaderSize + payloadLen);
      return Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: containerType,
        controlCmd: controlCmd,
        payload: payload,
      );
    }
  }
}
