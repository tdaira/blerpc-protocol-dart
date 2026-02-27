// Command encode/decode layer for blerpc.
//
// Command format (bits):
// | type(1) | reserved(7) | cmd_name_len(8) | cmd_name(N*8) |
// | data_len(16) | data(data_len*8) |
//
// - type: 0=request, 1=response
// - cmd_name: ASCII command name
// - data_len: little-endian uint16
// - data: protobuf-encoded bytes
import 'dart:convert';
import 'dart:typed_data';

/// Command type: REQUEST or RESPONSE.
enum CommandType {
  request(0),
  response(1);

  const CommandType(this.value);
  final int value;
}

/// A single command packet.
class CommandPacket {
  final CommandType cmdType;
  final String cmdName;
  final Uint8List data;

  CommandPacket({
    required this.cmdType,
    required this.cmdName,
    Uint8List? data,
  }) : data = data ?? Uint8List(0);

  /// Serialize command to bytes.
  Uint8List serialize() {
    final nameBytes = ascii.encode(cmdName);
    if (nameBytes.length > 255) {
      throw ArgumentError('cmd_name too long: ${nameBytes.length} > 255');
    }
    if (data.length > 65535) {
      throw ArgumentError('data too long: ${data.length} > 65535');
    }

    // Byte 0: type in MSB (bit 7), reserved bits 6-0 = 0
    final byte0 = (cmdType.value & 0x01) << 7;
    final totalLen = 1 + 1 + nameBytes.length + 2 + data.length;
    final buf = ByteData(totalLen);
    var offset = 0;

    buf.setUint8(offset++, byte0);
    buf.setUint8(offset++, nameBytes.length);
    final bytes = buf.buffer.asUint8List();
    bytes.setRange(offset, offset + nameBytes.length, nameBytes);
    offset += nameBytes.length;
    buf.setUint16(offset, data.length, Endian.little);
    offset += 2;
    bytes.setRange(offset, offset + data.length, data);

    return bytes;
  }

  /// Deserialize bytes into a CommandPacket.
  static CommandPacket deserialize(Uint8List data) {
    if (data.length < 2) {
      throw ArgumentError('Command packet too short: ${data.length} bytes');
    }

    // Byte 0: type in MSB
    final cmdType =
        (data[0] >> 7) & 0x01 == 0 ? CommandType.request : CommandType.response;
    final cmdNameLen = data[1];

    var offset = 2;
    if (data.length < offset + cmdNameLen + 2) {
      throw ArgumentError('Command packet truncated');
    }

    final cmdName = ascii.decode(data.sublist(offset, offset + cmdNameLen));
    offset += cmdNameLen;

    final bd = ByteData.sublistView(data);
    final dataLen = bd.getUint16(offset, Endian.little);
    offset += 2;

    final payload = data.sublist(offset, offset + dataLen);
    return CommandPacket(
      cmdType: cmdType,
      cmdName: cmdName,
      data: payload,
    );
  }
}
