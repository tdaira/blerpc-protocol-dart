import 'dart:typed_data';

import 'package:blerpc_protocol/blerpc_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('CommandPacket serialize', () {
    test('serialize request', () {
      final cmd = CommandPacket(
        cmdType: CommandType.request,
        cmdName: 'echo',
        data: Uint8List.fromList([0x01, 0x02]),
      );
      final raw = cmd.serialize();
      // Byte 0: type=0 in MSB => 0x00
      expect(raw[0], 0x00);
      // Byte 1: cmd_name_len = 4
      expect(raw[1], 4);
      // Bytes 2-5: "echo"
      expect(raw.sublist(2, 6), 'echo'.codeUnits);
      // Bytes 6-7: data_len = 2 (little-endian)
      final bd = ByteData.sublistView(raw);
      expect(bd.getUint16(6, Endian.little), 2);
      // Bytes 8-9: data
      expect(raw.sublist(8, 10), [0x01, 0x02]);
    });

    test('serialize response', () {
      final cmd = CommandPacket(
        cmdType: CommandType.response,
        cmdName: 'echo',
        data: Uint8List.fromList([0x03]),
      );
      final raw = cmd.serialize();
      // Byte 0: type=1 in MSB => 0x80
      expect(raw[0], 0x80);
    });

    test('roundtrip request', () {
      final original = CommandPacket(
        cmdType: CommandType.request,
        cmdName: 'flash_read',
        data: Uint8List.fromList([0xaa, 0xbb, 0xcc]),
      );
      final raw = original.serialize();
      final decoded = CommandPacket.deserialize(raw);
      expect(decoded.cmdType, CommandType.request);
      expect(decoded.cmdName, 'flash_read');
      expect(decoded.data, [0xaa, 0xbb, 0xcc]);
    });

    test('roundtrip response', () {
      final original = CommandPacket(
        cmdType: CommandType.response,
        cmdName: 'echo',
        data: Uint8List.fromList('hello'.codeUnits),
      );
      final raw = original.serialize();
      final decoded = CommandPacket.deserialize(raw);
      expect(decoded.cmdType, CommandType.response);
      expect(decoded.cmdName, 'echo');
      expect(decoded.data, 'hello'.codeUnits);
    });

    test('ASCII cmd_name', () {
      final cmd = CommandPacket(
        cmdType: CommandType.request,
        cmdName: 'test_cmd_123',
      );
      final raw = cmd.serialize();
      final decoded = CommandPacket.deserialize(raw);
      expect(decoded.cmdName, 'test_cmd_123');
    });

    test('empty data', () {
      final cmd = CommandPacket(
        cmdType: CommandType.request,
        cmdName: 'ping',
      );
      final raw = cmd.serialize();
      final decoded = CommandPacket.deserialize(raw);
      expect(decoded.data, isEmpty);
      // data_len should be 0
      final nameLen = raw[1];
      final bd = ByteData.sublistView(raw);
      expect(bd.getUint16(2 + nameLen, Endian.little), 0);
    });

    test('data_len little endian', () {
      final data = Uint8List(300);
      final cmd = CommandPacket(
        cmdType: CommandType.request,
        cmdName: 'x',
        data: data,
      );
      final raw = cmd.serialize();
      // cmd_name_len=1, cmd_name="x"(1 byte), data_len at offset 3
      final dataLenBytes = raw.sublist(3, 5);
      final expected = ByteData(2)..setUint16(0, 300, Endian.little);
      expect(dataLenBytes, expected.buffer.asUint8List());
    });

    test('deserialize too short', () {
      expect(
        () => CommandPacket.deserialize(Uint8List.fromList([0x00])),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
