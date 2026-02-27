import 'dart:typed_data';

import 'package:blerpc_protocol/blerpc_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('Container serialize/deserialize', () {
    test('FIRST container roundtrip', () {
      final c = Container(
        transactionId: 42,
        sequenceNumber: 0,
        containerType: ContainerType.first,
        totalLength: 100,
        payload: Uint8List.fromList([0x01, 0x02, 0x03]),
      );
      final data = c.serialize();
      final c2 = Container.deserialize(data);
      expect(c2.transactionId, 42);
      expect(c2.sequenceNumber, 0);
      expect(c2.containerType, ContainerType.first);
      expect(c2.totalLength, 100);
      expect(c2.payload, [0x01, 0x02, 0x03]);
    });

    test('SUBSEQUENT container roundtrip', () {
      final c = Container(
        transactionId: 7,
        sequenceNumber: 3,
        containerType: ContainerType.subsequent,
        payload: Uint8List.fromList([0xaa, 0xbb]),
      );
      final data = c.serialize();
      final c2 = Container.deserialize(data);
      expect(c2.transactionId, 7);
      expect(c2.sequenceNumber, 3);
      expect(c2.containerType, ContainerType.subsequent);
      expect(c2.payload, [0xaa, 0xbb]);
    });

    test('CONTROL container roundtrip', () {
      final payload = ByteData(2)..setUint16(0, 500, Endian.little);
      final c = Container(
        transactionId: 1,
        sequenceNumber: 0,
        containerType: ContainerType.control,
        controlCmd: ControlCmd.timeout,
        payload: payload.buffer.asUint8List(),
      );
      final data = c.serialize();
      final c2 = Container.deserialize(data);
      expect(c2.containerType, ContainerType.control);
      expect(c2.controlCmd, ControlCmd.timeout);
      final bd = ByteData.sublistView(c2.payload);
      expect(bd.getUint16(0, Endian.little), 500);
    });

    test('flags byte encoding', () {
      // type=0b11 in bits 7-6 => 0xC0, control_cmd=0x2 in bits 5-2 => 0x08
      final c = Container(
        transactionId: 0,
        sequenceNumber: 0,
        containerType: ContainerType.control,
        controlCmd: ControlCmd.streamEndC2P,
      );
      final data = c.serialize();
      expect(data[2], 0xC0 | 0x08); // 0xC8
    });

    test('deserialize too short', () {
      expect(
        () => Container.deserialize(Uint8List.fromList([0x00, 0x01])),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('FIRST container header size', () {
      final c = Container(
        transactionId: 0,
        sequenceNumber: 0,
        containerType: ContainerType.first,
        totalLength: 0,
      );
      final data = c.serialize();
      expect(data.length, firstHeaderSize);
    });

    test('SUBSEQUENT container header size', () {
      final c = Container(
        transactionId: 0,
        sequenceNumber: 0,
        containerType: ContainerType.subsequent,
      );
      final data = c.serialize();
      expect(data.length, subsequentHeaderSize);
    });
  });
}
