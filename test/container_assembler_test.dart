import 'dart:typed_data';

import 'package:blerpc_protocol/blerpc_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('ContainerAssembler', () {
    test('single container assembly', () {
      final assembler = ContainerAssembler();
      final c = Container(
        transactionId: 0,
        sequenceNumber: 0,
        containerType: ContainerType.first,
        totalLength: 5,
        payload: Uint8List.fromList([0x68, 0x65, 0x6c, 0x6c, 0x6f]),
      );
      final result = assembler.feed(c);
      expect(result, Uint8List.fromList([0x68, 0x65, 0x6c, 0x6c, 0x6f]));
    });

    test('multi container assembly', () {
      final assembler = ContainerAssembler();
      final c1 = Container(
        transactionId: 1,
        sequenceNumber: 0,
        containerType: ContainerType.first,
        totalLength: 8,
        payload: Uint8List.fromList([0x68, 0x65, 0x6c, 0x6c]),
      );
      final c2 = Container(
        transactionId: 1,
        sequenceNumber: 1,
        containerType: ContainerType.subsequent,
        payload: Uint8List.fromList([0x6f, 0x20, 0x77, 0x6f]),
      );
      expect(assembler.feed(c1), isNull);
      final result = assembler.feed(c2);
      expect(result,
          Uint8List.fromList([0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f]));
    });

    test('sequence gap discards transaction', () {
      final assembler = ContainerAssembler();
      final c1 = Container(
        transactionId: 2,
        sequenceNumber: 0,
        containerType: ContainerType.first,
        totalLength: 10,
        payload: Uint8List.fromList([0x61, 0x62, 0x63]),
      );
      final cBad = Container(
        transactionId: 2,
        sequenceNumber: 2, // Gap: expected 1
        containerType: ContainerType.subsequent,
        payload: Uint8List.fromList([0x64, 0x65, 0x66]),
      );
      expect(assembler.feed(c1), isNull);
      final result = assembler.feed(cBad);
      expect(result, isNull);
      expect(assembler.hasTransaction(2), isFalse);
    });

    test('control container ignored', () {
      final assembler = ContainerAssembler();
      final c = makeTimeoutRequest(0);
      expect(assembler.feed(c), isNull);
    });

    test('subsequent without first ignored', () {
      final assembler = ContainerAssembler();
      final c = Container(
        transactionId: 99,
        sequenceNumber: 1,
        containerType: ContainerType.subsequent,
        payload: Uint8List.fromList([0x6f, 0x72, 0x70, 0x68]),
      );
      expect(assembler.feed(c), isNull);
    });
  });
}
