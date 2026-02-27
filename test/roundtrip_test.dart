import 'dart:typed_data';

import 'package:blerpc_protocol/blerpc_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('Split-then-assemble roundtrip', () {
    test('roundtrip small', () {
      final splitter = ContainerSplitter(mtu: 247);
      final assembler = ContainerAssembler();
      final payload = Uint8List.fromList('hello world'.codeUnits);

      final containers = splitter.split(payload, transactionId: 0);
      Uint8List? result;
      for (final c in containers) {
        final serialized = c.serialize();
        final deserialized = Container.deserialize(serialized);
        result = assembler.feed(deserialized);
      }
      expect(result, payload);
    });

    test('roundtrip large', () {
      final splitter = ContainerSplitter(mtu: 27);
      final assembler = ContainerAssembler();
      final payload = Uint8List.fromList(List.generate(1024, (i) => i % 256));

      final containers = splitter.split(payload, transactionId: 10);
      Uint8List? result;
      for (final c in containers) {
        final serialized = c.serialize();
        final deserialized = Container.deserialize(serialized);
        result = assembler.feed(deserialized);
      }
      expect(result, payload);
    });

    test('roundtrip large payload (60KB)', () {
      final splitter = ContainerSplitter(mtu: 247);
      final assembler = ContainerAssembler();
      final payload = Uint8List(60000)..fillRange(0, 60000, 0xab);

      final containers = splitter.split(payload, transactionId: 0);
      expect(containers.length, greaterThan(200));
      Uint8List? result;
      for (final c in containers) {
        final serialized = c.serialize();
        final deserialized = Container.deserialize(serialized);
        result = assembler.feed(deserialized);
      }
      expect(result, payload);
    });

    test('payload too large raises', () {
      final splitter = ContainerSplitter(mtu: 27);
      final payload = Uint8List(10000);
      expect(
        () => splitter.split(payload, transactionId: 0),
        throwsA(isA<ArgumentError>()
            .having((e) => e.message, 'message', contains('sequence_number'))),
      );
    });

    test('roundtrip empty', () {
      final splitter = ContainerSplitter(mtu: 247);
      final assembler = ContainerAssembler();
      final payload = Uint8List(0);

      final containers = splitter.split(payload, transactionId: 0);
      Uint8List? result;
      for (final c in containers) {
        final serialized = c.serialize();
        final deserialized = Container.deserialize(serialized);
        result = assembler.feed(deserialized);
      }
      expect(result, payload);
    });
  });
}
