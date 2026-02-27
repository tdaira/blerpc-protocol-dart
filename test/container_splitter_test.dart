import 'dart:typed_data';

import 'package:blerpc_protocol/blerpc_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('ContainerSplitter', () {
    test('small payload single container', () {
      final splitter = ContainerSplitter(mtu: 247);
      final containers = splitter.split(
          Uint8List.fromList([0x68, 0x65, 0x6c, 0x6c, 0x6f]),
          transactionId: 0); // "hello"
      expect(containers.length, 1);
      expect(containers[0].containerType, ContainerType.first);
      expect(containers[0].totalLength, 5);
      expect(containers[0].payload, [0x68, 0x65, 0x6c, 0x6c, 0x6f]);
    });

    test('large payload multiple containers', () {
      const mtu = 27;
      final splitter = ContainerSplitter(mtu: mtu);
      final effective = mtu - attOverhead; // 24
      final firstPayloadMax = effective - firstHeaderSize; // 18
      final subsequentPayloadMax = effective - subsequentHeaderSize; // 20

      final payload = Uint8List.fromList(List.generate(512, (i) => i % 256));
      final containers = splitter.split(payload, transactionId: 5);

      expect(containers[0].containerType, ContainerType.first);
      expect(containers[0].totalLength, 512);
      expect(containers[0].payload.length, firstPayloadMax);

      for (final c in containers.skip(1)) {
        expect(c.containerType, ContainerType.subsequent);
        expect(c.payload.length, lessThanOrEqualTo(subsequentPayloadMax));
      }

      // Verify all data is accounted for
      final reassembled = containers.expand((c) => c.payload).toList();
      expect(reassembled, payload);
    });

    test('boundary payload exactly first max', () {
      const mtu = 30;
      final splitter = ContainerSplitter(mtu: mtu);
      final effective = mtu - attOverhead; // 27
      final firstMax = effective - firstHeaderSize; // 21

      final payload = Uint8List(firstMax)..fillRange(0, firstMax, 0x41);
      final containers = splitter.split(payload, transactionId: 0);
      expect(containers.length, 1);
      expect(containers[0].payload, payload);
    });

    test('boundary payload one byte over first max', () {
      const mtu = 30;
      final splitter = ContainerSplitter(mtu: mtu);
      final effective = mtu - attOverhead;
      final firstMax = effective - firstHeaderSize;

      final payload = Uint8List(firstMax + 1)..fillRange(0, firstMax + 1, 0x41);
      final containers = splitter.split(payload, transactionId: 0);
      expect(containers.length, 2);
      expect(containers[0].payload.length, firstMax);
      expect(containers[1].payload.length, 1);
    });

    test('empty payload', () {
      final splitter = ContainerSplitter(mtu: 247);
      final containers = splitter.split(Uint8List(0), transactionId: 0);
      expect(containers.length, 1);
      expect(containers[0].totalLength, 0);
      expect(containers[0].payload, isEmpty);
    });

    test('transaction ID auto increment', () {
      final splitter = ContainerSplitter(mtu: 247);
      final c1 = splitter.split(Uint8List.fromList([0x61]));
      final c2 = splitter.split(Uint8List.fromList([0x62]));
      expect(c1[0].transactionId, 0);
      expect(c2[0].transactionId, 1);
    });

    test('transaction ID wraps at 256', () {
      final splitter = ContainerSplitter(mtu: 247);
      // Advance counter to 255
      for (var i = 0; i < 255; i++) {
        splitter.nextTransactionId();
      }
      final c1 = splitter.split(Uint8List.fromList([0x61]));
      final c2 = splitter.split(Uint8List.fromList([0x62]));
      expect(c1[0].transactionId, 255);
      expect(c2[0].transactionId, 0);
    });
  });
}
