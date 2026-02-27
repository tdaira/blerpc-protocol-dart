import 'dart:typed_data';

import 'package:blerpc_protocol/blerpc_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('Control containers', () {
    test('timeout request', () {
      final c = makeTimeoutRequest(5);
      expect(c.containerType, ContainerType.control);
      expect(c.controlCmd, ControlCmd.timeout);
      expect(c.payload, isEmpty);
    });

    test('timeout response', () {
      final c = makeTimeoutResponse(5, 200);
      expect(c.containerType, ContainerType.control);
      expect(c.controlCmd, ControlCmd.timeout);
      final bd = ByteData.sublistView(c.payload);
      expect(bd.getUint16(0, Endian.little), 200);
    });

    test('stream end C2P roundtrip', () {
      final c = makeStreamEndC2P(3);
      expect(c.controlCmd, ControlCmd.streamEndC2P);
      final data = c.serialize();
      final c2 = Container.deserialize(data);
      expect(c2.controlCmd, ControlCmd.streamEndC2P);
    });

    test('stream end P2C', () {
      final c = makeStreamEndP2C(3);
      expect(c.controlCmd, ControlCmd.streamEndP2C);
    });

    test('error response', () {
      final c = makeErrorResponse(10, blerpcErrorResponseTooLarge);
      expect(c.containerType, ContainerType.control);
      expect(c.controlCmd, ControlCmd.error);
      expect(c.payload, [0x01]);

      final data = c.serialize();
      final c2 = Container.deserialize(data);
      expect(c2.containerType, ContainerType.control);
      expect(c2.controlCmd, ControlCmd.error);
      expect(c2.payload, [blerpcErrorResponseTooLarge]);
    });
  });
}
