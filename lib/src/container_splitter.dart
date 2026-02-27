// Splits a payload into MTU-sized containers.
import 'dart:typed_data';

import 'container.dart';
import 'container_types.dart';

/// Splits a payload into containers respecting MTU.
class ContainerSplitter {
  final int _mtu;
  int _transactionCounter = 0;

  ContainerSplitter({int mtu = 247}) : _mtu = mtu;

  /// Usable bytes per BLE packet (MTU - ATT overhead).
  int get effectiveMtu => _mtu - attOverhead;

  /// Get next transaction ID (auto-increments, wraps at 256).
  int nextTransactionId() {
    final tid = _transactionCounter;
    _transactionCounter = (_transactionCounter + 1) & 0xFF;
    return tid;
  }

  /// Split payload into a list of containers.
  ///
  /// Raises [ArgumentError] if payload is too large for 8-bit
  /// sequence_number (>255 containers) or > 65535 bytes.
  List<Container> split(Uint8List payload, {int? transactionId}) {
    transactionId ??= nextTransactionId();

    final totalLength = payload.length;
    if (totalLength > 65535) {
      throw ArgumentError('Payload too large: $totalLength > 65535');
    }

    final containers = <Container>[];

    // First container
    final firstMaxPayload = effectiveMtu - firstHeaderSize;
    final firstEnd =
        firstMaxPayload < totalLength ? firstMaxPayload : totalLength;
    final firstPayload = payload.sublist(0, firstEnd);
    containers.add(Container(
      transactionId: transactionId,
      sequenceNumber: 0,
      containerType: ContainerType.first,
      totalLength: totalLength,
      payload: firstPayload,
    ));

    var offset = firstPayload.length;
    var seq = 1;

    // Subsequent containers
    final subsequentMaxPayload = effectiveMtu - subsequentHeaderSize;
    while (offset < totalLength) {
      if (seq > 255) {
        throw ArgumentError(
          'Payload requires more than 256 containers (seq=$seq), '
          'exceeding 8-bit sequence_number limit',
        );
      }
      final chunkEnd = offset + subsequentMaxPayload < totalLength
          ? offset + subsequentMaxPayload
          : totalLength;
      final chunk = payload.sublist(offset, chunkEnd);
      containers.add(Container(
        transactionId: transactionId,
        sequenceNumber: seq,
        containerType: ContainerType.subsequent,
        payload: chunk,
      ));
      offset += chunk.length;
      seq++;
    }

    return containers;
  }
}
