// Reassembles containers into a complete payload.
import 'dart:typed_data';

import 'container.dart';
import 'container_types.dart';

class _AssemblyState {
  final int totalLength;
  int expectedSeq;
  final List<Uint8List> fragments;
  int receivedLength;

  _AssemblyState({
    required this.totalLength,
    required this.expectedSeq,
    List<Uint8List>? fragments,
    this.receivedLength = 0,
  }) : fragments = fragments ?? [];
}

/// Reassembles containers into a complete payload.
class ContainerAssembler {
  final Map<int, _AssemblyState> _transactions = {};

  /// Feed a container. Returns complete payload when done, else null.
  Uint8List? feed(Container container) {
    if (container.containerType == ContainerType.control) {
      return null; // Control containers are handled separately
    }

    final tid = container.transactionId;

    if (container.containerType == ContainerType.first) {
      _transactions[tid] = _AssemblyState(
        totalLength: container.totalLength,
        expectedSeq: 1,
        fragments: [container.payload],
        receivedLength: container.payload.length,
      );
    } else if (_transactions.containsKey(tid)) {
      final state = _transactions[tid]!;
      if (container.sequenceNumber != state.expectedSeq) {
        // Sequence gap — discard entire transaction
        _transactions.remove(tid);
        return null;
      }
      state.fragments.add(container.payload);
      state.receivedLength += container.payload.length;
      state.expectedSeq += 1;
    } else {
      // Subsequent without a FIRST — ignore
      return null;
    }

    final state = _transactions[tid]!;
    if (state.receivedLength >= state.totalLength) {
      // Combine fragments and trim to totalLength
      final builder = BytesBuilder(copy: false);
      for (final f in state.fragments) {
        builder.add(f);
      }
      final combined = builder.toBytes();
      _transactions.remove(tid);
      return Uint8List.fromList(combined.sublist(0, state.totalLength));
    }

    return null;
  }

  /// Clear all pending assembly state.
  void reset() {
    _transactions.clear();
  }

  /// Visible for testing: check if a transaction is tracked.
  bool hasTransaction(int tid) => _transactions.containsKey(tid);
}
